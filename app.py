#!/usr/bin/env python3
"""
VAPT Web Application Backend.
Flask server wrapping the recon_engine pipeline with SSE streaming.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import threading
import uuid
import json
import time
from datetime import datetime
from urllib.parse import urlparse

# Fix Windows cp1252 stdout before anything else
from recon_engine.logging_setup import reconfigure_stdout_utf8
reconfigure_stdout_utf8()

from flask import (
    Flask, Response, jsonify, render_template, request, send_file,
)
from flask_cors import CORS

from recon_engine import config
from recon_engine.runner import ScanStopped, execute_recon_pipeline, generate_executive_html_report
from recon_engine.scope import normalize_domain, validate_target

app = Flask(__name__)
CORS(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")
RESULTS_DIR = config.RESULTS_DIR
os.makedirs(RESULTS_DIR, exist_ok=True)

GITDUMP_VENV = os.path.join(BASE_DIR, "venv")
GITDUMP_OUTPUT_DIR = os.environ.get("GITDUMP_OUTPUT_DIR", os.path.expanduser("~"))

# Windows has a WSL bash shim that fails silently. Force Python engine there.
USE_BASH_SCRIPTS = (sys.platform != "win32") and bool(shutil.which("bash"))

jobs: dict = {}
jobs_lock = threading.Lock()


def _load_persisted_sessions() -> None:
    """Populate jobs from existing results/recon_*/recon_report.json files on disk."""
    if not os.path.isdir(RESULTS_DIR):
        return
    try:
        for entry in os.listdir(RESULTS_DIR):
            sub_dir = os.path.join(RESULTS_DIR, entry)
            rep_file = os.path.join(sub_dir, "recon_report.json")
            if os.path.isdir(sub_dir) and entry.startswith("recon_") and os.path.isfile(rep_file):
                try:
                    with open(rep_file, "r", encoding="utf-8", errors="ignore") as f:
                        data = json.load(f)
                    dom = data.get("domain") or entry[len("recon_"):]
                    ts = data.get("timestamp") or datetime.fromtimestamp(os.path.getmtime(rep_file)).isoformat()
                    jid = f"saved-{sanitize_label(dom)}"
                    with jobs_lock:
                        if jid not in jobs:
                            jobs[jid] = {
                                "id": jid,
                                "type": data.get("scan_type", "full"),
                                "domain": dom,
                                "status": "completed",
                                "output_lines": [f"[+] Loaded persisted session report for {dom}."],
                                "result": data,
                                "created_at": ts,
                                "finished_at": ts,
                                "stop_event": threading.Event(),
                            }
                except Exception:
                    pass
    except Exception:
        pass


def new_job(job_type: str, domain: str) -> str:
    job_id = str(uuid.uuid4())
    with jobs_lock:
        jobs[job_id] = {
            "id": job_id,
            "type": job_type,
            "domain": domain,
            "status": "pending",
            "output_lines": [],
            "result": {},
            "created_at": datetime.now().isoformat(),
            "finished_at": None,
            "stop_event": threading.Event(),
        }
    return job_id


def append_line(job_id: str, line: str) -> None:
    with jobs_lock:
        if job_id in jobs:
            jobs[job_id]["output_lines"].append(line)


def set_job_status(job_id: str, status: str, result: dict = None) -> None:
    with jobs_lock:
        if job_id in jobs:
            if jobs[job_id]["status"] == "stopped" and status != "stopped":
                if result:
                    jobs[job_id]["result"].update(result)
                return
            jobs[job_id]["status"] = status
            if status in ("completed", "failed", "stopped"):
                jobs[job_id]["finished_at"] = datetime.now().isoformat()
            if result:
                jobs[job_id]["result"].update(result)


# ────────────────────────────────────────────────────────────────────
# Pipeline worker
# ────────────────────────────────────────────────────────────────────
def run_pipeline_job(job_id: str, domain: str, scan_type: str = "full",
                     options: dict = None) -> None:
    set_job_status(job_id, "running")

    def log_cb(line):
        with jobs_lock:
            ev = jobs.get(job_id, {}).get("stop_event")
        if ev and ev.is_set():
            raise ScanStopped()
        append_line(job_id, line)

    try:
        result = execute_recon_pipeline(
            domain=domain,
            results_base_dir=RESULTS_DIR,
            scan_type=scan_type,
            scan_options=options or {},
            log_cb=log_cb,
        )
        if result.get("status") == "stopped":
            set_job_status(job_id, "stopped", result)
        elif result.get("status") == "failed":
            set_job_status(job_id, "failed", result)
        else:
            set_job_status(job_id, "completed", result)
    except ScanStopped:
        set_job_status(job_id, "stopped")
    except Exception as e:
        append_line(job_id, f"[ERROR] Pipeline execution crashed: {e}")
        set_job_status(job_id, "failed")


def run_subdomain_script(job_id: str, domain: str, options: dict = None) -> None:
    run_pipeline_job(job_id, domain, scan_type="subdomain", options=options)


# ────────────────────────────────────────────────────────────────────
# Legacy bash wrappers (Linux/macOS only; Windows uses Python engine)
# ────────────────────────────────────────────────────────────────────
def run_dirscan_script(job_id: str, alive_file: str, domain: str) -> None:
    set_job_status(job_id, "running")
    script = os.path.join(SCRIPTS_DIR, "dir_search.sh")
    scan_id = f"dirscan_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    scan_dir = os.path.join(RESULTS_DIR, scan_id)
    os.makedirs(scan_dir, exist_ok=True)
    output_file = os.path.join(scan_dir, "exposed_secrets.txt")

    try:
        process = subprocess.Popen(
            ["bash", script, alive_file],
            cwd=scan_dir,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, start_new_session=True,
        )
        with jobs_lock:
            jobs[job_id]["pid"] = process.pid
        for line in iter(process.stdout.readline, ""):
            line = line.rstrip("\n")
            if line:
                append_line(job_id, line)
        process.stdout.close()
        process.wait()

        findings = []
        if os.path.exists(output_file):
            with open(output_file) as f:
                findings = list(dict.fromkeys(
                    l.strip() for l in f if l.strip()
                ))
        result = {
            "domain": domain, "scan_dir": scan_dir,
            "output_file": output_file,
            "findings": findings, "total_findings": len(findings),
        }
        if process.returncode == 0:
            append_line(job_id, f"[+] Scan complete. {len(findings)} verified exposures.")
            set_job_status(job_id, "completed", result)
        else:
            append_line(job_id, f"[!] Script exited with code {process.returncode}")
            set_job_status(job_id, "failed", result)
    except Exception as e:
        append_line(job_id, f"[ERROR] {e}")
        set_job_status(job_id, "failed")


def run_common_dirscan_script(job_id: str, target_url: str, domain: str) -> None:
    set_job_status(job_id, "running")
    script = os.path.join(SCRIPTS_DIR, "common_dir_scan.sh")
    wordlist = os.path.join(SCRIPTS_DIR, "common.txt")
    scan_id = f"commondir_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    scan_dir = os.path.join(RESULTS_DIR, scan_id)
    os.makedirs(scan_dir, exist_ok=True)
    output_file = os.path.join(scan_dir, "common_dirs_found.txt")

    import tempfile
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                      delete=False, dir=scan_dir)
    tmp.write(target_url.strip() + "\n")
    tmp.close()
    tmp_file = tmp.name

    try:
        process = subprocess.Popen(
            ["bash", script, tmp_file, wordlist],
            cwd=scan_dir,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, start_new_session=True,
        )
        with jobs_lock:
            jobs[job_id]["pid"] = process.pid
        for line in iter(process.stdout.readline, ""):
            line = line.rstrip("\n")
            if line:
                append_line(job_id, line)
        process.stdout.close()
        process.wait()

        try:
            os.unlink(tmp_file)
        except Exception:
            pass

        findings = []
        if os.path.exists(output_file):
            with open(output_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(" ", 1)
                    findings.append({
                        "code": parts[0] if len(parts) == 2 else "?",
                        "url": parts[1] if len(parts) == 2 else line,
                    })
        result = {
            "domain": domain, "scan_dir": scan_dir,
            "output_file": output_file,
            "findings": findings, "total_findings": len(findings),
        }
        if process.returncode == 0:
            append_line(job_id, f"[+] Scan complete. {len(findings)} paths found.")
            set_job_status(job_id, "completed", result)
        else:
            append_line(job_id, f"[!] Script exited with code {process.returncode}")
            set_job_status(job_id, "failed", result)
    except Exception as e:
        append_line(job_id, f"[ERROR] {e}")
        set_job_status(job_id, "failed")


# ────────────────────────────────────────────────────────────────────
# git-dumper helpers
# ────────────────────────────────────────────────────────────────────
def sanitize_label(label: str) -> str:
    label = label.strip().lower()
    label = re.sub(r"^https?://", "", label)
    label = re.sub(r"[^a-z0-9._-]+", "_", label)
    return label.strip("._-") or "target"


def unique_dump_path(base_dir: str, dump_name: str) -> str:
    candidate = os.path.join(base_dir, dump_name)
    if not os.path.exists(candidate):
        return candidate
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(base_dir, f"{dump_name}_{ts}")


def find_gitdumper_binary():
    venv_bin = os.path.join(GITDUMP_VENV, "bin", "git-dumper")
    venv_bin_win = os.path.join(GITDUMP_VENV, "Scripts", "git-dumper.exe")
    for p in (venv_bin, venv_bin_win):
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return shutil.which("git-dumper")


def _python_git_extractor(job_id: str, base_url: str, dump_path: str) -> int:
    """Built-in pure-Python .git metadata & object extractor when git-dumper CLI is absent."""
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    git_root = os.path.join(dump_path, ".git")
    os.makedirs(git_root, exist_ok=True)
    base_url = base_url.rstrip("/")

    static_Targets = [
        "HEAD", "config", "description", "packed-refs", "index",
        "COMMIT_EDITMSG", "FETCH_HEAD", "ORIG_HEAD", "info/exclude",
        "info/refs", "logs/HEAD", "logs/refs/heads/main",
        "logs/refs/heads/master", "refs/heads/main", "refs/heads/master",
        "refs/remotes/origin/HEAD", "refs/remotes/origin/main",
        "refs/remotes/origin/master",
    ]
    downloaded = 0
    shas = set()
    sha_re = re.compile(r"\b([0-9a-f]{40})\b")

    with requests.Session() as sess:
        sess.headers.update({"User-Agent": config.USER_AGENT})
        sess.verify = False
        sess.trust_env = False

        for rel in list(static_Targets):
            url = f"{base_url}/{rel}"
            try:
                r = sess.get(url, timeout=5, allow_redirects=False)
                if r.status_code == 200 and r.content and b"<html" not in r.content[:256].lower():
                    dest = os.path.join(git_root, *rel.split("/"))
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    with open(dest, "wb") as f:
                        f.write(r.content)
                    downloaded += 1
                    append_line(job_id, f"[+] Retrieved /.git/{rel} ({len(r.content)} bytes)")
                    txt = r.content.decode("utf-8", errors="ignore")
                    for m in re.findall(r"ref:\s*(refs/[A-Za-z0-9_./-]+)", txt):
                        if m not in static_Targets:
                            static_Targets.append(m)
                    for sha in sha_re.findall(txt):
                        shas.add(sha)
            except Exception:
                pass

        for sha in list(shas)[:25]:
            obj_rel = f"objects/{sha[:2]}/{sha[2:]}"
            url = f"{base_url}/{obj_rel}"
            try:
                r = sess.get(url, timeout=5, allow_redirects=False)
                if r.status_code == 200 and r.content and b"<html" not in r.content[:256].lower():
                    dest = os.path.join(git_root, "objects", sha[:2], sha[2:])
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    with open(dest, "wb") as f:
                        f.write(r.content)
                    downloaded += 1
                    append_line(job_id, f"[+] Retrieved object {sha[:12]}... ({len(r.content)} bytes)")
            except Exception:
                pass

    return downloaded


def run_gitdump_job(job_id: str, base_url: str, label: str) -> None:
    set_job_status(job_id, "running")
    gitdumper_bin = find_gitdumper_binary()

    try:
        os.makedirs(GITDUMP_OUTPUT_DIR, exist_ok=True)
    except Exception as e:
        append_line(job_id, f"[ERROR] Cannot create {GITDUMP_OUTPUT_DIR}: {e}")
        set_job_status(job_id, "failed")
        return

    safe = sanitize_label(label)
    dump_path = unique_dump_path(GITDUMP_OUTPUT_DIR, f"{safe}_dump")
    append_line(job_id, f"[+] Target : {base_url}")
    append_line(job_id, f"[+] Dump to: {dump_path}")

    if not gitdumper_bin:
        append_line(job_id, "[*] git-dumper CLI not found; using built-in Python .git extractor...")
        try:
            file_count = _python_git_extractor(job_id, base_url, dump_path)
            result = {"target": base_url, "label": safe, "dump_path": dump_path, "file_count": file_count}
            if file_count > 0:
                append_line(job_id, f"[+] Dump complete. {file_count} .git artifacts retrieved to {dump_path}")
                set_job_status(job_id, "completed", result)
            else:
                append_line(job_id, "[!] Target did not return valid .git artifacts.")
                set_job_status(job_id, "failed", result)
        except Exception as e:
            append_line(job_id, f"[ERROR] {e}")
            set_job_status(job_id, "failed")
        return

    append_line(job_id, f"[+] Using  : {gitdumper_bin}")

    try:
        process = subprocess.Popen(
            [gitdumper_bin, base_url, dump_path],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, start_new_session=True,
        )
        with jobs_lock:
            jobs[job_id]["pid"] = process.pid
        for line in iter(process.stdout.readline, ""):
            line = line.rstrip("\n")
            if line:
                append_line(job_id, line)
        process.stdout.close()
        process.wait()

        file_count = 0
        if os.path.isdir(dump_path):
            for _root, _dirs, files in os.walk(dump_path):
                file_count += len(files)
        result = {"target": base_url, "label": safe,
                  "dump_path": dump_path, "file_count": file_count}
        if process.returncode == 0 and file_count > 0:
            append_line(job_id, f"[+] Dump complete. {file_count} files.")
            set_job_status(job_id, "completed", result)
        else:
            append_line(job_id, f"[!] git-dumper exited {process.returncode} "
                                 f"({file_count} files retrieved)")
            set_job_status(job_id, "failed", result)
    except Exception as e:
        append_line(job_id, f"[ERROR] {e}")
        set_job_status(job_id, "failed")


_load_persisted_sessions()


# ────────────────────────────────────────────────────────────────────
# Routes
# ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


def _start_scan(scan_type: str, options_key: str = "options"):
    data = request.get_json() or {}
    domain = data.get("domain", "").strip().lower()
    if not domain:
        return jsonify({"error": "domain is required"}), 400
    ok, err = validate_target(domain)
    if not ok:
        return jsonify({"error": err}), 400

    options = data.get(options_key, {})
    job_id = new_job(scan_type, domain)
    t = threading.Thread(
        target=run_pipeline_job,
        args=(job_id, domain, scan_type, options),
        daemon=True,
    )
    t.start()
    return jsonify({"job_id": job_id, "domain": domain})


@app.route("/api/scan/full", methods=["POST"])
def start_full_scan():
    return _start_scan("full")


@app.route("/api/scan/associated", methods=["POST"])
def start_associated_scan():
    return _start_scan("associated")


@app.route("/api/scan/ports", methods=["POST"])
def start_ports_scan():
    return _start_scan("ports")


@app.route("/api/scan/crawler", methods=["POST"])
def start_crawler_scan():
    return _start_scan("crawler")


@app.route("/api/scan/subdomain", methods=["POST"])
@app.route("/api/scan/subdomains", methods=["POST"])
def start_subdomain_scan():
    data = request.get_json() or {}
    domain = data.get("domain", "").strip().lower()
    if not domain:
        return jsonify({"error": "domain is required"}), 400
    ok, err = validate_target(domain)
    if not ok:
        return jsonify({"error": err}), 400
    options = data.get("options", {})
    job_id = new_job("subdomain", domain)
    t = threading.Thread(target=run_subdomain_script, args=(job_id, domain, options), daemon=True)
    t.start()
    return jsonify({"job_id": job_id, "domain": domain})


@app.route("/api/scan/directories", methods=["POST"])
def start_dir_scan():
    data = request.get_json() or {}
    domain = data.get("domain", "").strip()
    alive_file = data.get("alive_file", "").strip()

    if not domain and not alive_file:
        return jsonify({"error": "domain or alive_file is required"}), 400

    if domain:
        ok, err = validate_target(domain)
        if not ok:
            return jsonify({"error": err}), 400

    target = domain or "target"
    job_id = new_job("dirscan", target)

    if USE_BASH_SCRIPTS and alive_file and os.path.isfile(alive_file):
        t = threading.Thread(
            target=run_dirscan_script,
            args=(job_id, alive_file, target),
            daemon=True,
        )
    else:
        if alive_file and not USE_BASH_SCRIPTS:
            append_line(job_id, "[*] Windows detected - using Python engine.")
        t = threading.Thread(
            target=run_pipeline_job,
            args=(job_id, target, "directories", data.get("options")),
            daemon=True,
        )
    t.start()
    return jsonify({"job_id": job_id, "domain": target})


@app.route("/api/scan/common-dirs", methods=["POST"])
def start_common_dir_scan():
    data = request.get_json() or {}
    target_url = (data or {}).get("url", "").strip()
    domain = (data or {}).get("domain", "unknown").strip()

    if not target_url:
        return jsonify({"error": "url is required"}), 400
    if not target_url.startswith(("http://", "https://")):
        return jsonify({"error": "url must start with http:// or https://"}), 400
    if any(c in target_url for c in [";", "|", "$", "`", "\n", "\r"]):
        return jsonify({"error": "invalid url"}), 400

    if not domain or domain == "unknown":
        domain = urlparse(target_url).netloc or target_url

    ok, err = validate_target(domain)
    if not ok:
        return jsonify({"error": err}), 400

    job_id = new_job("commondir", domain)
    if USE_BASH_SCRIPTS:
        t = threading.Thread(
            target=run_common_dirscan_script,
            args=(job_id, target_url, domain),
            daemon=True,
        )
    else:
        append_line(job_id, "[*] Windows detected - using Python engine.")
        t = threading.Thread(
            target=run_pipeline_job,
            args=(job_id, domain, "directories", None),
            daemon=True,
        )
    t.start()
    return jsonify({"job_id": job_id, "domain": domain})


@app.route("/api/jobs/<job_id>/stream")
def stream_job(job_id):
    def event_stream():
        sent_index = 0
        while True:
            with jobs_lock:
                job = jobs.get(job_id)
                if not job:
                    yield 'data: {"error": "job not found"}\n\n'
                    return
                lines = job["output_lines"]
                status = job["status"]
                while sent_index < len(lines):
                    payload = json.dumps({"line": lines[sent_index], "status": status})
                    yield f"data: {payload}\n\n"
                    sent_index += 1
                if status in ("completed", "failed", "stopped"):
                    final = json.dumps({
                        "done": True, "status": status,
                        "result": job.get("result", {}),
                    })
                    yield f"data: {final}\n\n"
                    return
            time.sleep(0.3)
    return Response(event_stream(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})


@app.route("/api/jobs/<job_id>/status")
def job_status(job_id):
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "id": job["id"], "type": job["type"], "domain": job["domain"],
        "status": job["status"], "created_at": job["created_at"],
        "finished_at": job["finished_at"], "result": job.get("result", {}),
        "line_count": len(job["output_lines"]),
    })


@app.route("/api/jobs/<job_id>/stop", methods=["POST"])
def stop_job(job_id):
    import signal
    with jobs_lock:
        job = jobs.get(job_id)
        if not job:
            return jsonify({"error": "not found"}), 404
        if job["status"] not in ("running", "pending"):
            return jsonify({"error": "job is not running"}), 400
        pid = job.get("pid")
        ev = job.get("stop_event")
        if ev:
            ev.set()
        job["status"] = "stopped"
        job["finished_at"] = datetime.now().isoformat()
        job["output_lines"].append("[!] Scan stopped by user.")
    if pid:
        try:
            os.killpg(pid, signal.SIGTERM)
        except Exception:
            try:
                os.kill(pid, signal.SIGTERM)
            except Exception:
                pass
    return jsonify({"ok": True, "job_id": job_id})


@app.route("/api/sessions")
def list_sessions():
    with jobs_lock:
        out = []
        for job in jobs.values():
            res = job.get("result", {})
            out.append({
                "id": job["id"], "type": job["type"], "domain": job["domain"],
                "status": job["status"], "created_at": job["created_at"],
                "finished_at": job["finished_at"],
                "result_summary": {
                    "alive_count": res.get("alive_count")
                        or res.get("subdomains", {}).get("alive"),
                    "total_subdomains": res.get("total_subdomains")
                        or res.get("subdomains", {}).get("total"),
                    "total_findings": res.get("total_findings")
                        or len(res.get("directories", {}).get("sensitive_findings", [])),
                    "open_ports_count": res.get("ports", {}).get("open_count")
                        or len(res.get("ports", {}).get("findings", [])),
                    "crawled_count": res.get("crawler", {}).get("total_crawled"),
                    "associated_count": len(res.get("associated_domains", [])),
                },
            })
    out.sort(key=lambda x: x["created_at"], reverse=True)
    return jsonify(out)


@app.route("/api/jobs/<job_id>/report/html")
def view_html_report(job_id):
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        return "Job not found", 404
    result = job.get("result", {})
    html_path = result.get("html_report_file")
    if html_path and os.path.isfile(html_path):
        return send_file(html_path, mimetype="text/html")
    return Response(generate_executive_html_report(result), mimetype="text/html")


@app.route("/api/jobs/<job_id>/export")
def export_job_report(job_id):
    fmt = request.args.get("format", "json").lower()
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "job not found"}), 404

    result = job.get("result", {})
    domain = job.get("domain", "target")
    import io

    if fmt == "html":
        content = generate_executive_html_report(result)
        mem = io.BytesIO(content.encode("utf-8"))
        mem.seek(0)
        return send_file(mem, mimetype="text/html", as_attachment=True,
                         download_name=f"recon_report_{domain}_{job_id[:8]}.html")

    if fmt == "json":
        mem = io.BytesIO(json.dumps(result, indent=2, default=str).encode("utf-8"))
        mem.seek(0)
        return send_file(mem, mimetype="application/json", as_attachment=True,
                         download_name=f"recon_{domain}_{job_id[:8]}.json")

    if fmt == "md":
        risk = result.get("risk_assessment", {})
        lines = [
            f"# Executive VAPT Reconnaissance Report - `{domain}`",
            f"**Generated:** {job.get('finished_at') or job.get('created_at')}  ",
            f"**Risk Posture:** `{risk.get('level', 'LOW')}` "
            f"(Score: {risk.get('score', 10)}/100)",
            "\n## Subdomains", "| # | Subdomain | IP | Status | Server | WAF |",
            "|---|---|---|---|---|---|",
        ]
        for i, r in enumerate(result.get("subdomains", {}).get("records", [])[:50], 1):
            lines.append(
                f"| {i} | `{r.get('subdomain')}` | `{r.get('ip')}` | "
                f"{r.get('status_code')} | {r.get('server', '-')} | "
                f"{r.get('waf', '-')} |"
            )
        lines.extend(["\n## Open Ports",
                      "| # | Host | Port | Service | Banner |",
                      "|---|---|---|---|---|"])
        for i, p in enumerate(result.get("ports", {}).get("findings", []), 1):
            lines.append(f"| {i} | `{p.get('host')}` | **{p.get('port')}** | "
                         f"{p.get('service')} | {p.get('banner', '-')} |")
        lines.extend(["\n## Sensitive Exposures",
                      "| # | URL | Status | Size |",
                      "|---|---|---|---|"])
        for i, s in enumerate(
            result.get("directories", {}).get("sensitive_findings", []), 1
        ):
            lines.append(f"| {i} | `{s.get('url')}` | {s.get('status')} | "
                         f"{s.get('size')}B |")
        mem = io.BytesIO("\n".join(lines).encode("utf-8"))
        mem.seek(0)
        return send_file(mem, mimetype="text/markdown", as_attachment=True,
                         download_name=f"recon_report_{domain}_{job_id[:8]}.md")

    if fmt == "txt":
        lines = [
            "=== VAPT RECONNAISSANCE REPORT ===",
            f"Target: {domain}",
            f"Type: {job.get('type')}",
            f"Started: {job.get('created_at')}",
            f"Finished: {job.get('finished_at')}",
            "",
            "--- SUBDOMAINS ---",
        ]
        for r in result.get("subdomains", {}).get("records", []):
            lines.append(f"* {r.get('subdomain')} ({r.get('ip')}) "
                         f"alive={r.get('alive')} title={r.get('title')}")
        lines.extend(["", "--- PORTS ---"])
        for p in result.get("ports", {}).get("findings", []):
            lines.append(f"* {p.get('host')}:{p.get('port')} "
                         f"[{p.get('service')}] {p.get('banner')}")
        lines.extend(["", "--- SENSITIVE EXPOSURES ---"])
        for s in result.get("directories", {}).get("sensitive_findings", []):
            lines.append(f"* [EXPOSED] {s.get('url')} (HTTP {s.get('status')})")
        mem = io.BytesIO("\n".join(lines).encode("utf-8"))
        mem.seek(0)
        return send_file(mem, mimetype="text/plain", as_attachment=True,
                         download_name=f"recon_{domain}_{job_id[:8]}.txt")

    return jsonify({"error": "invalid format; use html, json, md, or txt"}), 400


@app.route("/download/handover-guide")
@app.route("/api/handover-guide/download")
def download_handover_guide():
    path = os.path.join(BASE_DIR, "PROJECT_ARCHITECTURE_AND_DEVELOPER_HANDOVER.md")
    if os.path.isfile(path):
        return send_file(path, mimetype="text/markdown", as_attachment=True,
                         download_name="PROJECT_ARCHITECTURE_AND_DEVELOPER_HANDOVER.md")
    return "Handover guide not found", 404


@app.route("/api/download")
def download_file():
    filepath = request.args.get("path", "")
    abs_path = os.path.realpath(filepath)
    if not abs_path.startswith(os.path.realpath(RESULTS_DIR)):
        return jsonify({"error": "access denied"}), 403
    if not os.path.isfile(abs_path):
        return jsonify({"error": "file not found"}), 404
    return send_file(abs_path, as_attachment=True)


@app.route("/api/results/subdomains/<domain>")
def get_subdomain_results(domain):
    domain = normalize_domain(domain)
    if not domain:
        return jsonify({"error": "invalid domain"}), 400
    recon_dir = os.path.realpath(os.path.join(RESULTS_DIR, f"recon_{domain}"))
    if not recon_dir.startswith(os.path.realpath(RESULTS_DIR)):
        return jsonify({"error": "access denied"}), 403
    alive_file = os.path.join(recon_dir, "alive_subdomains.txt")
    all_file = os.path.join(recon_dir, "all_subdomains.txt")
    if not os.path.isdir(recon_dir):
        return jsonify({"error": "no results for domain"}), 404
    alive = []
    all_subs = []
    if os.path.exists(alive_file):
        with open(alive_file, encoding="utf-8", errors="ignore") as f:
            alive = [l.strip() for l in f if l.strip()]
    if os.path.exists(all_file):
        with open(all_file, encoding="utf-8", errors="ignore") as f:
            all_subs = [l.strip() for l in f if l.strip()]
    return jsonify({
        "domain": domain, "alive": alive, "all_subdomains": all_subs,
        "alive_file": alive_file, "all_file": all_file,
    })


@app.route("/api/gitdump/start", methods=["POST"])
def start_gitdump():
    data = request.get_json() or {}
    git_head_url = (data.get("git_head_url") or "").strip()
    label = (data.get("label") or "").strip()
    authorized = bool(data.get("authorized"))

    if not authorized:
        return jsonify({"error": "You must confirm authorization."}), 400
    if not git_head_url.startswith(("http://", "https://")):
        return jsonify({"error": "URL must start with http:// or https://"}), 400
    if not git_head_url.endswith("/.git/HEAD"):
        return jsonify({"error": "URL must end with /.git/HEAD"}), 400
    if any(c in git_head_url for c in [";", "&", "|", "$", "`", "\n"]):
        return jsonify({"error": "invalid url"}), 400

    base_url = git_head_url[: -len("/HEAD")]
    if not label:
        label = urlparse(git_head_url).netloc or "target"

    job_id = new_job("gitdump", label)
    t = threading.Thread(target=run_gitdump_job, args=(job_id, base_url, label), daemon=True)
    t.start()
    return jsonify({"job_id": job_id, "label": sanitize_label(label), "target": base_url})


@app.route("/api/gitdump/check")
def gitdump_check():
    binary = find_gitdumper_binary()
    return jsonify({
        "available": True,
        "binary_path": binary or "Built-in Python .git Extractor",
        "output_dir": GITDUMP_OUTPUT_DIR,
    })


@app.route("/api/gitdump/preview", methods=["POST"])
def gitdump_preview():
    data = request.get_json() or {}
    git_head_url = (data.get("git_head_url") or "").strip()
    label = (data.get("label") or "").strip()
    if not git_head_url.endswith("/.git/HEAD"):
        return jsonify({"error": "URL must end with /.git/HEAD"}), 400
    if not label:
        label = urlparse(git_head_url).netloc or "target"
    base_url = git_head_url[: -len("/HEAD")]
    safe = sanitize_label(label)
    dump_path = os.path.join(GITDUMP_OUTPUT_DIR, f"{safe}_dump")
    return jsonify({
        "label": safe, "target": base_url, "dump_path": dump_path,
        "command": f'git-dumper "{base_url}" "{dump_path}"',
    })


if __name__ == "__main__":
    # Ensure UTF-8 output before Flask starts
    reconfigure_stdout_utf8()
    print("[*] VAPT Web App starting on http://127.0.0.1:5000")
    print(f"[*] Python: {sys.executable}")
    print(f"[*] Bash scripts: {'enabled' if USE_BASH_SCRIPTS else 'disabled (Python engine)'}")
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)