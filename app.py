#!/usr/bin/env python3
"""
VAPT Web Application Backend
Flask server wrapping subdomain_finder.sh and dir_search.sh
with real-time SSE streaming and job management.
"""

import os
import re
import shutil
import subprocess
import threading
import uuid
import json
import time
from datetime import datetime
from urllib.parse import urlparse
from flask import Flask, request, jsonify, render_template, Response, send_file
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# --- Paths ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

# --- Git-Dumper config ---
# NOTE: dumps are ONLY ever triggered by an explicit, per-target confirmation
# from the UI (see /api/gitdump/start). This is intentionally NOT wired to
# fire automatically when a directory scan finds an exposed /.git/HEAD —
# a human has to review the finding and click "Dump" for that specific
# target. Only run this against hosts you are explicitly authorized to test.
GITDUMP_VENV = os.path.join(BASE_DIR, "venv")
GITDUMP_OUTPUT_DIR = os.environ.get("GITDUMP_OUTPUT_DIR", "/home/kali")

# --- In-memory job store ---
jobs = {}  # job_id -> { status, output_lines, result, created_at, type, domain }
jobs_lock = threading.Lock()


def new_job(job_type, domain):
    job_id = str(uuid.uuid4())
    with jobs_lock:
        jobs[job_id] = {
            "id": job_id,
            "type": job_type,  # "subdomain" | "dirscan" | "commondir"
            "domain": domain,
            "status": "pending",       # pending | running | completed | failed
            "output_lines": [],
            "result": {},
            "created_at": datetime.now().isoformat(),
            "finished_at": None,
        }
    return job_id


def append_line(job_id, line):
    with jobs_lock:
        if job_id in jobs:
            jobs[job_id]["output_lines"].append(line)


def set_job_status(job_id, status, result=None):
    with jobs_lock:
        if job_id in jobs:
            jobs[job_id]["status"] = status
            jobs[job_id]["finished_at"] = datetime.now().isoformat()
            if result:
                jobs[job_id]["result"].update(result)


def run_subdomain_script(job_id, domain):
    """Run subdomain_finder.sh <domain> from inside the results dir so output lands there."""
    set_job_status(job_id, "running")
    script = os.path.join(SCRIPTS_DIR, "subdomain_finder.sh")
    recon_dir_name = f"recon_{domain}"

    # Run from RESULTS_DIR so recon_<domain>/ is created there
    try:
        process = subprocess.Popen(
            ["bash", script, domain],
            cwd=RESULTS_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        with jobs_lock:
            jobs[job_id]["pid"] = process.pid

        for line in iter(process.stdout.readline, ""):
            line = line.rstrip("\n")
            if line:
                append_line(job_id, line)

        process.stdout.close()
        process.wait()

        recon_path = os.path.join(RESULTS_DIR, recon_dir_name)
        alive_file = os.path.join(recon_path, "alive_subdomains.txt")
        all_file = os.path.join(recon_path, "all_subdomains.txt")

        total = 0
        alive = 0
        if os.path.exists(all_file):
            with open(all_file) as f:
                total = sum(1 for l in f if l.strip())
        if os.path.exists(alive_file):
            with open(alive_file) as f:
                alive = sum(1 for l in f if l.strip())

        result = {
            "domain": domain,
            "recon_dir": recon_path,
            "alive_file": alive_file if os.path.exists(alive_file) else None,
            "all_file": all_file if os.path.exists(all_file) else None,
            "total_subdomains": total,
            "alive_count": alive,
        }

        if process.returncode == 0:
            append_line(job_id, f"[✓] Job completed. {alive} alive domains found.")
            set_job_status(job_id, "completed", result)
        else:
            append_line(job_id, f"[!] Script exited with code {process.returncode}")
            set_job_status(job_id, "failed", result)

    except Exception as e:
        append_line(job_id, f"[ERROR] {str(e)}")
        set_job_status(job_id, "failed")


def run_dirscan_script(job_id, alive_file, domain):
    """Run dir_search.sh <alive_subdomains.txt>, capturing output to results."""
    set_job_status(job_id, "running")
    script = os.path.join(SCRIPTS_DIR, "dir_search.sh")

    # Each dir scan gets its own results folder
    scan_id = f"dirscan_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    scan_dir = os.path.join(RESULTS_DIR, scan_id)
    os.makedirs(scan_dir, exist_ok=True)
    output_file = os.path.join(scan_dir, "exposed_secrets.txt")

    try:
        # The script writes exposed_secrets.txt in CWD — we run from scan_dir
        process = subprocess.Popen(
            ["bash", script, alive_file],
            cwd=scan_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,
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
                # Use a set to deduplicate, but keep order if desired (using dict keys)
                lines = [l.strip() for l in f if l.strip()]
                findings = list(dict.fromkeys(lines))

        result = {
            "domain": domain,
            "scan_dir": scan_dir,
            "output_file": output_file,
            "findings": findings,
            "total_findings": len(findings),
        }

        if process.returncode == 0:
            append_line(job_id, f"[✓] Scan complete. {len(findings)} verified exposures found.")
            set_job_status(job_id, "completed", result)
        else:
            append_line(job_id, f"[!] Script exited with code {process.returncode}")
            set_job_status(job_id, "failed", result)

    except Exception as e:
        append_line(job_id, f"[ERROR] {str(e)}")
        set_job_status(job_id, "failed")


def sanitize_label(label):
    """Turn a hostname/label into a filesystem-safe folder name component."""
    label = label.strip().lower()
    label = re.sub(r"^https?://", "", label)
    label = re.sub(r"[^a-z0-9._-]+", "_", label)
    return label.strip("._-") or "target"


def unique_dump_path(base_dir, dump_name):
    """Avoid clobbering an existing dump for the same target."""
    candidate = os.path.join(base_dir, dump_name)
    if not os.path.exists(candidate):
        return candidate
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(base_dir, f"{dump_name}_{ts}")


def build_gitdump_command(git_head_url, label):
    """
    Build (but never run) the git-dumper command for a confirmed finding.
    Returns dict with the ready-to-copy shell command and metadata.

    IMPORTANT: this project intentionally does NOT execute git-dumper on the
    user's behalf. Pulling the full contents of a target's .git repository
    is a deliberate data-extraction step against a third-party server, so
    it stays a manual, conscious action the analyst runs themselves in
    their own terminal — this function only prepares that command string.
    """
    base_url = git_head_url[: -len("/HEAD")]  # "<scheme>://<host>/.git"
    safe_label = sanitize_label(label)
    dump_name = f"{safe_label}_dump"
    dump_path = os.path.join(GITDUMP_OUTPUT_DIR, dump_name)
    activate_rel = os.path.join("venv", "bin", "activate")

    command = (
        f'source {activate_rel} && '
        f'git-dumper "{base_url}" "{dump_path}"'
    )

    return {
        "label": safe_label,
        "target": base_url,
        "dump_path": dump_path,
        "command": command,
        "venv_hint": f"Run from {BASE_DIR} so `{activate_rel}` resolves "
                     f"(or activate your own venv with git-dumper installed).",
    }


def find_gitdumper_binary():
    """Locate git-dumper: prefer the project venv, fall back to PATH."""
    venv_bin = os.path.join(GITDUMP_VENV, "bin", "git-dumper")
    if os.path.isfile(venv_bin) and os.access(venv_bin, os.X_OK):
        return venv_bin
    return shutil.which("git-dumper")


def run_gitdump_job(job_id, base_url, label):
    """
    Run git-dumper against a SINGLE confirmed target.

    Only ever invoked from /api/gitdump/start, which requires the caller to
    pass authorized=true for this specific target — there is no automatic
    scan -> dump chaining anywhere in this app. base_url is the "<scheme>://
    <host>/.git" prefix (already validated + stripped of "/HEAD" by the
    caller), so this always writes to a fresh, uniquely-named folder under
    GITDUMP_OUTPUT_DIR and never touches anything outside it.
    """
    set_job_status(job_id, "running")

    gitdumper_bin = find_gitdumper_binary()
    if not gitdumper_bin:
        append_line(job_id, "[ERROR] git-dumper binary not found.")
        append_line(job_id, f"[!] Checked {os.path.join(GITDUMP_VENV, 'bin', 'git-dumper')} and PATH.")
        append_line(job_id, "[!] Install it, e.g.: source venv/bin/activate && pip install git-dumper")
        set_job_status(job_id, "failed")
        return

    try:
        os.makedirs(GITDUMP_OUTPUT_DIR, exist_ok=True)
    except Exception as e:
        append_line(job_id, f"[ERROR] Could not create output dir {GITDUMP_OUTPUT_DIR}: {e}")
        set_job_status(job_id, "failed")
        return

    safe_label = sanitize_label(label)
    dump_path = unique_dump_path(GITDUMP_OUTPUT_DIR, f"{safe_label}_dump")

    append_line(job_id, f"[+] Target      : {base_url}")
    append_line(job_id, f"[+] Dump folder : {dump_path}")
    append_line(job_id, f"[+] Using       : {gitdumper_bin}")
    append_line(job_id, "------------------------------------------------")

    try:
        process = subprocess.Popen(
            [gitdumper_bin, base_url, dump_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,
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

        result = {
            "target": base_url,
            "label": safe_label,
            "dump_path": dump_path,
            "file_count": file_count,
        }

        if process.returncode == 0 and file_count > 0:
            append_line(job_id, f"[\u2713] Dump complete. {file_count} files saved to {dump_path}")
            set_job_status(job_id, "completed", result)
        else:
            append_line(job_id, f"[!] git-dumper exited with code {process.returncode} "
                                 f"({file_count} files retrieved)")
            set_job_status(job_id, "failed", result)

    except Exception as e:
        append_line(job_id, f"[ERROR] {str(e)}")
        set_job_status(job_id, "failed")


def run_common_dirscan_script(job_id, target_url, domain):
    """Run common_dir_scan.sh against a single target URL."""
    set_job_status(job_id, "running")
    script = os.path.join(SCRIPTS_DIR, "common_dir_scan.sh")
    wordlist = os.path.join(SCRIPTS_DIR, "common.txt")

    scan_id = f"commondir_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    scan_dir = os.path.join(RESULTS_DIR, scan_id)
    os.makedirs(scan_dir, exist_ok=True)
    output_file = os.path.join(scan_dir, "common_dirs_found.txt")

    # Write the single URL to a temp file so the script can read it
    import tempfile
    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, dir=scan_dir)
    tmp.write(target_url.strip() + "\n")
    tmp.close()
    tmp_file = tmp.name

    try:
        process = subprocess.Popen(
            ["bash", script, tmp_file, wordlist],
            cwd=scan_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        with jobs_lock:
            jobs[job_id]["pid"] = process.pid

        for line in iter(process.stdout.readline, ""):
            line = line.rstrip("\n")
            if line:
                append_line(job_id, line)

        process.stdout.close()
        process.wait()

        # Clean up temp file
        try:
            os.unlink(tmp_file)
        except Exception:
            pass

        # Parse results — each line is "STATUS_CODE URL", only 200 saved
        findings = []
        if os.path.exists(output_file):
            with open(output_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(" ", 1)
                    if len(parts) == 2:
                        findings.append({"code": parts[0], "url": parts[1]})
                    else:
                        findings.append({"code": "?", "url": line})

        result = {
            "domain": domain,
            "scan_dir": scan_dir,
            "output_file": output_file,
            "findings": findings,
            "total_findings": len(findings),
        }

        if process.returncode == 0:
            append_line(job_id, f"[\u2713] Scan complete. {len(findings)} paths found.")
            set_job_status(job_id, "completed", result)
        else:
            append_line(job_id, f"[!] Script exited with code {process.returncode}")
            set_job_status(job_id, "failed", result)

    except Exception as e:
        append_line(job_id, f"[ERROR] {str(e)}")
        set_job_status(job_id, "failed")


# ─────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan/subdomains", methods=["POST"])
def start_subdomain_scan():
    data = request.get_json()
    domain = (data or {}).get("domain", "").strip().lower()
    if not domain:
        return jsonify({"error": "domain is required"}), 400
    # Basic sanitization
    if any(c in domain for c in [";", "&", "|", "$", "`", " "]):
        return jsonify({"error": "invalid domain"}), 400

    job_id = new_job("subdomain", domain)
    t = threading.Thread(target=run_subdomain_script, args=(job_id, domain), daemon=True)
    t.start()
    return jsonify({"job_id": job_id, "domain": domain})


@app.route("/api/scan/directories", methods=["POST"])
def start_dir_scan():
    data = request.get_json()
    domain = (data or {}).get("domain", "unknown").strip()
    alive_file = (data or {}).get("alive_file", "").strip()

    if not alive_file:
        return jsonify({"error": "alive_file path is required"}), 400
    if not os.path.isfile(alive_file):
        return jsonify({"error": f"File not found: {alive_file}"}), 404

    job_id = new_job("dirscan", domain)
    t = threading.Thread(target=run_dirscan_script, args=(job_id, alive_file, domain), daemon=True)
    t.start()
    return jsonify({"job_id": job_id, "domain": domain})


@app.route("/api/jobs/<job_id>/stream")
def stream_job(job_id):
    """SSE endpoint — streams job output lines to the browser."""
    def event_stream():
        sent_index = 0
        while True:
            with jobs_lock:
                job = jobs.get(job_id)
                if not job:
                    yield "data: {\"error\": \"job not found\"}\n\n"
                    return

                lines = job["output_lines"]
                status = job["status"]

                # Send any new lines
                while sent_index < len(lines):
                    line = lines[sent_index]
                    payload = json.dumps({"line": line, "status": status})
                    yield f"data: {payload}\n\n"
                    sent_index += 1

                if status in ("completed", "failed", "stopped"):
                    # Send final status event
                    final = json.dumps({
                        "done": True,
                        "status": status,
                        "result": job.get("result", {}),
                    })
                    yield f"data: {final}\n\n"
                    return

            time.sleep(0.3)

    return Response(event_stream(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/jobs/<job_id>/status")
def job_status(job_id):
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "not found"}), 404
    # Return safe subset
    return jsonify({
        "id": job["id"],
        "type": job["type"],
        "domain": job["domain"],
        "status": job["status"],
        "created_at": job["created_at"],
        "finished_at": job["finished_at"],
        "result": job.get("result", {}),
        "line_count": len(job["output_lines"]),
    })


@app.route("/api/jobs/<job_id>/stop", methods=["POST"])
def stop_job(job_id):
    """Kill the running subprocess for this job (not Flask itself).
    Each script is launched with start_new_session=True so it has its
    own process group — killing that group does not affect Flask.
    """
    import signal
    with jobs_lock:
        job = jobs.get(job_id)
        if not job:
            return jsonify({"error": "not found"}), 404
        if job["status"] not in ("running", "pending"):
            return jsonify({"error": "job is not running"}), 400
        pid = job.get("pid")
        job["status"] = "stopped"
        job["finished_at"] = datetime.now().isoformat()
        job["output_lines"].append("[!] Scan stopped by user.")

    if pid:
        try:
            # Kill the child's own process group (safe — isolated from Flask)
            os.killpg(pid, signal.SIGTERM)
        except Exception:
            try:
                os.kill(pid, signal.SIGTERM)
            except Exception:
                pass

    return jsonify({"ok": True, "job_id": job_id})


@app.route("/api/sessions")
def list_sessions():
    """List all past scan job summaries."""
    with jobs_lock:
        session_list = []
        for job in jobs.values():
            session_list.append({
                "id": job["id"],
                "type": job["type"],
                "domain": job["domain"],
                "status": job["status"],
                "created_at": job["created_at"],
                "finished_at": job["finished_at"],
                "result_summary": {
                    "alive_count": job.get("result", {}).get("alive_count"),
                    "total_findings": job.get("result", {}).get("total_findings"),
                    "common_dirs_count": job.get("result", {}).get("total_findings") if job.get("type") == "commondir" else None,
                }
            })
    session_list.sort(key=lambda x: x["created_at"], reverse=True)
    return jsonify(session_list)


@app.route("/api/download")
def download_file():
    """Download any result file by path (must be inside RESULTS_DIR)."""
    filepath = request.args.get("path", "")
    # Security: ensure file is within RESULTS_DIR
    abs_path = os.path.realpath(filepath)
    if not abs_path.startswith(os.path.realpath(RESULTS_DIR)):
        return jsonify({"error": "access denied"}), 403
    if not os.path.isfile(abs_path):
        return jsonify({"error": "file not found"}), 404
    return send_file(abs_path, as_attachment=True)


@app.route("/api/results/subdomains/<domain>")
def get_subdomain_results(domain):
    """Return alive subdomains list for a given domain."""
    recon_dir = os.path.join(RESULTS_DIR, f"recon_{domain}")
    alive_file = os.path.join(recon_dir, "alive_subdomains.txt")
    all_file = os.path.join(recon_dir, "all_subdomains.txt")

    if not os.path.isdir(recon_dir):
        return jsonify({"error": "no results for domain"}), 404

    alive = []
    all_subs = []
    if os.path.exists(alive_file):
        with open(alive_file) as f:
            alive = [l.strip() for l in f if l.strip()]
    if os.path.exists(all_file):
        with open(all_file) as f:
            all_subs = [l.strip() for l in f if l.strip()]

    return jsonify({
        "domain": domain,
        "alive": alive,
        "all_subdomains": all_subs,
        "alive_file": alive_file,
        "all_file": all_file,
    })


@app.route("/api/gitdump/start", methods=["POST"])
def start_gitdump():
    """
    Kick off a git-dumper run for a SINGLE, explicitly confirmed target.

    Required body:
      git_head_url  — the exact "<scheme>://<host>/.git/HEAD" URL that was
                       flagged by the Sensitive File Scan (or pasted in
                       manually). We require the literal /.git/HEAD suffix
                       so this can't silently be pointed at an arbitrary path.
      authorized    — must be `true`. This is the person confirming, for
                       this specific target, that they have permission to
                       test it. There is no automatic scan -> dump chaining;
                       this endpoint only ever fires from a manual click.
      label         — optional folder name override (defaults to hostname).
    """
    data = request.get_json() or {}
    git_head_url = (data.get("git_head_url") or "").strip()
    label = (data.get("label") or "").strip()
    authorized = bool(data.get("authorized"))

    if not authorized:
        return jsonify({"error": "You must confirm you are authorized to test this target."}), 400

    if not git_head_url.startswith(("http://", "https://")):
        return jsonify({"error": "git_head_url must start with http:// or https://"}), 400
    if not git_head_url.endswith("/.git/HEAD"):
        return jsonify({"error": "git_head_url must be a discovered /.git/HEAD finding"}), 400
    if any(c in git_head_url for c in [";", "&", "|", "$", "`", "\n"]):
        return jsonify({"error": "invalid url"}), 400

    base_url = git_head_url[: -len("/HEAD")]  # "<scheme>://<host>/.git"

    if not label:
        label = urlparse(git_head_url).netloc or "target"

    job_id = new_job("gitdump", label)
    t = threading.Thread(target=run_gitdump_job, args=(job_id, base_url, label), daemon=True)
    t.start()
    return jsonify({"job_id": job_id, "label": sanitize_label(label), "target": base_url})


@app.route("/api/gitdump/check")
def gitdump_check():
    """Lets the UI show an upfront warning if git-dumper isn't installed yet,
    instead of only discovering that mid-job."""
    binary = find_gitdumper_binary()
    return jsonify({
        "available": bool(binary),
        "binary_path": binary,
        "output_dir": GITDUMP_OUTPUT_DIR,
    })


@app.route("/api/gitdump/preview", methods=["POST"])
def gitdump_preview():
    """Returns the exact command + destination path for a candidate finding
    WITHOUT running anything, so the analyst can review it before confirming."""
    data = request.get_json() or {}
    git_head_url = (data.get("git_head_url") or "").strip()
    label = (data.get("label") or "").strip()

    if not git_head_url.startswith(("http://", "https://")):
        return jsonify({"error": "git_head_url must start with http:// or https://"}), 400
    if not git_head_url.endswith("/.git/HEAD"):
        return jsonify({"error": "git_head_url must be a discovered /.git/HEAD finding"}), 400
    if any(c in git_head_url for c in [";", "&", "|", "$", "`", "\n"]):
        return jsonify({"error": "invalid url"}), 400

    if not label:
        label = urlparse(git_head_url).netloc or "target"

    return jsonify(build_gitdump_command(git_head_url, label))


@app.route("/api/scan/common-dirs", methods=["POST"])
def start_common_dir_scan():
    data = request.get_json()
    target_url = (data or {}).get("url", "").strip()
    domain = (data or {}).get("domain", "unknown").strip()

    if not target_url:
        return jsonify({"error": "url is required"}), 400
    if not target_url.startswith(("http://", "https://")):
        return jsonify({"error": "url must start with http:// or https://"}), 400
    if any(c in target_url for c in [";", "&", "|", "$", "`"]):
        return jsonify({"error": "invalid url"}), 400

    if not domain or domain == "unknown":
        # derive label from URL
        from urllib.parse import urlparse
        domain = urlparse(target_url).netloc or target_url

    job_id = new_job("commondir", domain)
    t = threading.Thread(target=run_common_dirscan_script, args=(job_id, target_url, domain), daemon=True)
    t.start()
    return jsonify({"job_id": job_id, "domain": domain})


if __name__ == "__main__":
    print("[*] VAPT Web App starting on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True, threaded=True)
