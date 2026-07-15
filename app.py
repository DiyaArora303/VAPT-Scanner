#!/usr/bin/env python3
"""
VAPT Web Application Backend
Flask server wrapping subdomain_finder.sh and dir_search.sh
with real-time SSE streaming and job management.
"""

import os
import subprocess
import threading
import uuid
import json
import time
from datetime import datetime
from flask import Flask, request, jsonify, render_template, Response, send_file
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# --- Paths ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

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
                findings = [l.strip() for l in f if l.strip()]

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
