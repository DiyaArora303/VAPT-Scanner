#!/usr/bin/env python3
"""
_diagnose.py — Non-destructive diagnostic for the VAPT Recon Suite.
Run:  python _diagnose.py
Writes _diagnostics_report.json next to itself.
Safe: only reads files, imports modules, and makes short non-invasive network probes.
"""
from __future__ import annotations

import importlib
import io
import json
import os
import socket
import sys
import time
import traceback
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPORT: dict = {
    "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    "root": str(ROOT),
    "env": {},
    "files": {},
    "imports": {},
    "runtime": {},
    "network": {},
    "issues": [],
}


def issue(sev: str, code: str, msg: str, detail: str = "") -> None:
    REPORT["issues"].append({"severity": sev, "code": code, "message": msg, "detail": detail})
    print(f"  [{sev}] {code}: {msg}")


def safe_print(*a, **kw) -> None:
    try:
        print(*a, **kw)
    except UnicodeEncodeError:
        print(*(str(x).encode("ascii", "replace").decode() for x in a), **kw)


def section(title: str) -> None:
    safe_print()
    safe_print("=" * 72)
    safe_print(f"  {title}")
    safe_print("=" * 72)


# ───────────────────────────────────────────────────────────────────────
# 1. Environment
# ───────────────────────────────────────────────────────────────────────
section("1. Environment")
REPORT["env"]["python_version"] = sys.version
REPORT["env"]["executable"] = sys.executable
REPORT["env"]["platform"] = sys.platform
REPORT["env"]["cwd"] = os.getcwd()
REPORT["env"]["encoding_stdout"] = getattr(sys.stdout, "encoding", "?")
safe_print(f"  Python   : {sys.version.splitlines()[0]}")
safe_print(f"  Exe      : {sys.executable}")
safe_print(f"  Platform : {sys.platform}")
safe_print(f"  Stdout   : {REPORT['env']['encoding_stdout']}")

if sys.version_info < (3, 11):
    issue("HIGH", "ENV-1", f"Python {sys.version_info.major}.{sys.version_info.minor} detected. Project targets 3.11-3.13.")


# ───────────────────────────────────────────────────────────────────────
# 2. Required files
# ───────────────────────────────────────────────────────────────────────
section("2. Required files")
REQUIRED = [
    "app.py",
    "requirements.txt",
    "start.bat",
    "start.sh",
    "templates/index.html",
    "static/css/style.css",
    "static/js/app.js",
    "recon_engine/__init__.py",
    "recon_engine/scope.py",
    "recon_engine/runner.py",
    "recon_engine/subdomains.py",
    "recon_engine/ports.py",
    "recon_engine/crawler.py",
    "recon_engine/directories.py",
    "recon_engine/associated.py",
    "scripts/common.txt",
    "scripts/common_dir_scan.sh",
    "scripts/dir_search.sh",
    "scripts/subdomain_finder.sh",
]
for rel in REQUIRED:
    p = ROOT / rel
    exists = p.is_file()
    size = p.stat().st_size if exists else 0
    REPORT["files"][rel] = {"exists": exists, "size": size}
    flag = "OK " if exists else "MISSING"
    safe_print(f"  [{flag}] {rel:45} {size:>8} bytes")
    if not exists:
        issue("HIGH" if rel.endswith((".py", "requirements.txt")) else "MEDIUM",
              "FILE-1", f"Missing file: {rel}")


# ───────────────────────────────────────────────────────────────────────
# 3. Dependency check via pip freeze
# ───────────────────────────────────────────────────────────────────────
section("3. Dependencies")
try:
    import importlib.metadata as md
    installed = {d.metadata["Name"].lower(): d.version for d in md.distributions() if d.metadata.get("Name")}
    for pkg in ["flask", "flask-cors", "requests", "beautifulsoup4", "dnspython", "httpx", "cryptography"]:
        key = pkg.lower()
        if key in installed:
            REPORT["env"][f"pkg_{key}"] = installed[key]
            safe_print(f"  [OK ] {pkg:20} {installed[key]}")
        else:
            REPORT["env"][f"pkg_{key}"] = None
            safe_print(f"  [   ] {pkg:20} not installed")
            if key in ("flask", "requests", "beautifulsoup4"):
                issue("HIGH", "DEP-1", f"Required package missing: {pkg}")
            else:
                issue("LOW", "DEP-2", f"Optional package missing: {pkg}")

    # Compare with requirements.txt
    req_file = ROOT / "requirements.txt"
    if req_file.is_file():
        lines = [l.strip() for l in req_file.read_text(encoding="utf-8", errors="ignore").splitlines()
                 if l.strip() and not l.startswith("#")]
        safe_print(f"\n  requirements.txt declares {len(lines)} packages:")
        for l in lines:
            safe_print(f"    {l}")
except Exception as e:
    issue("HIGH", "DEP-3", f"Could not enumerate installed packages: {e}")


# ───────────────────────────────────────────────────────────────────────
# 4. Module imports (isolated)
# ───────────────────────────────────────────────────────────────────────
section("4. Module imports")
sys.path.insert(0, str(ROOT))
MODULES = [
    "recon_engine",
    "recon_engine.scope",
    "recon_engine.logging_setup",
    "recon_engine.config",
    "recon_engine.subdomains",
    "recon_engine.ports",
    "recon_engine.crawler",
    "recon_engine.directories",
    "recon_engine.associated",
    "recon_engine.runner",
]
for mod in MODULES:
    buf = io.StringIO()
    try:
        with redirect_stdout(buf), redirect_stderr(buf):
            m = importlib.import_module(mod)
        public = sorted([n for n in dir(m) if not n.startswith("_")])
        REPORT["imports"][mod] = {"ok": True, "public": public[:30]}
        safe_print(f"  [OK ] {mod:35} ({len(public)} public attrs)")
    except Exception as e:
        tb = traceback.format_exc()
        REPORT["imports"][mod] = {"ok": False, "error": str(e), "traceback": tb}
        safe_print(f"  [ERR] {mod:35} {type(e).__name__}: {e}")
        issue("HIGH", "IMP-1", f"Module import failed: {mod}", tb[-500:])

# app.py import (without running)
buf = io.StringIO()
try:
    with redirect_stdout(buf), redirect_stderr(buf):
        import app as _app_module  # noqa
    REPORT["imports"]["app"] = {"ok": True}
    safe_print("  [OK ] app                                (Flask app imported without running)")
except Exception as e:
    tb = traceback.format_exc()
    REPORT["imports"]["app"] = {"ok": False, "error": str(e), "traceback": tb}
    safe_print(f"  [ERR] app                               {type(e).__name__}: {e}")
    issue("HIGH", "IMP-2", f"app.py import failed: {e}", tb[-800:])


# ───────────────────────────────────────────────────────────────────────
# 5. Scope smoke tests
# ───────────────────────────────────────────────────────────────────────
section("5. Scope smoke tests")
try:
    from recon_engine import scope

    NORMALIZE_CASES = {
        "https://srmist.edu.in/portal": "srmist.edu.in",
        "srmist.edu.in:8443":            "srmist.edu.in",
        "sub.test.xyz.rh":               "sub.test.xyz.rh",
        "SRMIST.EDU.IN":                 "srmist.edu.in",
        "https://user:pass@host.com/x":  "host.com",
    }
    for raw, expected in NORMALIZE_CASES.items():
        got = scope.normalize_domain(raw)
        ok = got == expected
        REPORT["runtime"].setdefault("normalize", {})[raw] = {"got": got, "expected": expected, "ok": ok}
        safe_print(f"  [{'OK ' if ok else 'ERR'}] normalize_domain({raw!r}) = {got!r}" +
                   ("" if ok else f"  (expected {expected!r})"))
        if not ok:
            issue("MEDIUM", "SCOPE-1", f"normalize_domain({raw!r}) gave {got!r}, expected {expected!r}")

    IN_SCOPE_CASES = [
        ("portal.srmist.edu.in", "srmist.edu.in", True),
        ("evil-srmist.edu.in",   "srmist.edu.in", False),
        ("test.xyz.rh",          "xyz.rh",        True),
        ("xyz.rh",               "xyz.rh",        True),
    ]
    for cand, root, expected in IN_SCOPE_CASES:
        got = scope.is_in_scope(cand, root)
        ok = got == expected
        safe_print(f"  [{'OK ' if ok else 'ERR'}] is_in_scope({cand!r}, {root!r}) = {got}")
        if not ok:
            issue("MEDIUM", "SCOPE-2", f"is_in_scope({cand!r},{root!r}) gave {got}, expected {expected}")

    # SSRF guard
    for t in ["127.0.0.1", "169.254.169.254", "localhost", "example.com"]:
        ok, err = scope.validate_target(t)
        safe_print(f"  [   ] validate_target({t!r}) = valid={ok} err={err!r}")
        REPORT["runtime"].setdefault("validate", {})[t] = {"valid": ok, "err": err}

    # RateLimiter thread safety probe
    import threading
    rl = scope.RateLimiter(max_rate=20)  # 0.05s interval
    t0 = time.monotonic()
    def _worker():
        for _ in range(5):
            rl.wait()
    threads = [threading.Thread(target=_worker) for _ in range(4)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    elapsed = time.monotonic() - t0
    # 20 waits @ 20 rps = 1.0s minimum if serialized globally.
    threshold = 0.9
    ok = elapsed >= threshold
    safe_print(f"  [{'OK ' if ok else 'WARN'}] RateLimiter serialised 20 waits in {elapsed:.2f}s "
               f"(expected >= {threshold}s for global 20 rps)")
    REPORT["runtime"]["ratelimiter"] = {"elapsed": elapsed, "ok": ok}
    if not ok:
        issue("MEDIUM", "SCOPE-3",
              f"RateLimiter appears NOT thread-safe: 20 waits finished in {elapsed:.2f}s "
              f"(expected >= {threshold}s). Likely missing lock (known bug B-2).")
except Exception as e:
    safe_print(f"  [ERR] Scope smoke tests crashed: {e}")
    issue("HIGH", "SCOPE-4", f"Scope smoke tests crashed: {e}", traceback.format_exc()[-800:])


# ───────────────────────────────────────────────────────────────────────
# 6. Ports module — verify banner bug
# ───────────────────────────────────────────────────────────────────────
section("6. Ports banner probe")
try:
    from recon_engine import ports as ports_mod
    # Non-invasive: just inspect source to confirm the bug
    import inspect
    src = inspect.getsource(ports_mod.grab_port_banner)
    uses_plaintext_on_443 = (
        "s.sendall(b\"HEAD / HTTP/1.0" in src
        and "443" in src
    )
    REPORT["runtime"]["ports_banner_bug"] = uses_plaintext_on_443
    if uses_plaintext_on_443:
        safe_print("  [WARN] grab_port_banner sends PLAINTEXT HTTP to port 443/8443 - TLS ports need TLS handshake.")
        safe_print("         Confirmed bug B-1: banners on 443/8443 will always be empty.")
        issue("HIGH", "PORT-1", "grab_port_banner sends plaintext HTTP to TLS ports 443/8443 (bug B-1).")
    else:
        safe_print("  [OK ] grab_port_banner appears TLS-aware.")
except Exception as e:
    issue("MEDIUM", "PORT-2", f"Could not inspect ports module: {e}")


# ───────────────────────────────────────────────────────────────────────
# 7. Network reachability (short timeouts)
# ───────────────────────────────────────────────────────────────────────
section("7. Network reachability (non-invasive HEAD only)")
import urllib.request

PROBES = [
    ("crt.sh",       "https://crt.sh/?q=example.com&output=json"),
    ("certspotter",  "https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names"),
    ("anubis",       "https://jldc.me/anubis/subdomains/example.com"),
    ("hackertarget", "https://api.hackertarget.com/hostsearch/?q=example.com"),
]
for name, url in PROBES:
    t0 = time.monotonic()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "VAPT-Diagnostic/1.0"}, method="GET")
        with urllib.request.urlopen(req, timeout=6) as r:
            code = r.getcode()
            _ = r.read(512)
        dt = time.monotonic() - t0
        REPORT["network"][name] = {"code": code, "elapsed": dt}
        safe_print(f"  [OK ] {name:14} HTTP {code}  ({dt:.2f}s)")
    except Exception as e:
        dt = time.monotonic() - t0
        REPORT["network"][name] = {"error": str(e), "elapsed": dt}
        safe_print(f"  [ERR] {name:14} {type(e).__name__}: {e}  ({dt:.2f}s)")
        issue("MEDIUM" if name != "crt.sh" else "LOW",
              "NET-1", f"Passive source unreachable: {name} ({e})")


# ───────────────────────────────────────────────────────────────────────
# 8. Flask app surface
# ───────────────────────────────────────────────────────────────────────
section("8. Flask app surface")
try:
    import app as app_module
    routes = sorted(
        [(r.rule, sorted(r.methods - {"HEAD", "OPTIONS"}))
         for r in app_module.app.url_map.iter_rules()]
    )
    REPORT["runtime"]["flask_routes"] = routes
    safe_print(f"  Registered {len(routes)} routes:")
    for rule, methods in routes:
        safe_print(f"    {','.join(methods):10} {rule}")
except Exception as e:
    issue("HIGH", "FLASK-1", f"Could not enumerate Flask routes: {e}")


# ───────────────────────────────────────────────────────────────────────
# 9. Git-dumper availability (gitdump endpoints depend on it)
# ───────────────────────────────────────────────────────────────────────
section("9. git-dumper availability")
import shutil as _sh
gd = _sh.which("git-dumper")
if gd:
    REPORT["runtime"]["git_dumper"] = gd
    safe_print(f"  [OK ] git-dumper -> {gd}")
else:
    REPORT["runtime"]["git_dumper"] = None
    safe_print("  [   ] git-dumper not found on PATH")
    safe_print("        /api/gitdump/* endpoints will fail at runtime.")
    issue("LOW", "GIT-1", "git-dumper not installed; gitdump endpoints will 500 at runtime.")


# ───────────────────────────────────────────────────────────────────────
# 10. Bash availability (Windows concern)
# ───────────────────────────────────────────────────────────────────────
section("10. Bash availability (Windows concern)")
bash = _sh.which("bash")
if bash:
    REPORT["runtime"]["bash"] = bash
    safe_print(f"  [OK ] bash -> {bash}")
    safe_print("        NOTE: app.py will prefer scripts/*.sh when bash is present.")
else:
    REPORT["runtime"]["bash"] = None
    safe_print("  [   ] bash not on PATH")
    safe_print("        app.py's /api/scan/directories will fall back to Python engine.")


# ───────────────────────────────────────────────────────────────────────
# 11. Write JSON
# ───────────────────────────────────────────────────────────────────────
REPORT["summary"] = {
    "total_issues": len(REPORT["issues"]),
    "high":   sum(1 for i in REPORT["issues"] if i["severity"] == "HIGH"),
    "medium": sum(1 for i in REPORT["issues"] if i["severity"] == "MEDIUM"),
    "low":    sum(1 for i in REPORT["issues"] if i["severity"] == "LOW"),
}

out = ROOT / "_diagnostics_report.json"
out.write_text(json.dumps(REPORT, indent=2, default=str), encoding="utf-8")

section("Summary")
safe_print(f"  HIGH   : {REPORT['summary']['high']}")
safe_print(f"  MEDIUM : {REPORT['summary']['medium']}")
safe_print(f"  LOW    : {REPORT['summary']['low']}")
safe_print(f"\n  JSON report: {out}")
safe_print("  Send me this file plus the console output.\n")