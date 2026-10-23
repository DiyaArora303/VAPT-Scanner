#!/usr/bin/env python3
"""
CLI per-stage runner. Lets you execute individual pipeline stages and
inspect each artifact file before passing control to the next stage.

Usage:
  python scripts/run_stage.py 1 --domain srmist.edu.in    # Scope check
  python scripts/run_stage.py 2 --domain srmist.edu.in    # Associated roots
  python scripts/run_stage.py 3 --domain srmist.edu.in    # Subdomains
  python scripts/run_stage.py 4 --domain srmist.edu.in    # Ports
  python scripts/run_stage.py 5 --domain srmist.edu.in    # Crawler
  python scripts/run_stage.py 6 --domain srmist.edu.in    # Directories
  python scripts/run_stage.py full --domain srmist.edu.in # Full pipeline
"""
from __future__ import annotations

import argparse
import os
import sys

# Ensure project root is importable
_THIS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_THIS)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from recon_engine.logging_setup import reconfigure_stdout_utf8  # noqa: E402
reconfigure_stdout_utf8()

from recon_engine import config  # noqa: E402
from recon_engine.associated import discover_associated_domains  # noqa: E402
from recon_engine.crawler import crawl_target  # noqa: E402
from recon_engine.directories import audit_target_directories  # noqa: E402
from recon_engine.ports import WEB_PORTS_ONLY, scan_ports  # noqa: E402
from recon_engine.runner import execute_recon_pipeline  # noqa: E402
from recon_engine.scope import normalize_domain, validate_target  # noqa: E402
from recon_engine.subdomains import enumerate_subdomains  # noqa: E402


def log(msg: str) -> None:
    print(msg, flush=True)


def stage_1(domain: str, out_dir: str) -> int:
    log("[STAGE 1] Scope validation")
    ok, err = validate_target(domain)
    if not ok:
        log(f"[ERROR] {err}")
        return 1
    log(f"[+] {domain} is in scope")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "01_scope.txt"), "w", encoding="utf-8") as f:
        f.write(f"domain={domain}\nvalid=True\n")
    return 0


def stage_2(domain: str, out_dir: str) -> int:
    log("[STAGE 2] Associated domains")
    assoc = discover_associated_domains(domain, log_cb=log)
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "02_associated.json")
    import json
    with open(out, "w", encoding="utf-8") as f:
        json.dump(assoc, f, indent=2)
    log(f"[+] Wrote {out} ({len(assoc)} associated)")
    return 0


def stage_3(domain: str, out_dir: str) -> int:
    log("[STAGE 3] Subdomain enumeration")
    res = enumerate_subdomains(domain, log_cb=log)
    os.makedirs(out_dir, exist_ok=True)
    import json
    with open(os.path.join(out_dir, "03_subdomains.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, default=str)
    with open(os.path.join(out_dir, "all_subdomains.txt"), "w", encoding="utf-8") as f:
        for r in res["records"]:
            f.write(f"{r['subdomain']}\n")
    with open(os.path.join(out_dir, "alive_subdomains.txt"), "w", encoding="utf-8") as f:
        for h in res["alive_hosts"]:
            f.write(f"{h}\n")
    log(f"[+] {res['total_subdomains']} total, {res['alive_count']} alive")
    return 0


def stage_4(domain: str, out_dir: str) -> int:
    log("[STAGE 4] Port scan")
    # Read alive fqdns from stage 3 if available
    fqdns = [domain]
    alive_file = os.path.join(out_dir, "alive_subdomains.txt")
    if os.path.exists(alive_file):
        with open(alive_file) as f:
            from urllib.parse import urlparse
            fqdns = [urlparse(l.strip()).netloc for l in f if l.strip()][:10]
    res = scan_ports(fqdns, ports=WEB_PORTS_ONLY, log_cb=log)
    os.makedirs(out_dir, exist_ok=True)
    import json
    with open(os.path.join(out_dir, "05_ports.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2)
    log(f"[+] {res['open_ports_count']} open ports")
    return 0


def stage_5(domain: str, out_dir: str, depth: int = 2, pages: int = 30) -> int:
    log("[STAGE 5] Crawler")
    res = crawl_target(f"https://{domain}", domain, max_depth=depth,
                       max_pages=pages, log_cb=log)
    os.makedirs(out_dir, exist_ok=True)
    import json
    with open(os.path.join(out_dir, "06_crawl.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, default=str)
    log(f"[+] {res['total_crawled']} crawled, {len(res['api_endpoints'])} APIs")
    return 0


def stage_6(domain: str, out_dir: str) -> int:
    log("[STAGE 6] Directory & secret audit")
    res = audit_target_directories(f"https://{domain}", log_cb=log)
    os.makedirs(out_dir, exist_ok=True)
    import json
    with open(os.path.join(out_dir, "07_dirs.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, default=str)
    log(f"[+] {len(res['directory_findings'])} dirs, "
        f"{len(res['sensitive_findings'])} exposures")
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("stage", help="1-6 for a single stage, 'full' for the whole pipeline")
    p.add_argument("--domain", required=True)
    p.add_argument("--depth", type=int, default=2)
    p.add_argument("--pages", type=int, default=30)
    args = p.parse_args()

    domain = normalize_domain(args.domain)
    if not domain:
        print(f"[ERROR] Cannot normalize domain: {args.domain}")
        return 1

    out_dir = os.path.join(config.RESULTS_DIR, f"recon_{domain}")
    os.makedirs(out_dir, exist_ok=True)

    print(f"[*] Project root  : {_ROOT}")
    print(f"[*] Results dir   : {out_dir}")
    print(f"[*] Target domain : {domain}")
    print()

    if args.stage == "full":
        res = execute_recon_pipeline(domain, config.RESULTS_DIR,
                                     scan_type="full", log_cb=log)
        return 0 if res.get("status") != "failed" else 1

    try:
        stage_num = int(args.stage)
    except ValueError:
        print(f"[ERROR] Unknown stage: {args.stage}")
        return 1

    dispatch = {
        1: lambda: stage_1(domain, out_dir),
        2: lambda: stage_2(domain, out_dir),
        3: lambda: stage_3(domain, out_dir),
        4: lambda: stage_4(domain, out_dir),
        5: lambda: stage_5(domain, out_dir, args.depth, args.pages),
        6: lambda: stage_6(domain, out_dir),
    }
    if stage_num not in dispatch:
        print(f"[ERROR] Stage must be 1-6 or 'full'")
        return 1
    return dispatch[stage_num]()


if __name__ == "__main__":
    sys.exit(main())