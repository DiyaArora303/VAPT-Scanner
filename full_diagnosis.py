import os
import sys
import time
import json
import socket
import requests

from recon_engine.logging_setup import reconfigure_stdout_utf8
reconfigure_stdout_utf8()

TARGET = "testphp.vulnweb.com"
SCHEME = "http"

def _select_reachable_target():
    global TARGET, SCHEME
    try:
        r = requests.get(f"http://{TARGET}", timeout=3)
        if r.status_code < 500:
            return
    except Exception:
        pass
    # Fallback when local firewall/ISP blackholes testphp.vulnweb.com on port 80
    TARGET = "example.com"
    SCHEME = "https"

def print_header(title):
    print(f"\n{'='*65}\n {title}\n{'='*65}")

def check(desc, condition, critical=True):
    if condition:
        print(f"[ OK ] {desc}")
        return True
    else:
        print(f"[FAIL] {desc}")
        if critical: print(f"      -> Critical error. Pipeline may fail.")
        return False

def main():
    print_header("VAPT SUITE COMPREHENSIVE BACKEND DIAGNOSTIC")
    
    print_header("1. Core Engine Imports")
    try:
        from recon_engine import scope, config, associated, subdomains, ports, crawler, directories, runner
        check("All recon_engine modules imported successfully", True)
    except Exception as e:
        check(f"Module import failed: {e}", False)
        sys.exit(1)

    print_header("2. Dynamic Module Tests (Live Network)")
    _select_reachable_target()
    
    try:
        valid, _ = scope.validate_target(TARGET)
        check(f"Scope Guard: Accepts {TARGET}", valid)
        valid, _ = scope.validate_target("127.0.0.1")
        check("Scope Guard: Blocks Loopback (127.0.0.1)", not valid)
    except Exception as e: check(f"Scope module failed: {e}", False)

    try:
        port_res = ports.scan_ports([TARGET], ports=[80, 443], log_cb=lambda x: None)
        check(f"Port Scanner: Found {port_res['open_ports_count']} open ports on {TARGET}", port_res['open_ports_count'] > 0)
    except Exception as e: check(f"Port module failed: {e}", False)

    try:
        ip = subdomains.resolve_host_dns(TARGET)
        check(f"Subdomain Resolver: Resolved {TARGET} -> {ip}", ip is not None)
        
        probe = subdomains.probe_http_liveness(TARGET)
        check(f"HTTP Prober: Status {probe['code']}, Server: {probe['server']}", probe['alive'])
    except Exception as e: check(f"Subdomain module failed: {e}", False)

    try:
        fp_hash, fp_len = directories.get_custom_404_fingerprint(f"{SCHEME}://{TARGET}")
        check(f"Dir Scanner: Generated 404 Fingerprint (len: {fp_len})", len(fp_hash) > 0)
    except Exception as e: check(f"Directory module failed: {e}", False)
    
    try:
        crawl_res = crawler.crawl_target(f"{SCHEME}://{TARGET}", max_pages=3, max_depth=1, log_cb=lambda x: None)
        check(f"Crawler: Successfully crawled {crawl_res['total_crawled']} pages", crawl_res['total_crawled'] > 0)
    except Exception as e: check(f"Crawler module failed: {e}", False)

    print_header("3. Full End-to-End Pipeline Execution")
    print("Running full pipeline... this should take 15-30 seconds.")

    try:
        os.makedirs("diagnostic_results", exist_ok=True)
        result = runner.execute_recon_pipeline(
            domain=TARGET,
            results_base_dir="diagnostic_results",
            scan_type="full",
            log_cb=lambda x: None
        )
        
        check("Pipeline: Completed without crashing", result.get("status") != "failed")
        check("Pipeline: Subdomains array populated", len(result.get("subdomains", {}).get("records", [])) > 0)
        check("Pipeline: Ports array populated", len(result.get("ports", {}).get("findings", [])) > 0)
        
        json_file = result.get("report_file")
        html_file = result.get("html_report_file")
        
        check(f"Pipeline: Saved JSON Report", os.path.exists(json_file))
        check(f"Pipeline: Saved HTML Executive Report", os.path.exists(html_file))
    except Exception as e: check(f"Pipeline failed to execute: {e}", False)

    print_header("4. Flask Web Server & API Test")
    try:
        import app
        client = app.app.test_client()
        res = client.get("/")
        check("Flask: Serves index.html successfully", res.status_code == 200)
        res = client.post("/api/scan/full", json={"domain": TARGET, "options": {}})
        check("Flask: /api/scan/full returns 200 OK", res.status_code == 200)
    except Exception as e: check(f"Flask API failed: {e}", False)

    print_header("DIAGNOSTIC COMPLETE")
    print("If all checks above are [ OK ], the backend engine is fully operational.\n")

if __name__ == "__main__":
    main()
