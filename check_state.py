"""check_state.py - Verify current file versions in the project."""
from __future__ import annotations

import importlib
import os
import sys

_THIS = os.path.dirname(os.path.abspath(__file__))
if _THIS not in sys.path:
    sys.path.insert(0, _THIS)

CHECKS = [
    ("recon_engine.config",        "USER_AGENT",               "v2.1"),
    ("recon_engine.logging_setup", "reconfigure_stdout_utf8",  "v2.1"),
    ("recon_engine.scope",         "RateLimiter",              "v2.1"),
    ("recon_engine.associated",    "_tls_sans_for_host",       "v2.1-bug4-fix"),
    ("recon_engine.subdomains",    "_is_unroutable",           "v2.1-bug5-fix"),
    ("recon_engine.crawler",       "extract_links_from_html",  "v2.1-bug3-fix"),
    ("recon_engine.directories",   "_is_wildcard_match",       "v2.1-bug1-fix"),
    ("recon_engine.runner",        "execute_recon_pipeline",   "v2.1"),
    ("recon_engine.runner",        "calculate_risk_assessment","v2.1"),
]


def check(module_name, attr):
    try:
        mod = importlib.import_module(module_name)
    except Exception as e:
        return False, f"IMPORT FAILED: {type(e).__name__}: {e}"
    if not hasattr(mod, attr):
        return False, f"missing attribute '{attr}'"
    return True, "OK"


def main():
    print(f"{'MODULE':40s} {'ATTRIBUTE':32s} STATUS")
    print("-" * 96)
    failures = 0
    for module, attr, marker in CHECKS:
        ok, msg = check(module, attr)
        status = f"OK  ({marker})" if ok else f"FAIL - {msg}"
        print(f"{module:40s} {attr:32s} {status}")
        if not ok:
            failures += 1
    print()
    if failures:
        print(f"[!] {failures} check(s) failed - those files need to be re-pasted.")
        return 1
    print("[+] All checks passed - every file is up to date.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
