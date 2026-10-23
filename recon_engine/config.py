"""
Central configuration. Every module imports from here.
Environment-variable overridable, no side effects on import.
"""
from __future__ import annotations

import os
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ─── Identity ────────────────────────────────────────────────────────
USER_AGENT = os.environ.get(
    "RECON_USER_AGENT",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36",
)

# ─── Networking ──────────────────────────────────────────────────────
DEFAULT_TIMEOUT = float(os.environ.get("RECON_TIMEOUT", "8"))
DEFAULT_RETRIES = int(os.environ.get("RECON_RETRIES", "3"))
DEFAULT_BACKOFF = float(os.environ.get("RECON_BACKOFF", "1.5"))

# Optional HTTP/SOCKS proxy — e.g. "http://127.0.0.1:8080" for Burp Suite
HTTP_PROXY = os.environ.get("RECON_HTTP_PROXY", "").strip() or None

# Optional custom DNS resolvers — comma-separated. Empty = system resolver.
DNS_RESOLVERS = [
    r.strip() for r in os.environ.get("RECON_DNS_RESOLVERS", "").split(",") if r.strip()
]

# ─── Concurrency ─────────────────────────────────────────────────────
DNS_WORKERS = int(os.environ.get("RECON_DNS_WORKERS", "50"))
HTTP_WORKERS = int(os.environ.get("RECON_HTTP_WORKERS", "20"))
PORT_WORKERS = int(os.environ.get("RECON_PORT_WORKERS", "100"))
DIR_WORKERS = int(os.environ.get("RECON_DIR_WORKERS", "10"))
CRAWL_WORKERS = int(os.environ.get("RECON_CRAWL_WORKERS", "5"))

# ─── Rate Limiting ───────────────────────────────────────────────────
DEFAULT_RATE_PER_SEC = float(os.environ.get("RECON_RATE", "15"))

# ─── Paths ───────────────────────────────────────────────────────────
RESULTS_DIR = os.environ.get(
    "RECON_RESULTS_DIR",
    str(_PROJECT_ROOT / "results"),
)
SCRIPTS_DIR = str(_PROJECT_ROOT / "scripts")
COMMON_WORDLIST = str(_PROJECT_ROOT / "scripts" / "common.txt")

# ─── Safety ──────────────────────────────────────────────────────────
# Never permitted as targets, even after DNS resolution.
BLOCKED_NETWORKS = [
    "127.0.0.0/8",     # loopback
    "169.254.0.0/16",  # link-local / AWS metadata 169.254.169.254
    "::1/128",
    "fe80::/10",
    "224.0.0.0/4",     # multicast
]

# ─── Ports ───────────────────────────────────────────────────────────
TLS_PORTS = {443, 8443, 9443, 10443}
HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 8081, 9443, 10443, 9000}