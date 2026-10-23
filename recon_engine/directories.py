"""
recon_engine/directories.py — Fast Directory & Secret Audit.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Tuple

import requests
import urllib3

from . import config
from .scope import USER_AGENT

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SENSITIVE_FILES = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.bak",
    "/.git/HEAD",
    "/.git/config",
    "/.svn/entries",
    "/composer.json",
    "/package.json",
    "/config.php",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/.aws/credentials",
    "/id_rsa",
    "/database.sql",
    "/backup.sql",
    "/dump.sql",
    "/phpinfo.php",
    "/.htpasswd",
    "/docker-compose.yml",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
]

TOP_COMMON_DIRS = [
    "/admin", "/login", "/portal", "/api", "/dashboard", "/backup",
    "/uploads", "/files", "/config", "/test", "/dev", "/docs",
    "/server-status", "/webmail", "/cpanel", "/app", "/v1", "/swagger",
]

_SOFT_404_PATTERNS = re.compile(
    r"(?:<title[^>]*>[^<]*(?:404|not\s+found|error|page\s+unavailable)[^<]*</title>"
    r"|cannot\s+get\s+/"
    r"|the\s+requested\s+url\s+.*?\s+was\s+not\s+found"
    r"|404\s*[-:|]\s*(?:file\s+or\s+directory\s+)?not\s+found"
    r"|page\s+you\s+are\s+looking\s+for\s+(?:might\s+have\s+been\s+removed|does\s+not\s+exist))",
    re.IGNORECASE | re.DOTALL,
)


def _create_session(pool_size: int = 50) -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
    s.verify = False
    s.trust_env = False
    if config.HTTP_PROXY:
        s.proxies.update({"http": config.HTTP_PROXY, "https": config.HTTP_PROXY})
    adapter = requests.adapters.HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def _fetch_capped(session: requests.Session, url: str, timeout: int = 5, base_url: str = None) -> Tuple[int, bytes]:
    try:
        resp = session.get(url, timeout=(3, timeout), stream=True, allow_redirects=True)
        # Filter soft-404 redirects that bounce sub-paths back to the root homepage
        if base_url and resp.history and resp.url.rstrip("/") == base_url.rstrip("/"):
            resp.close()
            return 0, b""
        content = b""
        for chunk in resp.iter_content(chunk_size=8192):
            content += chunk
            if len(content) >= 65536:
                break
        resp.close()
        return resp.status_code, content[:65536]
    except requests.exceptions.RequestException:
        return 0, b""
    except Exception:
        return 0, b""


def get_custom_404_fingerprint(base_url: str, timeout: int = 5, session: requests.Session = None) -> Tuple[str, int]:
    own_session = session is None
    if own_session:
        session = _create_session(pool_size=4)
    hashes, lengths = [], []
    try:
        for _ in range(2):
            rand_path = f"/fp_detect_{hashlib.md5(str(time.time() + random.random()).encode()).hexdigest()[:12]}"
            code, body = _fetch_capped(session, base_url.rstrip("/") + rand_path, timeout=timeout)
            if code and body:
                hashes.append(hashlib.md5(body).hexdigest())
                lengths.append(len(body))
    finally:
        if own_session:
            session.close()
    if not hashes:
        return "", 0
    idx = lengths.index(max(lengths))
    return hashes[idx], lengths[idx]


def _is_wildcard_match(body: bytes, fp_hash: str, fp_len: int) -> bool:
    if not body:
        return False
    if fp_hash and hashlib.md5(body).hexdigest() == fp_hash:
        return True
    if fp_len > 0:
        diff = abs(len(body) - fp_len)
        if diff <= 5:
            return True
        # Dynamic 404 pages that echo the requested path or include a request ID/nonce
        if fp_len > 250 and (diff / fp_len) <= 0.03:
            return True
    return False


def _is_soft_404_html(text: str) -> bool:
    """Detect HTTP 200 HTML pages that are actually soft-404 error templates."""
    head = text[:4096]
    if any(t in head.lower() for t in ("<html", "<!doctype", "<head", "<body")):
        if _SOFT_404_PATTERNS.search(head):
            return True
    return False


def validate_sensitive_structure(path: str, body: str) -> bool:
    body = body.strip()
    if not body:
        return False
    lower_head = body[:2048].lower()
    is_html = any(t in lower_head for t in ("<html", "<body", "<!doctype", "<head", "<script"))

    if path.startswith("/.env"):
        if (
            not is_html
            and not body.startswith(("{", "[", "<"))
            and re.search(r"^[A-Za-z_][A-Za-z0-9_]*\s*=\s*[^\s;]+", body, re.MULTILINE)
        ):
            return True
    elif path == "/.git/HEAD":
        if not is_html and len(body) < 256 and (
            body.startswith("ref: refs/") or re.match(r"^[0-9a-f]{40}$", body)
        ):
            return True
    elif path.startswith("/.git"):
        if not is_html and (
            body.startswith("ref:") or "[core]" in body or "[remote " in body or re.match(r"^[0-9a-f]{40}$", body)
        ):
            return True
    elif path == "/.svn/entries":
        if not is_html and (
            re.search(r"(?:^|\r?\n)dir(?:\r?\n|$)", body) or "svn:" in body
        ):
            return True
    elif path in ("/composer.json", "/package.json"):
        if not is_html and body.startswith("{"):
            try:
                data = json.loads(body)
                if isinstance(data, dict) and any(
                    k in data for k in ("name", "version", "dependencies", "devDependencies", "scripts", "require")
                ):
                    return True
            except Exception:
                pass
    elif path in ("/config.php", "/wp-config.php", "/wp-config.php.bak"):
        if not is_html and (
            "<?php" in body
            or "DB_NAME" in body
            or "DB_USER" in body
            or "DB_PASSWORD" in body
            or re.search(r"define\s*\(\s*['\"]DB_", body)
        ):
            return True
    elif "id_rsa" in path:
        if not is_html and re.search(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----", body):
            return True
    elif "credentials" in path:
        if not is_html and ("aws_access_key_id" in lower_head or "aws_secret_access_key" in lower_head):
            return True
    elif path.endswith(".sql"):
        if not is_html and (
            "CREATE TABLE" in body.upper()
            or "INSERT INTO" in body.upper()
            or "MYSQL DUMP" in body.upper()
            or "POSTGRESQL DATABASE DUMP" in body.upper()
        ):
            return True
    elif path == "/phpinfo.php":
        if "<title>phpinfo()</title>" in lower_head or "php version" in lower_head and "zend" in lower_head:
            return True
    elif path == "/.htpasswd":
        if not is_html and re.search(r"^[a-zA-Z0-9_.-]+:(?:\$apr1\$|\$2[ayb]\$|\{SHA\}|[a-zA-Z0-9./]{13})", body, re.MULTILINE):
            return True
    elif path == "/docker-compose.yml":
        if not is_html and ("services:" in body and ("image:" in body or "build:" in body)):
            return True
    elif path == "/robots.txt":
        if not is_html and ("user-agent:" in lower_head or "disallow:" in lower_head or "sitemap:" in lower_head):
            return True
    elif path == "/sitemap.xml":
        if "<urlset" in lower_head or "<sitemapindex" in lower_head:
            return True
    elif path == "/.well-known/security.txt":
        if not is_html and "contact:" in lower_head:
            return True
    return False


def audit_target_directories(
    target_url: str,
    check_paths: List[str] = None,
    wordlist_file: str = None,
    log_cb: Callable[[str], None] = None,
    concurrency: int = 30,
) -> Dict:
    def log(m):
        if log_cb:
            log_cb(m)

    with _create_session(pool_size=max(concurrency * 2, 50)) as shared_session:
        if not target_url.startswith(("http://", "https://")):
            raw_host = target_url.strip("/")
            candidates = [f"https://{raw_host}", f"http://{raw_host}"]
            if not raw_host.startswith("www."):
                candidates.extend([f"https://www.{raw_host}", f"http://www.{raw_host}"])
        else:
            stripped = target_url.rstrip("/")
            scheme, rest = stripped.split("://", 1)
            alt_scheme = "http" if scheme == "https" else "https"
            candidates = [stripped, f"{alt_scheme}://{rest}"]
            if not rest.startswith("www."):
                candidates.extend([f"https://www.{rest}", f"http://www.{rest}"])

        fp_hash, fp_len = "", 0
        chosen_url = candidates[0].rstrip("/")
        for cand in candidates:
            h, l = get_custom_404_fingerprint(cand, timeout=3, session=shared_session)
            if h:
                chosen_url = cand.rstrip("/")
                fp_hash, fp_len = h, l
                break
        target_url = chosen_url

        log(f"[*] Starting Directory & Sensitive Asset Scan on: {target_url}")
        if not fp_hash:
            fp_hash, fp_len = get_custom_404_fingerprint(target_url, timeout=4, session=shared_session)
        log(f"[*] Custom-404 baseline established (Hash: {fp_hash[:10] if fp_hash else 'none'}..., Length: {fp_len} bytes)")

        paths = list(SENSITIVE_FILES)
        if check_paths:
            paths.extend(check_paths)
        else:
            wl = wordlist_file or config.COMMON_WORDLIST
            if wl and os.path.exists(wl):
                try:
                    with open(wl, "r", encoding="utf-8", errors="ignore") as f:
                        lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
                    paths.extend(lines[:1000])
                    log(f"[*] Loaded wordlist (testing top {min(len(lines), 1000)} paths)")
                except Exception:
                    paths.extend(TOP_COMMON_DIRS)
            else:
                paths.extend(TOP_COMMON_DIRS)

        cleaned, seen = [], set()
        for p in paths:
            if not p.startswith("/"):
                p = "/" + p
            if p not in seen:
                seen.add(p)
                cleaned.append(p)

        sensitive, dirs_found = [], []
        wildcard_count = [0]

        # Also fingerprint root homepage to filter SPA catch-all routes serving index.html
        _, home_body = _fetch_capped(shared_session, target_url + "/")
        home_hash = hashlib.md5(home_body).hexdigest() if home_body else ""
        home_len = len(home_body) if home_body else 0

        # Note: robots.txt, sitemap.xml, security.txt are informational directories unless real secrets
        HIGH_RISK_SENSITIVE = {
            "/.env", "/.env.local", "/.env.production", "/.env.bak",
            "/.git/HEAD", "/.git/config", "/.svn/entries",
            "/composer.json", "/package.json", "/config.php", "/wp-config.php",
            "/wp-config.php.bak", "/.aws/credentials", "/id_rsa",
            "/database.sql", "/backup.sql", "/dump.sql",
            "/phpinfo.php", "/.htpasswd", "/docker-compose.yml",
        }

        def check(path: str):
            url = target_url + path
            code, body = _fetch_capped(shared_session, url, base_url=target_url)
            if code == 0 or not body:
                return None
            if _is_wildcard_match(body, fp_hash, fp_len):
                wildcard_count[0] += 1
                return None
            if home_hash and _is_wildcard_match(body, home_hash, home_len):
                wildcard_count[0] += 1
                return None
            text = body.decode("utf-8", errors="ignore")
            if _is_soft_404_html(text):
                wildcard_count[0] += 1
                return None
            if path in HIGH_RISK_SENSITIVE:
                if code == 200 and validate_sensitive_structure(path, text):
                    return {
                        "type": "sensitive",
                        "url": url,
                        "path": path,
                        "status": code,
                        "size": len(body),
                        "verified": True,
                    }
            else:
                if code in (200, 301, 302, 403):
                    if path in SENSITIVE_FILES and code == 200 and not validate_sensitive_structure(path, text):
                        return None
                    return {
                        "type": "directory",
                        "url": url,
                        "path": path,
                        "status": code,
                        "size": len(body),
                        "verified": True,
                    }
            return None

        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            futures = [ex.submit(check, p) for p in cleaned]
            for fut in as_completed(futures):
                try:
                    r = fut.result()
                except Exception:
                    continue
                if not r:
                    continue
                if r["type"] == "sensitive":
                    sensitive.append(r)
                    log(f"[EXPOSED] {r['url']} (Status: {r['status']}, Size: {r['size']}B - VERIFIED)")
                else:
                    dirs_found.append(r)
                    log(f"[+] FOUND DIR: {r['url']} [HTTP {r['status']}] (Size: {r['size']}B)")

    log(f"[+] Directory scan complete. {len(dirs_found)} dirs, {len(sensitive)} verified leaks, {wildcard_count[0]} wildcards skipped.")
    return {
        "target_url": target_url,
        "total_paths_tested": len(cleaned),
        "wildcard_404_skipped": wildcard_count[0],
        "sensitive_findings": sensitive,
        "directory_findings": dirs_found,
    }


def sweep_additional_hosts_sensitive(
    host_urls: List[str],
    log_cb: Callable[[str], None] = None,
    concurrency: int = 20,
) -> List[Dict]:
    """
    Fast multi-host sensitive file sweep across secondary alive subdomains and non-standard web ports.
    """
    if not host_urls:
        return []

    def log(m):
        if log_cb:
            log_cb(m)

    core_sensitive = [
        "/.env", "/.git/HEAD", "/.git/config", "/config.php",
        "/wp-config.php.bak", "/phpinfo.php", "/database.sql", "/.aws/credentials",
    ]
    targets = [u.rstrip("/") for u in dict.fromkeys(host_urls) if u][:8]
    if not targets:
        return []

    log(f"[*] Multi-host sensitive sweep across {len(targets)} additional web service(s)...")
    findings: List[Dict] = []

    with _create_session(pool_size=max(concurrency * 2, 30)) as sess:
        baselines = {}
        for base in targets:
            baselines[base] = get_custom_404_fingerprint(base, timeout=3, session=sess)

        tasks = [(base, path) for base in targets for path in core_sensitive]

        def probe_item(item: Tuple[str, str]):
            base, path = item
            fp_h, fp_l = baselines.get(base, ("", 0))
            url = base + path
            code, body = _fetch_capped(sess, url, timeout=4, base_url=base)
            if code != 200 or not body:
                return None
            if _is_wildcard_match(body, fp_h, fp_l):
                return None
            text = body.decode("utf-8", errors="ignore")
            if _is_soft_404_html(text):
                return None
            if validate_sensitive_structure(path, text):
                return {
                    "type": "sensitive",
                    "url": url,
                    "path": path,
                    "status": code,
                    "size": len(body),
                    "verified": True,
                }
            return None

        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            futures = [ex.submit(probe_item, t) for t in tasks]
            for fut in as_completed(futures):
                try:
                    r = fut.result()
                    if r:
                        findings.append(r)
                        log(f"[EXPOSED] {r['url']} (Status: {r['status']}, Size: {r['size']}B - VERIFIED)")
                except Exception:
                    pass

    return findings
