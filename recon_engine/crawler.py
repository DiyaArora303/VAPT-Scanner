"""
recon_engine/crawler.py — Fast Spider & Secret Extraction.
"""
from __future__ import annotations

import base64
import json
import re
import ssl
import urllib.parse
import urllib.robotparser
from collections import deque
from typing import Callable, Dict, List, Set, Tuple

import requests
import urllib3

from . import config
from .scope import USER_AGENT, is_in_scope, normalize_domain

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

API_REGEX = re.compile(
    r"""(?:"|')(/(?:api|v[0-9]+|rest|auth|graphql|oauth|webhook|internal|user|admin|download|upload|data|login)[a-zA-Z0-9_\-/\.\?=]*)""",
    re.IGNORECASE,
)
SECRET_PATTERNS = {
    "AWS Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Google Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Stripe Key": re.compile(r"(?:sk|rk)_live_[0-9a-zA-Z]{24,99}"),
    "GitHub Token": re.compile(r"(?:gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59})"),
    "Slack Token": re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,48}"),
    "Slack Webhook": re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}"),
    "SendGrid Key": re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
    "Private Key": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    "JWT Token": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}"),
}
_EXAMPLE_AWS_KEYS = {"AKIAIOSFODNN7EXAMPLE", "AKIAI44QH8DHBEXAMPLE"}
STATIC_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf",
    ".zip", ".tar.gz",
)


def _create_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })
    s.verify = False
    s.trust_env = False
    if config.HTTP_PROXY:
        s.proxies.update({"http": config.HTTP_PROXY, "https": config.HTTP_PROXY})
    adapter = requests.adapters.HTTPAdapter(pool_connections=20, pool_maxsize=20)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def _canonical_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    path = parsed.path or "/"
    return urllib.parse.urlunparse((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        path,
        parsed.params,
        parsed.query,
        "",
    ))


def fetch_page_content(session_or_url, url: str = None, timeout: int = 5) -> Tuple[int, str, str]:
    """
    Fetch web page. Supports both:
      - fetch_page_content(url, timeout=5)
      - fetch_page_content(session, url, timeout=5)
    Returns (status_code, content_type, text_content).
    """
    own_session = isinstance(session_or_url, str)
    if own_session:
        target_url = session_or_url
        session = _create_session()
    else:
        session = session_or_url
        target_url = url

    try:
        resp = session.get(target_url, timeout=(3, timeout), allow_redirects=True, stream=True)
        raw_bytes = b""
        for chunk in resp.iter_content(chunk_size=8192):
            raw_bytes += chunk
            if len(raw_bytes) >= 150000:
                break
        resp.close()
        ctype = resp.headers.get("Content-Type", "")
        text = raw_bytes.decode("utf-8", errors="ignore")
        return resp.status_code, ctype, text
    except Exception:
        return 0, "", ""
    finally:
        if own_session:
            session.close()


def _is_valid_jwt(token: str) -> bool:
    """Verify JWT JOSE header decodes to a JSON object with standard JWT keys."""
    try:
        header_b64 = token.split(".", 1)[0]
        pad = "=" * ((4 - len(header_b64) % 4) % 4)
        raw = base64.urlsafe_b64decode(header_b64 + pad).decode("utf-8", errors="strict")
        hdr = json.loads(raw)
        return isinstance(hdr, dict) and any(k in hdr for k in ("alg", "typ", "kid", "enc"))
    except Exception:
        return False


def extract_secrets_from_text(text: str) -> List[Dict[str, str]]:
    found = []
    for name, pattern in SECRET_PATTERNS.items():
        for m in set(pattern.findall(text)):
            if len(m) <= 5:
                continue
            if name == "AWS Key" and m in _EXAMPLE_AWS_KEYS:
                continue
            if name == "JWT Token" and not _is_valid_jwt(m):
                continue
            found.append({"type": name, "match": m})
    return found


def extract_links_from_html(base_url: str, html_text: str, root_domain: str = None) -> Tuple[Set[str], Set[str], Set[str]]:
    """
    Extract (internal_links, external_links, script_sources) from HTML.
    """
    internal: Set[str] = set()
    external: Set[str] = set()
    scripts: Set[str] = set()

    parsed_base = urllib.parse.urlparse(base_url)
    base_host = normalize_domain(root_domain) if root_domain else parsed_base.netloc.split(":")[0].lower()

    def _classify_link(raw_href: str) -> None:
        href = (raw_href or "").strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            return
        full_url = _canonical_url(urllib.parse.urljoin(base_url, href).split("#")[0])
        parsed = urllib.parse.urlparse(full_url)
        if parsed.scheme not in ("http", "https"):
            return
        cand_host = (parsed.hostname or "").lower()
        if cand_host and is_in_scope(cand_host, base_host):
            internal.add(full_url)
        elif cand_host:
            external.add(full_url)

    if HAS_BS4:
        soup = BeautifulSoup(html_text, "html.parser")
        for a in soup.find_all(["a", "area"], href=True):
            _classify_link(a["href"])
        for form in soup.find_all("form", action=True):
            _classify_link(form["action"])
        for frame in soup.find_all(["iframe", "frame"], src=True):
            _classify_link(frame["src"])
        for s in soup.find_all("script", src=True):
            src = (s["src"] or "").strip()
            if src:
                scripts.add(urllib.parse.urljoin(base_url, src).split("#")[0])
    else:
        for href in re.findall(r'href=["\'](.*?)["\']', html_text, re.IGNORECASE):
            _classify_link(href)
        for src in re.findall(r'<script[^>]+src=["\'](.*?)["\']', html_text, re.IGNORECASE):
            if src.strip():
                scripts.add(urllib.parse.urljoin(base_url, src.strip()).split("#")[0])

    return internal, external, scripts


def _load_robots(session: requests.Session, base_url: str) -> urllib.robotparser.RobotFileParser | None:
    """Safely load robots.txt with strict timeout so it never hangs."""
    robots_url = urllib.parse.urljoin(base_url, "/robots.txt")
    code, ctype, text = fetch_page_content(session, robots_url, timeout=3)
    if code == 200 and text and "html" not in ctype.lower():
        rp = urllib.robotparser.RobotFileParser()
        rp.parse(text.splitlines())
        return rp
    return None


def _harvest_robots_paths(session: requests.Session, base_url: str) -> List[str]:
    """Extract Disallow/Allow routes from robots.txt as discovery seeds."""
    harvested: List[str] = []
    robots_url = urllib.parse.urljoin(base_url, "/robots.txt")
    code, ctype, text = fetch_page_content(session, robots_url, timeout=3)
    if code == 200 and text and "html" not in ctype.lower() and "user-agent:" in text.lower():
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            low = line.lower()
            if low.startswith(("disallow:", "allow:")):
                path = line.split(":", 1)[1].strip().lstrip("*")
                if path.startswith("/") and len(path) > 1 and "*" not in path:
                    harvested.append(urllib.parse.urljoin(base_url, path))
    return harvested[:15]


def crawl_target(
    start_url: str,
    root_domain: str = None,
    max_depth: int = 2,
    max_pages: int = 30,
    log_cb: Callable[[str], None] = None,
) -> Dict:
    session = _create_session()
    prefetched: Dict[str, Tuple[int, str, str]] = {}

    try:
        if not start_url.startswith(("http://", "https://")):
            raw_host = start_url.strip("/")
            candidates = [f"https://{raw_host}", f"http://{raw_host}"]
            if not raw_host.startswith("www."):
                candidates.extend([f"https://www.{raw_host}", f"http://www.{raw_host}"])
        else:
            parsed_init = urllib.parse.urlparse(start_url)
            host_init = parsed_init.netloc
            path_init = parsed_init.path or ""
            alt_scheme = "http" if parsed_init.scheme == "https" else "https"
            candidates = [
                start_url,
                f"{alt_scheme}://{host_init}{path_init}",
            ]
            if host_init and not host_init.startswith("www."):
                candidates.extend([
                    f"https://www.{host_init}{path_init}",
                    f"http://www.{host_init}{path_init}",
                ])

        chosen_url = candidates[0]
        for cand in candidates:
            c_code, c_type, c_html = fetch_page_content(session, cand, timeout=4)
            if c_code > 0:
                chosen_url = _canonical_url(cand)
                prefetched[chosen_url] = (c_code, c_type, c_html)
                break
        start_url = _canonical_url(chosen_url)

        if not root_domain:
            root_domain = urllib.parse.urlparse(start_url).netloc
        root_domain = normalize_domain(root_domain)
        if root_domain.startswith("www.") and root_domain.count(".") >= 2:
            root_domain = root_domain[4:]

        def log(m):
            if log_cb:
                log_cb(m)

        log(f"[*] Starting Web Crawler & Link Spider on: {start_url}")
        log(f"[*] Scope Boundary: *.{root_domain} (Max Depth: {max_depth}, Max Pages: {max_pages})")

        rp = _load_robots(session, start_url)

        visited: Set[str] = set()
        queue = deque([(start_url, 0)])
        for r_url in _harvest_robots_paths(session, start_url):
            queue.append((r_url, 1))
        pages: List[Dict] = []
        apis: Set[str] = set()
        scripts: Set[str] = set()
        ext: Set[str] = set()
        secrets: List[Dict[str, str]] = []

        while queue and len(visited) < max_pages:
            url, depth = queue.popleft()
            url = _canonical_url(url)
            if url in visited:
                continue
            # Respect robots.txt for sub-pages (depth > 0), but always crawl the entry URL (depth == 0)
            if depth > 0 and rp and not rp.can_fetch(USER_AGENT, url):
                continue

            visited.add(url)
            if any(url.lower().endswith(e) for e in STATIC_EXTENSIONS):
                pages.append({"url": url, "status": 200, "depth": depth, "type": "asset"})
                continue

            log(f"[*] [Depth {depth}] Crawling: {url}")
            if url in prefetched:
                code, ctype, html = prefetched.pop(url)
            else:
                code, ctype, html = fetch_page_content(session, url)
            if code == 0:
                continue

            pages.append({
                "url": url,
                "status": code,
                "depth": depth,
                "type": "page" if "html" in ctype.lower() else "file",
            })

            if url.endswith(".js") or "javascript" in ctype.lower():
                for sec in extract_secrets_from_text(html):
                    sec["url"] = url
                    if sec not in secrets:
                        secrets.append(sec)
                        log(f"[EXPOSED] {sec['type']} found in {url}!")

            if "html" in ctype.lower() or not ctype:
                for sec in extract_secrets_from_text(html):
                    sec["url"] = url
                    if sec not in secrets:
                        secrets.append(sec)
                        log(f"[EXPOSED] {sec['type']} found in {url}!")

                internal_links, external_links, page_scripts = extract_links_from_html(
                    url, html, root_domain=root_domain
                )
                scripts.update(page_scripts)
                ext.update(external_links)

                if depth < max_depth:
                    for link in internal_links:
                        if link not in visited:
                            queue.append((link, depth + 1))

                for m in API_REGEX.findall(html):
                    cand_api = urllib.parse.urljoin(url, m)
                    if not any(cand_api.lower().split("?", 1)[0].endswith(e) for e in STATIC_EXTENSIONS):
                        apis.add(cand_api)

        for js in list(scripts)[:15]:
            if is_in_scope(urllib.parse.urlparse(js).netloc, root_domain):
                code, _, content = fetch_page_content(session, js)
                if code == 200:
                    for m in API_REGEX.findall(content):
                        cand_api = urllib.parse.urljoin(js, m)
                        if not any(cand_api.lower().split("?", 1)[0].endswith(e) for e in STATIC_EXTENSIONS):
                            apis.add(cand_api)
                    for sec in extract_secrets_from_text(content):
                        sec["url"] = js
                        if sec not in secrets:
                            secrets.append(sec)
                            log(f"[EXPOSED] {sec['type']} found in JS: {js}!")
                    # Check for exposed JavaScript Source Map (.js.map)
                    if js.split("?", 1)[0].endswith(".js"):
                        map_url = js.split("?", 1)[0] + ".map"
                        m_code, m_type, m_body = fetch_page_content(session, map_url, timeout=3)
                        if (
                            m_code == 200
                            and "html" not in m_type.lower()
                            and m_body.strip().startswith("{")
                            and '"version"' in m_body[:512]
                            and '"sources"' in m_body[:2048]
                        ):
                            sm_sec = {"type": "JS SourceMap (.map)", "match": "Unminified Source Map Exposed", "url": map_url}
                            if sm_sec not in secrets:
                                secrets.append(sm_sec)
                                log(f"[EXPOSED] JS SourceMap (.map) found at: {map_url}!")

        log(f"[+] Crawler finished. Scanned {len(visited)} pages, discovered {len(pages)} internal paths, "
            f"{len(apis)} API endpoints, {len(scripts)} script assets, and {len(secrets)} secrets.")
        return {
            "start_url": start_url,
            "root_domain": root_domain,
            "total_crawled": len(visited),
            "pages": pages,
            "api_endpoints": sorted(apis),
            "scripts": sorted(scripts),
            "external_references": sorted(ext)[:50],
            "exposed_secrets": secrets,
        }
    finally:
        session.close()
