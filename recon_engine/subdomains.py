"""
recon_engine/subdomains.py — Fast Passive OSINT & DNS.
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional

import requests
import urllib3

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    dns = None
    HAS_DNSPYTHON = False

from . import config
from .scope import is_in_scope, normalize_domain

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
USER_AGENT = config.USER_AGENT

COMMON_SUBDOMAIN_PREFIXES = [
    "www", "api", "dev", "staging", "uat", "test", "admin", "portal",
    "mail", "webmail", "vpn", "git", "gitlab", "jenkins", "grafana",
    "status", "docs", "cdn", "static", "assets", "auth", "sso", "login",
    "beta", "app", "dashboard", "internal", "m", "support", "blog",
]

TAKEOVER_FINGERPRINTS = {
    "github.io": ("GitHub Pages", "There isn't a GitHub Pages site here"),
    "s3.amazonaws.com": ("AWS S3", "NoSuchBucket"),
    "herokuapp.com": ("Heroku", "No such app"),
    "azurewebsites.net": ("Azure App Service", "404 Web Site not found"),
    "cloudapp.net": ("Azure CloudApp", ""),
    "trafficmanager.net": ("Azure Traffic Manager", ""),
    "fastly.net": ("Fastly CDN", "Fastly error: unknown domain"),
    "pantheonsite.io": ("Pantheon", "404 error unknown site"),
    "myshopify.com": ("Shopify", "Sorry, this shop is currently unavailable"),
    "surge.sh": ("Surge.sh", "project not found"),
    "bitbucket.io": ("Bitbucket Pages", "Repository not found"),
    "ghost.io": ("Ghost", "The thing you were looking for is no longer here"),
    "wordpress.com": ("WordPress.com", "Do you want to register"),
}


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


def _http_get_json(url: str, timeout: int = 6):
    with _create_session(pool_size=4) as session:
        for attempt in range(2):
            try:
                r = session.get(url, timeout=(3, timeout))
                if r.status_code == 200:
                    return r.json()
                if r.status_code in (400, 401, 403, 404, 429):
                    break
            except Exception:
                pass
            if attempt == 0:
                time.sleep(0.5)
    return None


def _http_get_text(url: str, timeout: int = 6):
    with _create_session(pool_size=4) as session:
        for attempt in range(2):
            try:
                r = session.get(url, timeout=(3, timeout))
                if r.status_code == 200:
                    return r.text
                if r.status_code in (400, 401, 403, 404, 429):
                    break
            except Exception:
                pass
            if attempt == 0:
                time.sleep(0.5)
    return None


def fetch_crtsh_subdomains(domain: str, timeout: int = 8) -> set:
    found = set()
    data = _http_get_json(f"https://crt.sh/?q=%.{domain}&output=json", timeout=timeout)
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            for sub in item.get("name_value", "").split("\n"):
                clean = sub.strip().lower().lstrip("*.")
                if clean and is_in_scope(clean, domain):
                    found.add(clean)
    return found


def fetch_certspotter_subdomains(domain: str, timeout: int = 8) -> set:
    found = set()
    data = _http_get_json(
        f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
        timeout=timeout,
    )
    if isinstance(data, list):
        for entry in data:
            if not isinstance(entry, dict):
                continue
            for dns_name in entry.get("dns_names", []):
                clean = str(dns_name).strip().lower().lstrip("*.")
                if clean and is_in_scope(clean, domain):
                    found.add(clean)
    return found


def fetch_anubis_subdomains(domain: str, timeout: int = 6) -> set:
    found = set()
    data = _http_get_json(f"https://jldc.me/anubis/subdomains/{domain}", timeout=timeout)
    if isinstance(data, list):
        for sub in data:
            clean = str(sub).strip().lower().lstrip("*.")
            if clean and is_in_scope(clean, domain):
                found.add(clean)
    return found


def fetch_otx_subdomains(domain: str, timeout: int = 8) -> set:
    """AlienVault OTX passive DNS."""
    found = set()
    data = _http_get_json(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
        timeout=timeout,
    )
    if isinstance(data, dict):
        for rec in data.get("passive_dns", []):
            if isinstance(rec, dict):
                host = str(rec.get("hostname", "")).strip().lower().lstrip("*.")
                if host and is_in_scope(host, domain):
                    found.add(host)
    return found


def fetch_hackertarget_subdomains(domain: str, timeout: int = 8) -> set:
    found = set()
    text = _http_get_text(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=timeout)
    if text and "error" not in text.lower()[:40] and "api count exceeded" not in text.lower():
        for line in text.splitlines():
            if "," in line:
                host = line.split(",")[0].strip().lower()
                if host and is_in_scope(host, domain):
                    found.add(host)
    return found


def resolve_host_dns(host: str) -> Optional[str]:
    if HAS_DNSPYTHON:
        try:
            res = dns.resolver.Resolver(configure=True)
            if config.DNS_RESOLVERS:
                res.nameservers = config.DNS_RESOLVERS
            res.lifetime = 2.5
            answers = res.resolve(host, "A", lifetime=2.5)
            return str(answers[0])
        except Exception:
            pass
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def detect_wildcard_dns(domain: str) -> Optional[str]:
    """Return wildcard IP if random non-existent subdomain resolves, else None."""
    rand_sub = f"wildcard-check-{int(time.time())}.{domain}"
    return resolve_host_dns(rand_sub)


def resolve_cname(host: str) -> Optional[str]:
    """Return canonical CNAME target if present, else None."""
    if not HAS_DNSPYTHON:
        return None
    try:
        res = dns.resolver.Resolver(configure=True)
        if config.DNS_RESOLVERS:
            res.nameservers = config.DNS_RESOLVERS
        res.lifetime = 2.0
        answers = res.resolve(host, "CNAME", lifetime=2.0)
        return str(answers[0].target).rstrip(".").lower()
    except Exception:
        return None


def audit_dns_security(domain: str) -> Dict:
    """Inspect SPF, DMARC, and NS records for DNS security posture."""
    info = {"spf": False, "dmarc": False, "nameservers": []}
    if not HAS_DNSPYTHON:
        return info
    try:
        res = dns.resolver.Resolver(configure=True)
        if config.DNS_RESOLVERS:
            res.nameservers = config.DNS_RESOLVERS
        res.lifetime = 2.5
        try:
            for rdata in res.resolve(domain, "TXT", lifetime=2.5):
                txt = b"".join(getattr(rdata, "strings", [])).decode("utf-8", errors="ignore").lower()
                if "v=spf1" in txt:
                    info["spf"] = True
        except Exception:
            pass
        try:
            for rdata in res.resolve(f"_dmarc.{domain}", "TXT", lifetime=2.5):
                txt = b"".join(getattr(rdata, "strings", [])).decode("utf-8", errors="ignore").lower()
                if "v=dmarc1" in txt:
                    info["dmarc"] = True
        except Exception:
            pass
        try:
            for rdata in res.resolve(domain, "NS", lifetime=2.5):
                info["nameservers"].append(str(rdata.target).rstrip(".").lower())
        except Exception:
            pass
    except Exception:
        pass
    return info


def _is_unroutable(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified
    except ValueError:
        return False


def fetch_urlscan_subdomains(domain: str, timeout: int = 8) -> set:
    """urlscan.io passive domain search."""
    found = set()
    data = _http_get_json(
        f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100",
        timeout=timeout,
    )
    if isinstance(data, dict):
        for entry in data.get("results", []):
            if not isinstance(entry, dict):
                continue
            for section in ("page", "task"):
                sec_obj = entry.get(section)
                if isinstance(sec_obj, dict):
                    host = str(sec_obj.get("domain", "")).strip().lower().lstrip("*.")
                    if host and is_in_scope(host, domain):
                        found.add(host)
    return found


def detect_waf_cdn(headers: dict) -> str:
    h = {k.lower(): v.lower() for k, v in headers.items()}
    server = h.get("server", "")
    via = h.get("via", "")
    cookies = h.get("set-cookie", "")
    if "cf-ray" in h or "cloudflare" in server:
        return "Cloudflare"
    if "x-amz-cf-id" in h or "cloudfront" in server or "cloudfront" in via:
        return "AWS CloudFront"
    if "x-amzn-requestid" in h or "awselb" in server or "awselb" in cookies:
        return "AWS ALB/ELB"
    if "x-azure-ref" in h or "x-msedge-ref" in h:
        return "Azure CDN / FrontDoor"
    if "x-sucuri-id" in h or "sucuri" in server:
        return "Sucuri WAF"
    if "x-iinfo" in h or "incap_ses" in cookies or "visid_incap" in cookies:
        return "Imperva Incapsula"
    if "akamai" in server or "x-akamai-transformed" in h or "akamai" in via:
        return "Akamai"
    if "fastly" in server or "x-fastly-request-id" in h or "varnish" in via and "x-served-by" in h:
        return "Fastly CDN"
    if "x-vercel-id" in h or "vercel" in server:
        return "Vercel"
    if "x-nf-request-id" in h or "netlify" in server:
        return "Netlify"
    if "bigip" in cookies or "big-ip" in server:
        return "F5 BIG-IP"
    if "google" in via or server in ("gws", "esf", "sffe"):
        return "Google Cloud CDN"
    return "Direct / Unknown"


def check_security_headers(headers: dict) -> dict:
    h = {k.lower(): v for k, v in headers.items()}
    return {
        "hsts": "strict-transport-security" in h,
        "csp": "content-security-policy" in h,
        "x_frame_options": "x-frame-options" in h,
        "x_content_type": "x-content-type-options" in h,
    }


def probe_http_liveness(host: str, session: requests.Session = None, timeout: int = 5) -> Dict:
    own_session = session is None
    if own_session:
        session = _create_session(pool_size=4)

    try:
        for scheme in ("https://", "http://"):
            url = f"{scheme}{host}"
            try:
                resp = session.get(url, timeout=(3, timeout), allow_redirects=True, stream=True)
                raw_bytes = b""
                for chunk in resp.iter_content(chunk_size=4096):
                    raw_bytes += chunk
                    if len(raw_bytes) >= 16384:
                        break
                resp.close()
                body = raw_bytes.decode("utf-8", errors="ignore")
                m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                title = re.sub(r"\s+", " ", m.group(1)).strip()[:100] if m else ""
                server = resp.headers.get("Server", "Unknown")
                powered = resp.headers.get("X-Powered-By", "")
                tech = f"{server} {powered}".strip() if powered else server
                return {
                    "alive": True,
                    "url": url,
                    "code": resp.status_code,
                    "title": title or "OK",
                    "server": tech or "Web Server",
                    "waf": detect_waf_cdn(resp.headers),
                    "sec_headers": check_security_headers(resp.headers),
                }
            except requests.exceptions.RequestException:
                continue
            except Exception:
                continue
    finally:
        if own_session:
            session.close()

    return {
        "alive": False,
        "url": f"http://{host}",
        "code": 0,
        "title": "Unreachable",
        "server": "None",
        "waf": "None",
        "sec_headers": {
            "hsts": False,
            "csp": False,
            "x_frame_options": False,
            "x_content_type": False,
        },
    }


def enumerate_subdomains(
    domain: str,
    log_cb: Callable[[str], None] = None,
    concurrency: int = 30,
) -> Dict:
    domain = normalize_domain(domain)

    def log(m):
        if log_cb:
            log_cb(m)

    log(f"[*] Querying passive sources for: {domain}")
    all_subs = {domain}
    if not domain.startswith("www."):
        all_subs.add(f"www.{domain}")

    sources = [
        ("crt.sh", fetch_crtsh_subdomains),
        ("CertSpotter", fetch_certspotter_subdomains),
        ("AnubisDB", fetch_anubis_subdomains),
        ("HackerTarget", fetch_hackertarget_subdomains),
        ("AlienVault OTX", fetch_otx_subdomains),
        ("URLScan.io", fetch_urlscan_subdomains),
    ]

    with ThreadPoolExecutor(max_workers=len(sources)) as ex:
        futures = {ex.submit(fn, domain): name for name, fn in sources}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                res = fut.result()
                all_subs.update(res)
                log(f"[+] [{name}] Discovered {len(res)} subdomains.")
            except Exception as e:
                log(f"[!] [{name}] Query error: {e}")

    log(f"[+] Aggregated {len(all_subs)} candidate subdomains. Resolving DNS & probing HTTP...")
    records: List[Dict] = []
    alive = 0
    internal = 0

    wildcard_ip = detect_wildcard_dns(domain)
    wc_probe = None
    passive_subs = set(all_subs)
    if wildcard_ip:
        log(f"[!] Wildcard DNS detected (*.{domain} -> {wildcard_ip}); baseline-filtering phantom hosts...")
    else:
        # Add active DNS prefix candidates when wildcard DNS is not active
        for prefix in COMMON_SUBDOMAIN_PREFIXES:
            all_subs.add(f"{prefix}.{domain}")

    dns_sec = audit_dns_security(domain)
    log(
        f"[*] DNS Posture: SPF={'Present' if dns_sec['spf'] else 'Missing'}, "
        f"DMARC={'Present' if dns_sec['dmarc'] else 'Missing'}, "
        f"NS={len(dns_sec['nameservers'])}"
    )
    takeover_findings: List[Dict] = []

    with _create_session(pool_size=max(concurrency * 2, 50)) as shared_session:
        if wildcard_ip:
            wc_probe = probe_http_liveness(
                f"wildcard-check-{int(time.time())}.{domain}",
                session=shared_session,
                timeout=3,
            )

        def check(sub: str):
            ip = resolve_host_dns(sub)
            cname = resolve_cname(sub)
            takeover_provider = None
            if cname:
                for pat, (prov_name, _) in TAKEOVER_FINGERPRINTS.items():
                    if cname.endswith(pat):
                        takeover_provider = prov_name
                        break

            if not ip and not config.HTTP_PROXY:
                is_dangling_takeover = bool(takeover_provider)
                return {
                    "subdomain": sub,
                    "ip": f"CNAME -> {cname} (DANGLING)" if is_dangling_takeover else "DNS Unresolved",
                    "cname": cname or "",
                    "takeover_vulnerable": is_dangling_takeover,
                    "takeover_provider": takeover_provider or "",
                    "alive": False,
                    "internal_only": False,
                    "url": f"http://{sub}",
                    "status_code": 0,
                    "title": f"TAKEOVER RISK ({takeover_provider})" if is_dangling_takeover else "NXDOMAIN",
                    "server": "None",
                    "waf": "None",
                    "sec_headers": {
                        "hsts": False,
                        "csp": False,
                        "x_frame_options": False,
                        "x_content_type": False,
                    },
                }

            if ip and _is_unroutable(ip):
                return {
                    "subdomain": sub,
                    "ip": ip,
                    "cname": cname or "",
                    "takeover_vulnerable": False,
                    "takeover_provider": "",
                    "alive": False,
                    "internal_only": True,
                    "url": f"https://{sub}",
                    "status_code": 0,
                    "title": "Internal",
                    "server": "N/A",
                    "waf": "N/A",
                    "sec_headers": {
                        "hsts": False,
                        "csp": False,
                        "x_frame_options": False,
                        "x_content_type": False,
                    },
                }

            probe = probe_http_liveness(sub, session=shared_session)
            is_alive = probe["alive"]
            title_val = probe["title"]

            # Filter wildcard DNS catch-all clones on non-primary subdomains
            if (
                is_alive
                and wildcard_ip
                and ip == wildcard_ip
                and sub not in (domain, f"www.{domain}")
                and wc_probe
                and probe["code"] == wc_probe["code"]
                and probe["title"] == wc_probe["title"]
            ):
                is_alive = False
                title_val = "Wildcard DNS Catch-All"

            return {
                "subdomain": sub,
                "ip": ip or "DNS Unresolved",
                "cname": cname or "",
                "takeover_vulnerable": False,
                "takeover_provider": takeover_provider or "",
                "alive": is_alive,
                "internal_only": False,
                "url": probe["url"],
                "status_code": probe["code"],
                "title": title_val,
                "server": probe["server"],
                "waf": probe["waf"],
                "sec_headers": probe["sec_headers"],
            }

        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            futures = [ex.submit(check, s) for s in all_subs]
            for fut in as_completed(futures):
                try:
                    rec = fut.result()
                    if rec.get("takeover_vulnerable"):
                        takeover_findings.append(rec)
                        log(f"[EXPOSED] Subdomain Takeover Risk: {rec['subdomain']} -> {rec.get('cname')}")
                    # Keep all passive-discovered subdomains plus any resolved active brute-force subdomains
                    if rec["ip"] != "DNS Unresolved" or rec["subdomain"] in passive_subs or rec.get("takeover_vulnerable"):
                        records.append(rec)
                    if rec["alive"]:
                        alive += 1
                        log(f"[+] ALIVE: {rec['url']} [{rec['status_code']}] - IP: {rec['ip']} - Title: {rec['title']}")
                    elif rec["internal_only"]:
                        internal += 1
                except Exception:
                    pass

    # Prioritize apex domain and www.<domain> first among alive records so downstream
    # crawler / directory scanners target the primary site first.
    def _sort_key(r: Dict):
        sub = r["subdomain"]
        is_primary = 0 if sub == domain else (1 if sub == f"www.{domain}" else 2)
        return (not r["alive"], is_primary, sub)

    records.sort(key=_sort_key)

    return {
        "domain": domain,
        "total_subdomains": len(records),
        "alive_count": alive,
        "internal_only_count": internal,
        "dns_security": dns_sec,
        "takeover_findings": takeover_findings,
        "records": records,
        "alive_hosts": [r["url"] for r in records if r["alive"]],
        "alive_fqdns": [r["subdomain"] for r in records if r["alive"]],
    }
