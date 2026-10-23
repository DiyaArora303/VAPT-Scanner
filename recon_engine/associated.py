"""
Horizontal reconnaissance: TLS SANs + Certificate Transparency siblings.

Fixes vs. prior version:
  - BUG-4: crt.sh query now retries with exponential backoff.
  - Tries both apex and www host for TLS SAN extraction (cert may differ).
  - Logs each sub-step separately so failures are visible.
"""
from __future__ import annotations

import json
import socket
import ssl
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List

from . import config
from .scope import DOMAIN_REGEX, normalize_domain

USER_AGENT = config.USER_AGENT


def _http_get_json(url: str, timeout: int = 8, retries: int = 2):
    delay = config.DEFAULT_BACKOFF
    for attempt in range(retries):
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8", errors="ignore"))
        except urllib.error.HTTPError as e:
            if e.code in (400, 401, 403, 404, 429):
                return None
        except Exception:
            pass
        if attempt < retries - 1:
            time.sleep(delay)
            delay *= config.DEFAULT_BACKOFF
    return None


def _tls_sans_for_host(host: str, timeout: int = 5) -> set:
    """Extract DNS SANs from the peer certificate of one host."""
    sans = set()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, 443), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert()
                if cert and "subjectAltName" in cert:
                    for typ, val in cert["subjectAltName"]:
                        if typ == "DNS":
                            c = val.strip().lower().lstrip("*.")
                            if c and DOMAIN_REGEX.match(c):
                                sans.add(c)
    except Exception:
        pass
    return sans


def get_tls_sans(domain: str, timeout: int = 5) -> set:
    """Try apex AND www concurrently — certs may differ between hosts."""
    sans = set()
    hosts = [domain] if domain.startswith("www.") else [domain, f"www.{domain}"]
    with ThreadPoolExecutor(max_workers=len(hosts)) as ex:
        futures = [ex.submit(_tls_sans_for_host, h, timeout) for h in hosts]
        for fut in as_completed(futures):
            try:
                sans.update(fut.result())
            except Exception:
                pass
    sans.discard(domain)
    return sans


def get_crtsh_associated(domain: str, timeout: int = 8) -> List[Dict[str, str]]:
    results: List[Dict[str, str]] = []
    seen = set()
    data = _http_get_json(
        f"https://crt.sh/?q={domain}&output=json",
        timeout=timeout, retries=2,
    )
    if isinstance(data, list):
        for entry in data:
            nv = entry.get("name_value", "") if isinstance(entry, dict) else ""
            for item in nv.split("\n"):
                item = item.strip().lower().lstrip("*.")
                if item and item not in seen and item != domain and DOMAIN_REGEX.match(item):
                    seen.add(item)
                    results.append({
                        "associated_domain": item,
                        "source": "Certificate Transparency (crt.sh)",
                        "cert_issuer": (entry.get("issuer_name", "Unknown") or "")[:60],
                    })

    # Supplement / fallback with CertSpotter when crt.sh is slow or sparse
    if len(results) < 5:
        cs_data = _http_get_json(
            f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
            timeout=timeout, retries=1,
        )
        if isinstance(cs_data, list):
            for entry in cs_data:
                if not isinstance(entry, dict):
                    continue
                for dns_name in entry.get("dns_names", []):
                    item = str(dns_name).strip().lower().lstrip("*.")
                    if item and item not in seen and item != domain and DOMAIN_REGEX.match(item):
                        seen.add(item)
                        results.append({
                            "associated_domain": item,
                            "source": "Certificate Transparency (CertSpotter)",
                            "cert_issuer": "CT Log",
                        })

    return results[:30]


def discover_associated_domains(
    domain: str,
    log_cb: Callable[[str], None] = None,
) -> List[Dict[str, str]]:
    domain = normalize_domain(domain)
    findings: List[Dict[str, str]] = []
    seen = set()

    def log(m):
        if log_cb:
            log_cb(m)

    log(f"[*] Horizontal recon for: {domain}")

    # ── Step A: TLS SANs ──
    log("[*] Step A: Extracting TLS SANs (apex + www)...")
    try:
        sans = get_tls_sans(domain)
        log(f"[+] Step A: {len(sans)} SAN entries found")
        for san in sans:
            if san not in seen and san != domain:
                seen.add(san)
                findings.append({
                    "domain": san,
                    "relationship": "TLS SubjectAltName (co-hosted / sister asset)",
                    "source": "SSL/TLS Certificate",
                })
                log(f"[+] TLS SAN: {san}")
    except Exception as e:
        log(f"[!] Step A failed: {e}")

    # ── Step B: CT logs ──
    log("[*] Step B: Querying Certificate Transparency (crt.sh)...")
    try:
        ct_entries = get_crtsh_associated(domain)
        log(f"[+] Step B: {len(ct_entries)} CT entries found")
        for entry in ct_entries:
            item = entry["associated_domain"]
            if item not in seen and item != domain:
                seen.add(item)
                findings.append({
                    "domain": item,
                    "relationship": "Shared CT / CA history",
                    "source": entry.get("source", "CT Logs"),
                })
                log(f"[+] CT entity: {item}")
    except Exception as e:
        log(f"[!] Step B failed: {e}")

    log(f"[+] Associated domains total: {len(findings)}")
    return findings