"""
Normalization, validation, SSRF guard, thread-safe rate limiter.
Public API preserved: normalize_domain, validate_target, is_in_scope, RateLimiter, USER_AGENT.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import threading
import time
from typing import Tuple
from urllib.parse import urlparse

from . import config

USER_AGENT = config.USER_AGENT

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

_ILLEGAL_CHARS = set(";&|$` <>\"'\n\r\t\\")
_BLOCKED_NETS = [ipaddress.ip_network(n) for n in config.BLOCKED_NETWORKS]
PRIVATE_NETWORKS = _BLOCKED_NETS


def normalize_domain(raw_input: str) -> str:
    """
    Extract base hostname from URL, host:port, or raw domain.
        'https://srmist.edu.in/portal'          -> 'srmist.edu.in'
        'srmist.edu.in:8443'                    -> 'srmist.edu.in'
        'sub.test.xyz.rh'                       -> 'sub.test.xyz.rh'
        'https://user:pass@host.com/x'          -> 'host.com'
    """
    if not raw_input:
        return ""
    text = raw_input.strip().lower()

    if "://" in text:
        try:
            return (urlparse(text).hostname or "").strip(".")
        except Exception:
            return ""

    for sep in ("/", "?", "#"):
        if sep in text:
            text = text.split(sep, 1)[0]

    if "@" in text:
        text = text.rsplit("@", 1)[1]

    if text.startswith("[") and "]" in text:
        return text[1:text.index("]")].lower()

    if ":" in text:
        text = text.split(":", 1)[0]

    return text.strip(".")


def _has_illegal_chars(s: str) -> bool:
    return any(c in _ILLEGAL_CHARS for c in s)


def _resolve(host: str):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def validate_target(domain: str) -> Tuple[bool, str]:
    """
    (is_valid, error_message).
    Blocks loopback/link-local/metadata. Permits RFC1918 for split-horizon DNS.
    """
    if not domain:
        return False, "Target domain cannot be empty."

    domain = normalize_domain(domain)
    if not domain:
        return False, "Target could not be normalized to a hostname."

    if _has_illegal_chars(domain):
        return False, "Invalid characters detected in target domain."

    try:
        ipaddress.ip_address(domain)
        return False, f"'{domain}' is a literal IP address; supply a domain name instead."
    except ValueError:
        pass

    if not DOMAIN_REGEX.match(domain):
        return False, f"'{domain}' is not a valid fully qualified domain name (FQDN)."

    ip_str = _resolve(domain)
    if ip_str:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"DNS returned unparsable address: {ip_str}"
        for net in _BLOCKED_NETS:
            if ip_obj in net:
                return False, (
                    f"Target resolves to {ip_str} inside blocked range {net}. "
                    "Prohibited by scope controls."
                )
    return True, ""


def is_in_scope(candidate_host: str, root_domain: str) -> bool:
    if not candidate_host or not root_domain:
        return False
    cand = normalize_domain(candidate_host)
    root = normalize_domain(root_domain)
    if not cand or not root:
        return False
    return cand == root or cand.endswith("." + root)


class RateLimiter:
    """
    Thread-safe global rate limiter. Enforces at most max_rate calls/sec
    across ALL threads sharing this instance.
    """

    def __init__(self, max_rate: float = config.DEFAULT_RATE_PER_SEC):
        self.interval = 1.0 / max(float(max_rate), 1.0)
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            if self._next_allowed == 0.0:
                self._next_allowed = now + self.interval
                return
            if now < self._next_allowed:
                sleep_dur = self._next_allowed - now
                time.sleep(sleep_dur)
                now = time.monotonic()
            self._next_allowed = max(self._next_allowed + self.interval, now)
