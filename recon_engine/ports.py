"""
Concurrent TCP port scanner with TLS-aware banner grabbing.
Ports 443/8443/9443/10443 are wrapped in SSL before HTTP probe.
"""
from __future__ import annotations

import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List

from . import config
from .scope import normalize_domain

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    1433: "MSSQL", 3000: "Node/Dev", 3306: "MySQL", 3389: "RDP",
    5000: "Flask/Dev", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8081: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "Jupyter/HTTP-Alt", 9000: "PHP-FPM/Admin",
    9200: "Elasticsearch", 27017: "MongoDB",
}

EXTENDED_PORTS = {
    **COMMON_PORTS,
    20: "FTP-Data", 69: "TFTP", 81: "HTTP-Alt", 88: "Kerberos",
    111: "RPCBind", 123: "NTP", 135: "MSRPC", 139: "NetBIOS",
    161: "SNMP", 389: "LDAP", 465: "SMTPS", 514: "Syslog",
    587: "SMTP-Sub", 636: "LDAPS", 873: "Rsync", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1521: "Oracle-DB",
    1723: "PPTP", 2049: "NFS", 2082: "cPanel", 2083: "cPanel-SSL",
    2086: "WHM", 2087: "WHM-SSL", 2181: "ZooKeeper", 2375: "Docker",
    2376: "Docker-TLS", 3128: "Squid-Proxy", 3690: "SVN", 4000: "Dev-HTTP",
    4443: "HTTPS-Alt", 4567: "Sinatra", 4848: "GlassFish", 5001: "Synology/HTTPS",
    5601: "Kibana", 5672: "RabbitMQ", 5984: "CouchDB", 6443: "Kubernetes-API",
    7001: "WebLogic", 7474: "Neo4j", 8008: "HTTP-Alt", 8082: "HTTP-Alt",
    8088: "HTTP-Alt", 8090: "Confluence/HTTP", 8161: "ActiveMQ", 8200: "Vault",
    8500: "Consul", 8880: "HTTP-Alt", 9001: "Supervisor/Tor", 9042: "Cassandra",
    9090: "Prometheus/WebSM", 9092: "Kafka", 9300: "Elasticsearch-Cluster",
    9418: "Git", 9443: "VMware/HTTPS-Alt", 10000: "Webmin", 10443: "HTTPS-Alt",
    11211: "Memcached", 15672: "RabbitMQ-Mgmt",
}

WEB_PORTS_ONLY = [80, 443, 3000, 5000, 8000, 8080, 8081, 8443, 8888, 9000]
INFRA_PORTS = sorted(COMMON_PORTS.keys())
ALL_SCAN_PORTS = sorted(EXTENDED_PORTS.keys())

_TLS_PORTS = config.TLS_PORTS
_HTTP_PORTS = config.HTTP_PORTS


def grab_port_banner(host: str, port: int, timeout: float = 2.0) -> str:
    is_tls = port in _TLS_PORTS or port in {465, 636, 993, 995, 2083, 2087, 2376, 4443, 5001, 6443}
    svc_default = EXTENDED_PORTS.get(port, COMMON_PORTS.get(port, "Open Port"))
    tls_ver = ""
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        if is_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                sock = ctx.wrap_socket(raw, server_hostname=host)
                tls_ver = sock.version() or ""
            except Exception:
                raw.close()
                return svc_default
        else:
            sock = raw

        with sock:
            sock.settimeout(timeout)
            if port in _HTTP_PORTS or port in {9200, 2375, 5601, 8500, 9090, 15672}:
                try:
                    req_bytes = (
                        f"HEAD / HTTP/1.0\r\n"
                        f"Host: {host}\r\n"
                        f"User-Agent: {config.USER_AGENT}\r\n"
                        f"Accept: */*\r\n"
                        f"Connection: close\r\n\r\n"
                    ).encode("utf-8", errors="ignore")
                    sock.sendall(req_bytes)
                    data = sock.recv(1024).decode("utf-8", errors="ignore")
                    suffix = f" ({tls_ver})" if tls_ver else ""
                    for line in data.splitlines():
                        if line.lower().startswith("server:"):
                            return (line.strip() + suffix)[:120]
                    lines = data.splitlines()
                    if lines:
                        return (lines[0].strip() + suffix)[:120]
                except Exception:
                    pass
            elif port == 6379:
                try:
                    sock.sendall(b"PING\r\n")
                    data = sock.recv(128).decode("utf-8", errors="ignore").strip()
                    if "+PONG" in data:
                        return "Redis (UNAUTHENTICATED +PONG)"
                    if "-NOAUTH" in data:
                        return "Redis (Auth Required)"
                except Exception:
                    pass
            elif port == 11211:
                try:
                    sock.sendall(b"version\r\n")
                    data = sock.recv(128).decode("utf-8", errors="ignore").strip()
                    if data.startswith("VERSION"):
                        return f"Memcached (UNAUTHENTICATED {data.splitlines()[0]})"[:120]
                except Exception:
                    pass
            else:
                try:
                    data = sock.recv(256).decode("utf-8", errors="ignore").strip()
                    if data:
                        return data.splitlines()[0][:120]
                except Exception:
                    pass
    except Exception:
        pass
    return f"{svc_default} ({tls_ver})" if tls_ver else svc_default


def scan_single_host_ports(
    host: str,
    ports: List[int] = None,
    timeout: float = 1.5,
    log_cb: Callable[[str], None] = None,
) -> List[Dict]:
    host = normalize_domain(host)
    if ports is None:
        ports = sorted(COMMON_PORTS.keys())

    try:
        target_ip = socket.gethostbyname(host)
    except Exception:
        target_ip = host

    open_ports: List[Dict] = []

    def probe(p: int):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                t0 = time.monotonic()
                if s.connect_ex((target_ip, p)) == 0:
                    dt = time.monotonic() - t0
                    svc_name = EXTENDED_PORTS.get(p, COMMON_PORTS.get(p, "Custom"))
                    banner = grab_port_banner(host, p, timeout=timeout)
                    # Filter local transparent proxy SYN-ACK interception on proxy ports
                    if p in (8080, 8081, 8888, 3128) and dt < 0.002 and banner == svc_name:
                        return None
                    return {
                        "host": host, "port": p, "protocol": "tcp",
                        "service": svc_name,
                        "banner": banner, "state": "open",
                    }
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=25) as ex:
        futures = [ex.submit(probe, p) for p in ports]
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                open_ports.append(r)
                if log_cb:
                    log_cb(f"[PORT] {host}:{r['port']} OPEN ({r['service']}) - {r['banner']}")

    open_ports.sort(key=lambda x: x["port"])
    return open_ports


def scan_ports(
    targets: List[str],
    ports: List[int] = None,
    log_cb: Callable[[str], None] = None,
    concurrency: int = 5,
) -> Dict:
    if ports is None:
        ports = sorted(COMMON_PORTS.keys())

    def log(m):
        if log_cb:
            log_cb(m)

    log(f"[*] Port scan: {len(targets)} host(s) x {len(ports)} port(s)")

    findings: List[Dict] = []
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = [
            ex.submit(scan_single_host_ports, t, ports, 1.5, log_cb)
            for t in targets
        ]
        for fut in as_completed(futures):
            try:
                findings.extend(fut.result())
            except Exception as e:
                log(f"[!] Host scan error: {e}")

    log(f"[+] Port scanning completed. Found {len(findings)} open ports.")
    return {
        "total_targets": len(targets),
        "ports_checked": len(ports),
        "open_ports_count": len(findings),
        "findings": findings,
    }