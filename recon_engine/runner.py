"""
recon_engine/runner.py — Orchestrator + Risk Scoring + Executive HTML Report.
Writes per-stage artifact files to results/recon_<domain>/.
"""
from __future__ import annotations

import html
import json
import os
from datetime import datetime
from typing import Callable, Dict

from .associated import discover_associated_domains
from .crawler import crawl_target
from .directories import audit_target_directories, sweep_additional_hosts_sensitive
from .ports import ALL_SCAN_PORTS, COMMON_PORTS, INFRA_PORTS, WEB_PORTS_ONLY, scan_ports
from .scope import normalize_domain, validate_target
from .subdomains import enumerate_subdomains


class ScanStopped(BaseException):
    """Raised via log_cb when a user stops an active scan job."""


def _esc(val) -> str:
    return html.escape(str(val if val is not None else ""))


def calculate_risk_assessment(data: Dict) -> Dict:
    """
    Compute automated VAPT reconnaissance risk score and remediation recommendations.
    """
    score = 10
    recs = []

    sens = data.get("directories", {}).get("sensitive_findings", [])
    js_sec = data.get("crawler", {}).get("exposed_secrets", [])
    takeovers = data.get("subdomains", {}).get("takeover_findings", [])
    total_exposures = len(sens) + len(js_sec)

    if takeovers:
        score += min(len(takeovers) * 30, 50)
        hosts_str = ", ".join(t.get("subdomain", "") for t in takeovers[:5])
        recs.append({
            "severity": "CRITICAL",
            "title": f"Dangling CNAME / Subdomain Takeover Risk ({len(takeovers)})",
            "desc": f"Subdomains ({hosts_str}) point to unclaimed external cloud providers, allowing attackers to claim the host.",
            "action": "Remove dangling CNAME DNS records or claim the external cloud resource immediately.",
        })

    if total_exposures > 0:
        score += min(total_exposures * 25, 50)
        recs.append({
            "severity": "CRITICAL",
            "title": f"Exposed Sensitive Files / Secrets Detected ({total_exposures})",
            "desc": "Configuration files (.env, .git, etc.) or hardcoded API secrets are publicly accessible, risking immediate credential and source code exposure.",
            "action": "Block web server access to dotfiles (/.env, /.git) immediately and rotate any exposed keys.",
        })

    open_ports = data.get("ports", {}).get("findings", [])
    unauth_ports = [p for p in open_ports if "UNAUTHENTICATED" in str(p.get("banner", ""))]
    if unauth_ports:
        score += 35
        u_str = ", ".join(f"{p.get('host')}:{p.get('port')}" for p in unauth_ports)
        recs.append({
            "severity": "CRITICAL",
            "title": f"Unauthenticated Data Store Exposed ({u_str})",
            "desc": "In-memory cache or database service responded without authentication over public TCP.",
            "action": "Bind Redis/Memcached to 127.0.0.1, enable authentication, and block external firewall access.",
        })

    risky_ports = [
        p for p in open_ports
        if p.get("port") in (21, 22, 23, 25, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9000, 9200, 27017)
    ]
    if risky_ports:
        score += min(len(risky_ports) * 12, 30)
        ports_str = ", ".join(sorted({str(p["port"]) for p in risky_ports}))
        recs.append({
            "severity": "HIGH",
            "title": f"Sensitive Infrastructure Ports Open to Public WAN ({ports_str})",
            "desc": f"Database or management ports ({ports_str}) are directly reachable from external networks.",
            "action": "Restrict management and database ports to VPN/internal subnets using security group firewalls.",
        })

    subs = data.get("subdomains", {}).get("records", [])
    alive_subs = [s for s in subs if s.get("alive")]
    missing_hsts = [s for s in alive_subs if not s.get("sec_headers", {}).get("hsts")]
    if missing_hsts and alive_subs:
        score += 8
        recs.append({
            "severity": "MEDIUM",
            "title": "Missing Strict-Transport-Security (HSTS) Headers",
            "desc": f"{len(missing_hsts)} alive web hosts do not enforce HSTS, leaving users vulnerable to SSL stripping attacks.",
            "action": "Configure 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
        })

    dns_sec = data.get("subdomains", {}).get("dns_security", {})
    if dns_sec and (not dns_sec.get("spf") or not dns_sec.get("dmarc")):
        missing_dns = [k.upper() for k in ("spf", "dmarc") if not dns_sec.get(k)]
        score += 5
        recs.append({
            "severity": "LOW",
            "title": f"Missing Email Anti-Spoofing DNS Records ({', '.join(missing_dns)})",
            "desc": f"Root domain is missing {', '.join(missing_dns)} TXT records, increasing risk of domain email spoofing/phishing.",
            "action": "Publish strict SPF (-all) and DMARC (p=reject or p=quarantine) TXT records.",
        })

    if len(alive_subs) > 15:
        score += 7
        recs.append({
            "severity": "INFORMATIONAL",
            "title": f"Large Public Attack Surface ({len(alive_subs)} active subdomains)",
            "desc": "Wide attack surface increases exposure to shadow IT, forgotten staging environments, and subdomain takeover.",
            "action": "Maintain a central asset inventory and decommission unused DNS pointers.",
        })

    score = min(max(score, 10), 100)
    if score >= 70:
        level, color = "CRITICAL", "#ff4466"
    elif score >= 45:
        level, color = "HIGH", "#ff8c42"
    elif score >= 25:
        level, color = "MEDIUM", "#ffd166"
    else:
        level, color = "LOW", "#38bdf8"

    return {
        "score": score,
        "level": level,
        "color": color,
        "recommendations": recs,
    }


def generate_executive_html_report(data: Dict) -> str:
    """
    Build a comprehensive, standalone HTML executive VAPT report.
    """
    domain = _esc(data.get("domain", "target.com"))
    ts = _esc(str(data.get("timestamp", datetime.now().isoformat())))
    risk = data.get("risk_assessment") or calculate_risk_assessment(data)
    subs = data.get("subdomains", {}).get("records", [])
    alive_subs = [s for s in subs if s.get("alive")]
    ports = data.get("ports", {}).get("findings", [])
    crawler_pages = data.get("crawler", {}).get("pages", [])
    crawler_apis = data.get("crawler", {}).get("api_endpoints", [])
    js_secrets = data.get("crawler", {}).get("exposed_secrets", [])
    sens = data.get("directories", {}).get("sensitive_findings", [])
    assocs = data.get("associated_domains", [])

    recs_html = ""
    for r in risk.get("recommendations", []):
        color = (
            "#ff4466" if r.get("severity") == "CRITICAL"
            else "#ff8c42" if r.get("severity") == "HIGH"
            else "#ffd166"
        )
        recs_html += f"""
        <div class="rec-card" style="border-left: 4px solid {color};">
            <div class="rec-header">
                <span class="severity-badge" style="background:{color}22; color:{color}; border: 1px solid {color}55;">{r.get('severity')}</span>
                <strong>{r.get('title')}</strong>
            </div>
            <p style="margin: 6px 0; color: #94a3b8; font-size: 0.85rem;">{r.get('desc')}</p>
            <div style="background: rgba(255,255,255,0.03); padding: 8px 12px; border-radius: 6px; font-size: 0.8rem; font-family: monospace;">
                <strong>Recommended Action:</strong> {r.get('action')}
            </div>
        </div>
        """

    subs_rows = ""
    for i, s in enumerate(subs[:50], 1):
        status_badge = (
            f"<span class='badge' style='background:#38bdf822; color:#38bdf8;'>{_esc(s.get('status_code'))}</span>"
            if s.get("alive")
            else "<span class='badge'>Offline</span>"
        )
        waf_text = _esc(s.get("waf", "Direct / Unknown"))
        subs_rows += f"""
        <tr>
            <td>{i}</td>
            <td><strong>{_esc(s.get('subdomain'))}</strong></td>
            <td><code>{_esc(s.get('ip'))}</code></td>
            <td>{status_badge}</td>
            <td>{_esc(s.get('server', '-'))}</td>
            <td>{waf_text}</td>
        </tr>
        """

    ports_rows = ""
    for i, p in enumerate(ports, 1):
        ports_rows += f"""
        <tr>
            <td>{i}</td>
            <td><code>{_esc(p.get('host'))}</code></td>
            <td><strong style="color:#00d4ff;">{_esc(p.get('port'))}</strong></td>
            <td>{_esc(str(p.get('protocol', 'tcp')).upper())}</td>
            <td>{_esc(p.get('service'))}</td>
            <td>{_esc(p.get('banner', '-'))}</td>
        </tr>
        """

    sens_rows = ""
    for i, e in enumerate(sens, 1):
        sens_rows += f"""
        <tr style="background: rgba(255,68,102,0.05);">
            <td>{i}</td>
            <td><code style="color:#ff4466;">{_esc(e.get('url'))}</code></td>
            <td><span class="severity-badge" style="background:#ff446622; color:#ff4466;">VERIFIED EXPOSURE</span></td>
            <td>{_esc(e.get('status'))}</td>
            <td>{_esc(e.get('size'))} bytes</td>
        </tr>
        """
    for j, sec in enumerate(js_secrets, len(sens) + 1):
        sens_rows += f"""
        <tr style="background: rgba(255,140,66,0.05);">
            <td>{j}</td>
            <td><code style="color:#ffd166;">{_esc(sec.get('url'))}</code></td>
            <td><span class="severity-badge" style="background:#ff8c4222; color:#ff8c42;">JS SECRET ({_esc(sec.get('type'))})</span></td>
            <td>200</td>
            <td><code>{_esc(sec.get('match'))}</code></td>
        </tr>
        """

    total_exp_count = len(sens) + len(js_secrets)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VAPT Executive Reconnaissance Report — {domain}</title>
<style>
    body {{
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        background: #0f1117;
        color: #e2e8f0;
        margin: 0;
        padding: 40px 20px;
        line-height: 1.6;
    }}
    .container {{
        max-width: 1000px;
        margin: 0 auto;
        background: #151820;
        border: 1px solid rgba(255,255,255,0.1);
        border-radius: 12px;
        padding: 40px;
        box-shadow: 0 10px 40px rgba(0,0,0,0.5);
    }}
    .header {{
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        border-bottom: 1px solid rgba(255,255,255,0.1);
        padding-bottom: 24px;
        margin-bottom: 30px;
    }}
    .title {{ font-size: 26px; font-weight: 700; margin: 0; color: #fff; }}
    .subtitle {{ color: #94a3b8; font-size: 14px; margin-top: 4px; }}
    .kpi-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
        gap: 16px;
        margin-bottom: 30px;
    }}
    .kpi-card {{
        background: rgba(255,255,255,0.02);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 8px;
        padding: 16px;
        text-align: center;
    }}
    .kpi-value {{ font-size: 28px; font-weight: 800; color: #00d4ff; }}
    .kpi-label {{ font-size: 12px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 4px; }}
    .risk-banner {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        background: {risk.get('color', '#38bdf8')}15;
        border: 1px solid {risk.get('color', '#38bdf8')}44;
        border-radius: 8px;
        padding: 16px 24px;
        margin-bottom: 30px;
    }}
    .risk-score {{ font-size: 22px; font-weight: 800; color: {risk.get('color', '#38bdf8')}; }}
    h2 {{ font-size: 18px; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 8px; margin-top: 36px; color: #fff; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }}
    th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.06); }}
    th {{ background: rgba(255,255,255,0.03); color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 11px; }}
    code {{ background: rgba(255,255,255,0.06); padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 12px; }}
    .severity-badge {{ font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 4px; display: inline-block; }}
    .badge {{ font-size: 11px; padding: 2px 8px; border-radius: 10px; display: inline-block; background: rgba(255,255,255,0.08); }}
    .rec-card {{ background: rgba(255,255,255,0.02); padding: 14px 18px; border-radius: 8px; margin-bottom: 12px; }}
    .rec-header {{ display: flex; align-items: center; gap: 10px; }}
    .btn-print {{
        background: linear-gradient(135deg, #2563eb, #0ea5e9);
        color: #ffffff;
        font-weight: 700;
        border: none;
        padding: 10px 20px;
        border-radius: 6px;
        cursor: pointer;
        font-size: 13px;
    }}
    @media print {{
        body {{ background: #fff; color: #000; padding: 0; }}
        .container {{ border: none; box-shadow: none; max-width: 100%; padding: 10px; background: #fff; color: #000; }}
        .btn-print {{ display: none; }}
        .kpi-card, .rec-card {{ background: #f8fafc; border: 1px solid #cbd5e1; color: #000; }}
        th {{ background: #f1f5f9; color: #475569; }}
        td {{ color: #000; border-bottom: 1px solid #e2e8f0; }}
        code {{ background: #f1f5f9; color: #000; }}
        .risk-banner {{ background: #f8fafc; border: 1px solid #cbd5e1; }}
    }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <h1 class="title">VAPT Executive Reconnaissance Report</h1>
            <div class="subtitle">Target: <strong>{domain}</strong> | Generated: {ts[:19].replace('T', ' ')}</div>
            <div class="subtitle">Assessor: VAPT Automated Security Reconnaissance Suite v2.1</div>
        </div>
        <button class="btn-print" onclick="window.print()">Print / Save as PDF</button>
    </div>

    <div class="risk-banner">
        <div>
            <div style="font-size: 13px; text-transform: uppercase; color: #94a3b8; font-weight: 600;">Overall Attack Surface Posture</div>
            <div class="risk-score">{risk.get('level', 'LOW')} EXPOSURE (Score: {risk.get('score', 10)}/100)</div>
        </div>
        <div style="font-size: 12px; color: #94a3b8; text-align: right;">
            Based on active subdomains, exposed credentials,<br>open services, and transport security controls.
        </div>
    </div>

    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-value">{len(subs)}</div>
            <div class="kpi-label">Subdomains</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-value" style="color:#38bdf8;">{len(alive_subs)}</div>
            <div class="kpi-label">Active Web Hosts</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-value" style="color:#ffd166;">{len(ports)}</div>
            <div class="kpi-label">Open TCP Ports</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-value" style="color:#ba68ff;">{len(crawler_pages)}</div>
            <div class="kpi-label">Crawled URLs</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-value" style="color:#ff4466;">{total_exp_count}</div>
            <div class="kpi-label">Verified Exposures</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-value" style="color:#00d4ff;">{len(assocs)}</div>
            <div class="kpi-label">Associated Roots</div>
        </div>
    </div>

    <h2>1. Strategic Remediation Recommendations</h2>
    {recs_html if recs_html else "<p style='color:#38bdf8;'>No critical exposures or immediate risks detected.</p>"}

    <h2>2. Verified Sensitive File &amp; Secret Exposures</h2>
    {f"<table><thead><tr><th>#</th><th>Exposed URL</th><th>Severity / Type</th><th>HTTP Status</th><th>Details</th></tr></thead><tbody>{sens_rows}</tbody></table>" if sens_rows else "<p style='color:#38bdf8; font-size:13px;'>Zero exposed configuration files (.env, .git, config.php) identified.</p>"}

    <h2>3. Network Port &amp; Service Discovery</h2>
    {f"<table><thead><tr><th>#</th><th>Host</th><th>Port</th><th>Protocol</th><th>Service</th><th>Banner</th></tr></thead><tbody>{ports_rows}</tbody></table>" if ports else "<p style='color:#94a3b8; font-size:13px;'>No open ports identified on scanned targets.</p>"}

    <h2>4. Discovered Subdomains &amp; DNS Infrastructure</h2>
    <table>
        <thead>
            <tr><th>#</th><th>Subdomain</th><th>Resolved IP</th><th>HTTP</th><th>Server</th><th>WAF / CDN</th></tr>
        </thead>
        <tbody>
            {subs_rows if subs_rows else "<tr><td colspan='6'>No subdomains recorded.</td></tr>"}
        </tbody>
    </table>

    <h2>5. Web Application Sitemap &amp; Discovered APIs</h2>
    <div style="font-size: 13px; color: #94a3b8; margin-bottom: 8px;">
        Identified <strong>{len(crawler_pages)}</strong> routes and <strong>{len(crawler_apis)}</strong> API endpoints.
    </div>
    <table>
        <thead><tr><th>Type</th><th>Endpoint</th><th>Status</th></tr></thead>
        <tbody>
            {''.join([f"<tr><td><span class='badge' style='color:#ba68ff;'>API</span></td><td><code>{_esc(a)}</code></td><td>Discovered</td></tr>" for a in crawler_apis[:20]])}
            {''.join([f"<tr><td><span class='badge'>PAGE</span></td><td><code>{_esc(p.get('url'))}</code></td><td>{_esc(p.get('status'))}</td></tr>" for p in crawler_pages[:30]])}
        </tbody>
    </table>

    <div style="margin-top: 40px; padding-top: 16px; border-top: 1px solid rgba(255,255,255,0.1); font-size: 11px; color: #64748b; text-align: center;">
        CONFIDENTIAL SECURITY DOCUMENT - Generated for authorized security testing.
    </div>
</div>
</body>
</html>"""


def _write_json(path: str, obj) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, default=str)


def execute_recon_pipeline(
    domain: str,
    results_base_dir: str,
    scan_type: str = "full",
    scan_options: Dict = None,
    log_cb: Callable[[str], None] = None,
) -> Dict:
    """
    Unified orchestrator. Writes per-stage artifacts under results/recon_<domain>/.
    scan_type: "full" | "subdomain" | "associated" | "ports" | "crawler" | "directories"
    """
    options = scan_options or {}
    raw_url = domain.strip() if domain.strip().startswith(("http://", "https://")) else None
    domain = normalize_domain(domain)

    def log(m):
        if log_cb:
            log_cb(m)

    log("[PHASE:1:START] Target Scope Validation & SSRF Guard")
    is_valid, err = validate_target(domain)
    if not is_valid:
        log(f"[ERROR] Scope validation failed: {err}")
        return {"status": "failed", "error": err, "domain": domain}

    log("==================================================")
    log(f"[*] TARGET: {domain}")
    log(f"[*] MODE  : {scan_type.upper()} RECONNAISSANCE")
    log(f"[*] TIME  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log("==================================================")

    target_dir = os.path.join(results_base_dir, f"recon_{domain}")
    os.makedirs(target_dir, exist_ok=True)

    results_data: Dict = {
        "domain": domain,
        "scan_type": scan_type,
        "timestamp": datetime.now().isoformat(),
        "associated_domains": [],
        "subdomains": {
            "total": 0,
            "alive": 0,
            "total_subdomains": 0,
            "alive_count": 0,
            "records": [],
            "alive_hosts": [],
            "alive_fqdns": [],
        },
        "ports": {
            "open_count": 0,
            "open_ports_count": 0,
            "findings": [],
        },
        "crawler": {
            "total_crawled": 0,
            "pages": [],
            "api_endpoints": [],
            "scripts": [],
            "external_references": [],
            "exposed_secrets": [],
        },
        "directories": {
            "sensitive_findings": [],
            "directory_findings": [],
        },
    }

    try:
        rate_val = int(options.get("rate_limit", 10))
    except (ValueError, TypeError):
        rate_val = 10
    worker_concurrency = 12 if rate_val <= 5 else (25 if rate_val <= 10 else 40)

    try:
        # ─── PHASE 2: ASSOCIATED DOMAINS ───
        if scan_type in ("full", "associated"):
            log("[PHASE:2:START] Associated Root Domains Discovery")
            try:
                assoc = discover_associated_domains(domain, log_cb=log)
                results_data["associated_domains"] = assoc
                _write_json(os.path.join(target_dir, "02_associated.json"), assoc)
            except Exception as e:
                log(f"[!] Associated domains error: {e}")

        # ─── PHASE 3: SUBDOMAINS & DNS ───
        alive_hosts = [raw_url or f"https://{domain}"]
        alive_fqdns = [domain]

        if scan_type in ("full", "subdomain"):
            log("[PHASE:3:START] Subdomains & DNS Resolution")
            try:
                sub_res = enumerate_subdomains(domain, log_cb=log, concurrency=worker_concurrency)
                results_data["subdomains"] = {
                    "domain": domain,
                    "total": sub_res["total_subdomains"],
                    "alive": sub_res["alive_count"],
                    "total_subdomains": sub_res["total_subdomains"],
                    "alive_count": sub_res["alive_count"],
                    "internal_only_count": sub_res.get("internal_only_count", 0),
                    "dns_security": sub_res.get("dns_security", {}),
                    "takeover_findings": sub_res.get("takeover_findings", []),
                    "records": sub_res["records"],
                    "alive_hosts": sub_res["alive_hosts"],
                    "alive_fqdns": sub_res["alive_fqdns"],
                }
                if sub_res["alive_hosts"]:
                    alive_hosts = sub_res["alive_hosts"]
                if sub_res["alive_fqdns"]:
                    alive_fqdns = sub_res["alive_fqdns"]

                _write_json(os.path.join(target_dir, "03_subdomains.json"), sub_res)

                all_file = os.path.join(target_dir, "all_subdomains.txt")
                alive_file = os.path.join(target_dir, "alive_subdomains.txt")
                with open(all_file, "w", encoding="utf-8") as f:
                    for r in sub_res["records"]:
                        f.write(f"{r['subdomain']}\n")
                with open(alive_file, "w", encoding="utf-8") as f:
                    for h in sub_res["alive_hosts"]:
                        f.write(f"{h}\n")
                results_data["all_file"] = all_file
                results_data["alive_file"] = alive_file
            except Exception as e:
                log(f"[!] Subdomain error: {e}")

        # ─── PHASE 4: PORT & SERVICE DISCOVERY ───
        if scan_type in ("full", "ports"):
            log("[PHASE:4:START] Open Ports & Service Discovery")
            try:
                port_profile = options.get("port_profile", "web")
                if port_profile == "web":
                    ports_to_scan = WEB_PORTS_ONLY
                elif port_profile == "all":
                    ports_to_scan = ALL_SCAN_PORTS
                else:
                    ports_to_scan = INFRA_PORTS
                port_res = scan_ports(alive_fqdns[:10], ports=ports_to_scan, log_cb=log)
                if scan_type == "ports" and port_res["open_ports_count"] == 0 and not domain.startswith("www."):
                    www_res = scan_ports([f"www.{domain}"], ports=ports_to_scan, log_cb=log)
                    if www_res["open_ports_count"] > 0:
                        port_res = www_res
                results_data["ports"] = {
                    "total_targets": port_res["total_targets"],
                    "ports_checked": port_res["ports_checked"],
                    "open_count": port_res["open_ports_count"],
                    "open_ports_count": port_res["open_ports_count"],
                    "findings": port_res["findings"],
                }
                _write_json(os.path.join(target_dir, "05_ports.json"), port_res)

                ports_file = os.path.join(target_dir, "ports_open.txt")
                with open(ports_file, "w", encoding="utf-8") as f:
                    for p in port_res["findings"]:
                        f.write(f"{p['host']}:{p['port']} ({p['service']}) - {p['banner']}\n")
                results_data["ports_file"] = ports_file
            except Exception as e:
                log(f"[!] Port scanning error: {e}")

        # Determine best primary URL for crawling and directory audit
        primary_url = raw_url or (alive_hosts[0] if alive_hosts else domain)

        # ─── PHASE 5: WEB CRAWLER ───
        if scan_type in ("full", "crawler"):
            log("[PHASE:5:START] Web Application Crawler & Secret Hunter")
            try:
                max_depth = int(options.get("max_depth", 2))
                max_pages = int(options.get("max_pages", 30))
                crawl_res = crawl_target(
                    start_url=primary_url,
                    root_domain=domain,
                    max_depth=max_depth,
                    max_pages=max_pages,
                    log_cb=log,
                )
                results_data["crawler"] = crawl_res
                _write_json(os.path.join(target_dir, "06_crawl.json"), crawl_res)

                links_file = os.path.join(target_dir, "crawled_links.txt")
                with open(links_file, "w", encoding="utf-8") as f:
                    for p in crawl_res.get("pages", []):
                        f.write(f"[{p.get('status', '-')}] {p['url']}\n")
                results_data["links_file"] = links_file
            except Exception as e:
                log(f"[!] Crawler error: {e}")

        # ─── PHASE 6: DIRECTORY & SENSITIVE FILE AUDIT ───
        if scan_type in ("full", "directories"):
            log("[PHASE:6:START] Directory Enumeration & Secret Audit")
            try:
                dir_res = audit_target_directories(primary_url, log_cb=log, concurrency=worker_concurrency)
                # Multi-host sensitive sweep across secondary alive hosts & non-standard open web ports
                extra_web_urls = list(alive_hosts[1:6])
                for pf in results_data.get("ports", {}).get("findings", []):
                    p_num = pf.get("port")
                    p_host = pf.get("host")
                    if p_host and p_num in (3000, 5000, 8000, 8080, 8081, 8443, 8888, 9000):
                        sch = "https" if p_num == 8443 else "http"
                        extra_web_urls.append(f"{sch}://{p_host}:{p_num}")
                if extra_web_urls:
                    extra_sens = sweep_additional_hosts_sensitive(
                        extra_web_urls, log_cb=log, concurrency=worker_concurrency
                    )
                    existing_urls = {s["url"] for s in dir_res.get("sensitive_findings", [])}
                    for es in extra_sens:
                        if es["url"] not in existing_urls:
                            dir_res.setdefault("sensitive_findings", []).append(es)
                            existing_urls.add(es["url"])

                results_data["directories"] = dir_res
                _write_json(os.path.join(target_dir, "07_dirs.json"), dir_res)

                secrets_file = os.path.join(target_dir, "exposed_secrets.txt")
                with open(secrets_file, "w", encoding="utf-8") as f:
                    for s in dir_res.get("sensitive_findings", []):
                        f.write(f"{s['url']}\n")
                    for sec in results_data.get("crawler", {}).get("exposed_secrets", []):
                        f.write(f"{sec.get('url')} [{sec.get('type')}: {sec.get('match')}]\n")
                results_data["output_file"] = secrets_file
                results_data["total_findings"] = (
                    len(dir_res.get("sensitive_findings", []))
                    + len(results_data.get("crawler", {}).get("exposed_secrets", []))
                )
            except Exception as e:
                log(f"[!] Directory scan error: {e}")
    except ScanStopped:
        results_data["status"] = "stopped"
        return results_data

    # ─── PHASE 7: RISK SCORING & REPORT GENERATION ───
    log("[PHASE:7:START] Risk Assessment & Executive Report Generation")
    risk_info = calculate_risk_assessment(results_data)
    results_data["risk_assessment"] = risk_info

    report_file = os.path.join(target_dir, "recon_report.json")
    html_report_file = os.path.join(target_dir, "executive_report.html")

    results_data["report_file"] = report_file
    results_data["html_report_file"] = html_report_file
    results_data["recon_dir"] = target_dir
    results_data["alive_count"] = results_data["subdomains"].get("alive", 0)
    results_data["total_subdomains"] = results_data["subdomains"].get("total", 0)

    _write_json(report_file, results_data)
    with open(html_report_file, "w", encoding="utf-8") as f:
        f.write(generate_executive_html_report(results_data))

    log("--------------------------------------------------")
    log(f"[+] Assessment completed. Risk Posture: {risk_info['level']} (Score: {risk_info['score']}/100)")
    log(f"[+] JSON Report: {report_file}")
    log(f"[+] Executive HTML Report: {html_report_file}")
    log("[PHASE:DONE] Pipeline Execution Completed")
    log("==================================================")

    return results_data
