import os

svg_content = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 1250" width="100%" height="100%" style="background:#090d16; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
  <defs>
    <!-- Gradients -->
    <linearGradient id="grad-blue" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0284c7" />
      <stop offset="100%" stop-color="#0369a1" />
    </linearGradient>
    <linearGradient id="grad-purple" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#8b5cf6" />
      <stop offset="100%" stop-color="#6d28d9" />
    </linearGradient>
    <linearGradient id="grad-green" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#10b981" />
      <stop offset="100%" stop-color="#047857" />
    </linearGradient>
    <linearGradient id="grad-amber" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#f59e0b" />
      <stop offset="100%" stop-color="#d97706" />
    </linearGradient>
    <linearGradient id="grad-red" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#ef4444" />
      <stop offset="100%" stop-color="#b91c1c" />
    </linearGradient>

    <!-- Arrow Marker -->
    <marker id="arrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8" />
    </marker>
    <marker id="arrow-red" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#ef4444" />
    </marker>
    <marker id="arrow-green" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#10b981" />
    </marker>
    
    <!-- Filter for Glow/Shadow -->
    <filter id="shadow" x="-10%" y="-10%" width="120%" height="120%">
      <feDropShadow dx="0" dy="4" stdDeviation="6" flood-color="#000000" flood-opacity="0.5"/>
    </filter>
  </defs>

  <!-- Title Header -->
  <g transform="translate(50, 40)">
    <rect width="900" height="70" rx="12" fill="#131c2e" stroke="#1e293b" stroke-width="1.5" />
    <text x="450" y="35" fill="#38bdf8" font-size="22" font-weight="700" text-anchor="middle" letter-spacing="0.5">VAPT SCANNER — ARCHITECTURE &amp; RECON WORKFLOW</text>
    <text x="450" y="55" fill="#94a3b8" font-size="13" text-anchor="middle">End-to-End Execution Flow &amp; Security Tools Breakdown</text>
  </g>

  <!-- STEP 1: UI & Backend Layer -->
  <g transform="translate(50, 140)">
    <!-- User / Browser Card -->
    <rect x="0" y="0" width="420" height="90" rx="10" fill="#111827" stroke="#38bdf8" stroke-width="2" filter="url(#shadow)" />
    <rect x="0" y="0" width="420" height="28" rx="10" fill="#1e293b" />
    <text x="15" y="19" fill="#38bdf8" font-size="13" font-weight="700">1. USER INTERFACE (Frontend)</text>
    <text x="20" y="52" fill="#f8fafc" font-size="14" font-weight="600">Web Dashboard (HTML5 / CSS / Vanilla JS)</text>
    <text x="20" y="72" fill="#94a3b8" font-size="12">Target Domain/URL Input • SSE Real-Time Terminal • Stats &amp; Downloads</text>

    <!-- Connective arrow UI -> Flask -->
    <path d="M 420 45 L 478 45" stroke="#38bdf8" stroke-width="2" fill="none" marker-end="url(#arrow)" />

    <!-- Flask Backend Card -->
    <rect x="480" y="0" width="420" height="90" rx="10" fill="#111827" stroke="#8b5cf6" stroke-width="2" filter="url(#shadow)" />
    <rect x="480" y="0" width="420" height="28" rx="10" fill="#2e1065" />
    <text x="495" y="19" fill="#c084fc" font-size="13" font-weight="700">2. BACKEND CONTROLLER (app.py)</text>
    <text x="500" y="52" fill="#f8fafc" font-size="14" font-weight="600">Flask Server &amp; Job Management</text>
    <text x="500" y="72" fill="#94a3b8" font-size="12">Subprocess Execution • Threading Lock • SSE Log Streaming</text>
  </g>

  <!-- Arrow down to Recon Tools -->
  <path d="M 690 230 L 690 270 L 500 270 L 500 295" stroke="#38bdf8" stroke-width="2" fill="none" marker-end="url(#arrow)" />

  <!-- STEP 2: Subdomain Enumeration -->
  <g transform="translate(50, 300)">
    <rect x="0" y="0" width="900" height="150" rx="12" fill="#111827" stroke="#0284c7" stroke-width="2" filter="url(#shadow)" />
    <rect x="0" y="0" width="900" height="30" rx="12" fill="#0c4a6e" />
    <text x="20" y="21" fill="#7dd3fc" font-size="13" font-weight="700">PHASE 1: SUBDOMAIN ENUMERATION (subdomain_finder.sh)</text>

    <!-- Tool Chips -->
    <g transform="translate(20, 45)">
      <!-- Subfinder -->
      <rect x="0" y="0" width="130" height="42" rx="6" fill="#1e293b" stroke="#38bdf8" stroke-width="1"/>
      <text x="65" y="20" fill="#f8fafc" font-size="12" font-weight="600" text-anchor="middle">Subfinder</text>
      <text x="65" y="34" fill="#94a3b8" font-size="10" text-anchor="middle">Passive DNS</text>

      <!-- Assetfinder -->
      <rect x="145" y="0" width="130" height="42" rx="6" fill="#1e293b" stroke="#38bdf8" stroke-width="1"/>
      <text x="210" y="20" fill="#f8fafc" font-size="12" font-weight="600" text-anchor="middle">Assetfinder</text>
      <text x="210" y="34" fill="#94a3b8" font-size="10" text-anchor="middle">OSINT Scraping</text>

      <!-- Amass -->
      <rect x="290" y="0" width="130" height="42" rx="6" fill="#1e293b" stroke="#38bdf8" stroke-width="1"/>
      <text x="355" y="20" fill="#f8fafc" font-size="12" font-weight="600" text-anchor="middle">Amass</text>
      <text x="355" y="34" fill="#94a3b8" font-size="10" text-anchor="middle">Passive Enum</text>

      <!-- Chaos -->
      <rect x="435" y="0" width="130" height="42" rx="6" fill="#1e293b" stroke="#38bdf8" stroke-width="1"/>
      <text x="500" y="20" fill="#f8fafc" font-size="12" font-weight="600" text-anchor="middle">Chaos</text>
      <text x="500" y="34" fill="#94a3b8" font-size="10" text-anchor="middle">PDCP API Dataset</text>

      <!-- CertSpotter / Anubis -->
      <rect x="580" y="0" width="140" height="42" rx="6" fill="#1e293b" stroke="#38bdf8" stroke-width="1"/>
      <text x="650" y="20" fill="#f8fafc" font-size="12" font-weight="600" text-anchor="middle">CertSpotter / Anubis</text>
      <text x="650" y="34" fill="#94a3b8" font-size="10" text-anchor="middle">CT Log Search</text>

      <!-- github-subdomains -->
      <rect x="735" y="0" width="125" height="42" rx="6" fill="#1e293b" stroke="#38bdf8" stroke-width="1"/>
      <text x="797" y="20" fill="#f8fafc" font-size="12" font-weight="600" text-anchor="middle">GitHub Search</text>
      <text x="797" y="34" fill="#94a3b8" font-size="10" text-anchor="middle">Source Recon</text>
    </g>

    <!-- Deduplication Row -->
    <rect x="20" y="100" width="860" height="36" rx="6" fill="#0f172a" stroke="#334155" stroke-dasharray="4" />
    <text x="450" y="123" fill="#38bdf8" font-size="12" font-weight="600" text-anchor="middle">Merge &amp; Deduplicate Output:  cat *.txt | sort -u  ➔  all_subdomains.txt</text>
  </g>

  <!-- Arrow down to Alive Check -->
  <path d="M 500 450 L 500 488" stroke="#38bdf8" stroke-width="2" fill="none" marker-end="url(#arrow)" />

  <!-- STEP 3: Alive Host Probing -->
  <g transform="translate(50, 490)">
    <rect x="0" y="0" width="900" height="100" rx="12" fill="#111827" stroke="#10b981" stroke-width="2" filter="url(#shadow)" />
    <rect x="0" y="0" width="900" height="28" rx="12" fill="#064e3b" />
    <text x="20" y="19" fill="#6ee7b7" font-size="13" font-weight="700">PHASE 2: LIVE HOST PROBING &amp; RESOLUTION</text>

    <!-- Tool details -->
    <rect x="20" y="40" width="400" height="46" rx="6" fill="#1e293b" stroke="#10b981" stroke-width="1" />
    <text x="35" y="60" fill="#f8fafc" font-size="13" font-weight="600">⚡ httpx (ProjectDiscovery)</text>
    <text x="35" y="76" fill="#94a3b8" font-size="11">Probes HTTP/HTTPS ports &amp; confirms responsive domains (Fallback: curl loop)</text>

    <path d="M 420 63 L 478 63" stroke="#10b981" stroke-width="2" fill="none" marker-end="url(#arrow-green)" />

    <!-- File Output -->
    <rect x="480" y="40" width="400" height="46" rx="6" fill="#065f46" stroke="#34d399" stroke-width="1" />
    <text x="495" y="60" fill="#f8fafc" font-size="13" font-weight="600">📄 alive_subdomains.txt</text>
    <text x="495" y="76" fill="#a7f3d0" font-size="11">Filtered list of active web services fed into subsequent scans</text>
  </g>

  <!-- Branching Arrows to Phase 3 -->
  <path d="M 300 590 L 300 640" stroke="#38bdf8" stroke-width="2" fill="none" marker-end="url(#arrow)" />
  <path d="M 700 590 L 700 640" stroke="#38bdf8" stroke-width="2" fill="none" marker-end="url(#arrow)" />

  <!-- STEP 4: Vulnerability & Content Scanning -->
  <g transform="translate(50, 640)">
    <!-- Scan A: Sensitive File Scanner -->
    <rect x="0" y="0" width="430" height="250" rx="12" fill="#111827" stroke="#f59e0b" stroke-width="2" filter="url(#shadow)" />
    <rect x="0" y="0" width="430" height="28" rx="12" fill="#78350f" />
    <text x="15" y="19" fill="#fde68a" font-size="12" font-weight="700">PHASE 3A: SENSITIVE FILE SCANNER</text>
    
    <text x="15" y="50" fill="#f8fafc" font-size="13" font-weight="600">dir_search.sh</text>
    <text x="15" y="70" fill="#94a3b8" font-size="11">Audits each alive host for sensitive leaks:</text>

    <!-- Checks List -->
    <rect x="15" y="80" width="400" height="85" rx="6" fill="#1e293b" />
    <text x="25" y="98" fill="#f8fafc" font-size="11">🎯 Targets: /.env, /.git/HEAD, /.svn/entries,</text>
    <text x="80" y="114" fill="#f8fafc" font-size="11">composer.json, package.json, config.php, wp-config.php</text>
    <text x="25" y="134" fill="#38bdf8" font-size="11">🛡️ Anti-False Positive:</text>
    <text x="25" y="152" fill="#cbd5e1" font-size="11">Custom-404 hash check (md5sum) + Structural signatures</text>

    <!-- Output file -->
    <rect x="15" y="180" width="400" height="50" rx="6" fill="#0f172a" stroke="#f59e0b" stroke-width="1"/>
    <text x="25" y="200" fill="#f59e0b" font-size="12" font-weight="600">📁 Output: exposed_secrets.txt</text>
    <text x="25" y="218" fill="#94a3b8" font-size="11">Verified exposures displayed in web UI</text>


    <!-- Scan B: Common Directory Scanner -->
    <rect x="470" y="0" width="430" height="250" rx="12" fill="#111827" stroke="#3b82f6" stroke-width="2" filter="url(#shadow)" />
    <rect x="470" y="0" width="430" height="28" rx="12" fill="#1e3a8a" />
    <text x="485" y="19" fill="#93c5fd" font-size="12" font-weight="700">PHASE 3B: COMMON DIRECTORY SCANNER</text>

    <text x="485" y="50" fill="#f8fafc" font-size="13" font-weight="600">common_dir_scan.sh</text>
    <text x="485" y="70" fill="#94a3b8" font-size="11">Brute-forces common endpoints on alive hosts or URL:</text>

    <rect x="485" y="80" width="400" height="85" rx="6" fill="#1e293b" />
    <text x="495" y="100" fill="#f8fafc" font-size="11">📖 Wordlist: common.txt (4,750 high-priority paths)</text>
    <text x="495" y="122" fill="#38bdf8" font-size="11">⚙️ Mechanism: curl with timeout &amp; status inspection</text>
    <text x="495" y="144" fill="#cbd5e1" font-size="11">🛡️ False Positive Filter: Baseline 404 hash skipping</text>

    <!-- Output file -->
    <rect x="485" y="180" width="400" height="50" rx="6" fill="#0f172a" stroke="#3b82f6" stroke-width="1"/>
    <text x="495" y="200" fill="#60a5fa" font-size="12" font-weight="600">📁 Output: common_dirs_found.txt</text>
    <text x="495" y="218" fill="#94a3b8" font-size="11">Only verified HTTP 200 OK responses reported</text>
  </g>

  <!-- Arrow down to Git Dumper -->
  <path d="M 215 890 L 215 930 L 500 930 L 500 950" stroke="#ef4444" stroke-width="2" stroke-dasharray="4" fill="none" marker-end="url(#arrow-red)" />
  <text x="225" y="920" fill="#ef4444" font-size="11" font-weight="600">If /.git/HEAD Exposed</text>

  <!-- STEP 5: Exploitation / Dump Layer -->
  <g transform="translate(50, 950)">
    <rect x="0" y="0" width="900" height="120" rx="12" fill="#111827" stroke="#ef4444" stroke-width="2" filter="url(#shadow)" />
    <rect x="0" y="0" width="900" height="28" rx="12" fill="#7f1d1d" />
    <text x="20" y="19" fill="#fca5a5" font-size="13" font-weight="700">PHASE 4: TARGET REPO EXTRACTION (MANUAL CONFIRMATION REQUIRED)</text>

    <!-- Tool Details -->
    <rect x="20" y="42" width="400" height="62" rx="6" fill="#1e293b" stroke="#ef4444" stroke-width="1" />
    <text x="35" y="64" fill="#fca5a5" font-size="13" font-weight="700">💥 git-dumper (Python CLI Tool)</text>
    <text x="35" y="82" fill="#94a3b8" font-size="11">Triggered by explicit UI button click per confirmed target</text>
    <text x="35" y="96" fill="#94a3b8" font-size="11">Pulls complete Git commit history and source code</text>

    <path d="M 420 73 L 478 73" stroke="#ef4444" stroke-width="2" fill="none" marker-end="url(#arrow-red)" />

    <!-- Storage destination -->
    <rect x="480" y="42" width="400" height="62" rx="6" fill="#450a0a" stroke="#f87171" stroke-width="1" />
    <text x="495" y="64" fill="#fecaca" font-size="13" font-weight="700">📁 Local Extraction Directory</text>
    <text x="495" y="82" fill="#fca5a5" font-size="11">Saved to: /home/kali/&lt;target&gt;_dump/</text>
    <text x="495" y="96" fill="#cbd5e1" font-size="11">Full unpacked source code ready for offline forensic audit</text>
  </g>

  <!-- Return Flow back to UI Dashboard -->
  <path d="M 900 1010 L 970 1010 L 970 185 L 922 185" stroke="#8b5cf6" stroke-width="2" stroke-dasharray="4" fill="none" marker-end="url(#arrow)" />
  <text x="960" y="600" fill="#c084fc" font-size="11" font-weight="600" transform="rotate(90, 960, 600)" text-anchor="middle">Live Status &amp; Download Links to UI</text>

  <!-- Footer Info -->
  <g transform="translate(50, 1100)">
    <rect width="900" height="50" rx="8" fill="#1e293b" />
    <text x="20" y="30" fill="#94a3b8" font-size="11">Summary: User ➔ Flask Webapp ➔ Subdomain Recon (Subfinder/Assetfinder/Amass/Chaos/CT) ➔ Alive Probe (httpx) ➔ Sensitive &amp; Common Dir Scans (curl) ➔ Git Dump</text>
  </g>
</svg>
"""

with open("vapt_architecture_flow.svg", "w", encoding="utf-8") as f:
    f.write(svg_content)

print("Created vapt_architecture_flow.svg successfully!")
