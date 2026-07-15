# 🔐 VAPT Scanner — Recon Suite

A professional web application for automating VAPT (Vulnerability Assessment & Penetration Testing) reconnaissance workflows. Built as an internship project to wrap shell-based scanning tools into a clean, real-time web interface.

---

## ✨ Features

### 1. Subdomain Enumeration
- Runs multiple passive recon tools: **Subfinder**, **Assetfinder**, **Amass**, **Chaos**, **CertSpotter**, **Anubis**
- Deduplicates and probes all found subdomains for live hosts using **httpx**
- Streams real-time terminal output to the browser via SSE
- Displays alive vs total stats and provides download links for results

### 2. Sensitive File Scanner
- Checks each alive subdomain for exposed sensitive files:
  - `/.env`, `/.git/HEAD`, `/.svn/entries`
  - `/composer.json`, `/package.json`
  - `/config.php`, `/wp-config.php`
- **Structural signature validation** to eliminate false positives
- Per-domain custom-404 fingerprinting to avoid false positives from wildcard responses

### 3. Common Directory Scanner
- Enumerate **4750 common web paths** against a target URL
- Powered by a custom wordlist (`common.txt`)
- Reports only **HTTP 200 OK** responses
- Independent of subdomain scan — takes a direct URL input

---

## 🏗️ Architecture

```
vapt-webapp/
├── app.py                  # Flask backend — job management, SSE streaming, API routes
├── start.sh                # One-command startup script
├── scripts/
│   ├── subdomain_finder.sh # Passive subdomain enumeration script
│   ├── dir_search.sh       # Sensitive file scanner script
│   ├── common_dir_scan.sh  # Common directory enumerator
│   └── common.txt          # 4750-entry wordlist
├── templates/
│   └── index.html          # Single-page application
└── static/
    ├── css/style.css       # Dark hacker-terminal UI
    └── js/app.js           # Frontend logic + SSE client
```

---

## ⚙️ Requirements

- Python 3.8+
- `flask`, `flask-cors`
- External tools (must be in PATH):
  - `subfinder`, `assetfinder`, `amass`
  - `httpx` (projectdiscovery)
  - `chaos` (requires `PDCP_API_KEY` env variable)
  - `curl`

---

## 🚀 Setup & Run

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/vapt-scanner.git
cd vapt-scanner

# 2. Create virtual environment and install dependencies
python3 -m venv venv
source venv/bin/activate
pip install flask flask-cors

# 3. Make scripts executable
chmod +x scripts/*.sh

# 4. Start the app
./start.sh
```

Open your browser at **http://127.0.0.1:5000**

---

## 🔑 Optional: Chaos API Key

The subdomain finder uses [Chaos by ProjectDiscovery](https://chaos.projectdiscovery.io/). Set your key:

```bash
export PDCP_API_KEY="your_key_here"
```

---

## 📸 Workflow

1. **Enter a domain** in the Subdomain Finder → click Start Scan
2. Results stream live in the terminal panel
3. Once complete → click **Run Dir Scan →** to auto-pass alive hosts to the Sensitive Scanner
4. Switch to **Common Directory Scan** tab → enter a target URL for wordlist-based enumeration
5. Download reports from the results panel

---

## ⚠️ Legal Disclaimer

> This tool is intended for **authorized security testing only**.  
> Always obtain **written permission** before scanning any target.  
> Unauthorized scanning is illegal.

---

## 👨‍💻 Author

**Ugal Sharma** — VAPT Internship Project
