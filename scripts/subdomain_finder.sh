#!/bin/bash

# Check if a domain was provided
if [ -z "$1" ]; then
    echo "Usage: $0 <domain.com>"
    exit 1
fi

DOMAIN=$1
OUTPUT_DIR="recon_$DOMAIN"

# Create clean output directory
mkdir -p "$OUTPUT_DIR"
echo "[+] Starting passive enumeration for: $DOMAIN"
echo "[+] Results will be saved in: $OUTPUT_DIR/"

# -------------------------------------------------------------------
# Step 1: Passive Enumeration
# -------------------------------------------------------------------

# 1. Subfinder
if command -v subfinder &> /dev/null; then
    echo "[*] Running Subfinder..."
    subfinder -d "$DOMAIN" -silent > "$OUTPUT_DIR/subfinder.txt"
else
    echo "[!] Subfinder not found. Skipping."
fi

# 2. Assetfinder
if command -v assetfinder &> /dev/null; then
    echo "[*] Running Assetfinder..."
    assetfinder --subs-only "$DOMAIN" > "$OUTPUT_DIR/assetfinder.txt"
else
    echo "[!] Assetfinder not found. Skipping."
fi

# 3. Amass (Passive mode with interactive-block)
if command -v amass &> /dev/null; then
    echo "[*] Running Amass..."
    amass enum -passive -d "$DOMAIN" -silent </dev/null > "$OUTPUT_DIR/amass.txt" 2>/dev/null
else
    echo "[!] Amass not found. Skipping."
fi

# 4. Chaos (Checks for the standardized PDCP key)
if command -v chaos &> /dev/null; then
    if [ -n "$PDCP_API_KEY" ]; then
        echo "[*] Running Chaos..."
        chaos -d "$DOMAIN" -silent > "$OUTPUT_DIR/chaos.txt"
    else
        echo "[!] Chaos found, but PDCP_API_KEY variable is empty. Skipping."
    fi
else
    echo "[!] Chaos tool not found. Skipping."
fi

# 5. GitHub Search
if command -v github-subdomains &> /dev/null; then
    echo "[*] Running GitHub Subdomains search..."
    github-subdomains -d "$DOMAIN" -silent > "$OUTPUT_DIR/github.txt"
else
    echo "[!] github-subdomains tool not found. Skipping."
fi

# 6. Stable Certificate Transparency Backups (Replacing unstable crt.sh)
echo "[*] Querying alternative CT logs (CertSpotter & Anubis)..."
curl -s "https://api.certspotter.com/v1/issuances?domain=$DOMAIN&include_subdomains=true&expand=dns_names" | jq -r '.[].dns_names[]' 2>/dev/null | grep -E "\.${DOMAIN}$" | sed 's/\*\.//g' > "$OUTPUT_DIR/certspotter.txt"
curl -s "https://jldc.me/anubis/subdomains/$DOMAIN" | jq -r '.[]' 2>/dev/null | sed 's/\*\.//g' > "$OUTPUT_DIR/anubis.txt"


# -------------------------------------------------------------------
# Steps 2 & 3: Merge Results and Remove Duplicates
# -------------------------------------------------------------------
echo "[*] Merging results and removing duplicates..."
cat "$OUTPUT_DIR"/*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/all_subdomains.txt"

TOTAL_FOUND=$(wc -l < "$OUTPUT_DIR/all_subdomains.txt")
echo "[+] Total unique subdomains found: $TOTAL_FOUND"


# -------------------------------------------------------------------
# Step 4: Resolve Alive Domains via ProjectDiscovery httpx
# -------------------------------------------------------------------
if [ -f "$HOME/go/bin/httpx" ]; then
    echo "[*] Checking for live domains with ProjectDiscovery httpx..."
    cat "$OUTPUT_DIR/all_subdomains.txt" | "$HOME/go/bin/httpx" -silent -o "$OUTPUT_DIR/alive_subdomains.txt"
    
    if [ -s "$OUTPUT_DIR/alive_subdomains.txt" ]; then
        ALIVE_COUNT=$(wc -l < "$OUTPUT_DIR/alive_subdomains.txt")
        echo "[+] Done! $ALIVE_COUNT alive domains found."
        echo "[+] Final results saved to: $OUTPUT_DIR/alive_subdomains.txt"
    else
        echo "[!] Live check execution completed but no active hosts responded."
    fi
else
    echo "[!] ProjectDiscovery httpx binary not found at ~/go/bin/httpx. Using native fallback loop..."
    while read -r sub; do
        if curl -s -o /dev/null --connect-timeout 2 -w "%{http_code}" "http://$sub" | grep -E "^(200|301|302|403|404)" > /dev/null; then
            echo "http://$sub" >> "$OUTPUT_DIR/alive_subdomains.txt"
        fi
    done < "$OUTPUT_DIR/all_subdomains.txt"
    
    if [ -f "$OUTPUT_DIR/alive_subdomains.txt" ]; then
        ALIVE_COUNT=$(wc -l < "$OUTPUT_DIR/alive_subdomains.txt")
        echo "[+] Done! $ALIVE_COUNT alive domains found via fallback loop."
    else
        echo "[!] No alive domains found."
    fi
fi
