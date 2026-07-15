#!/bin/bash
# common_dir_scan.sh — Common Directory Enumerator
# Usage: ./common_dir_scan.sh <alive_subdomains.txt> [wordlist.txt]
#
# Checks each alive host against a wordlist of common directories/paths.
# Reports: HTTP status code, content length, and URL for each hit.
# False positive mitigation: baseline fingerprint via random path (same logic
# as dir_search.sh) — any response that matches the custom-404 hash is skipped.
# Only 200, 301, 302, 403 responses are reported (not 404 / empty).

if [ -z "$1" ] || [ ! -f "$1" ]; then
    echo "Usage: $0 <alive_subdomains.txt> [wordlist.txt]"
    exit 1
fi

ALIVE_LIST="$1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORDLIST="${2:-$SCRIPT_DIR/common.txt}"

if [ ! -f "$WORDLIST" ]; then
    echo "[!] Wordlist not found: $WORDLIST"
    exit 1
fi

OUTPUT_FILE="common_dirs_found.txt"
> "$OUTPUT_FILE"

TOTAL_WORDS=$(wc -l < "$WORDLIST")
echo "[+] Starting Common Directory Enumerator"
echo "[+] Target List  : $ALIVE_LIST"
echo "[+] Wordlist     : $WORDLIST ($TOTAL_WORDS entries)"
echo "[+] Results File : $OUTPUT_FILE"
echo "------------------------------------------------"

while read -r URL; do
    # Normalize — strip trailing slash
    URL=$(echo "$URL" | sed 's|/$||')
    echo "[*] Scanning: $URL"

    # --- CUSTOM 404 FINGERPRINT (false positive mitigation) ---
    RAND_PATH="/fp_baseline_$(date +%s%N | md5sum | head -c 8)"
    CUSTOM_404_CONTENT=$(curl -s --connect-timeout 3 --max-time 5 -L "$URL$RAND_PATH" 2>/dev/null)
    CUSTOM_404_HASH=$(echo -n "$CUSTOM_404_CONTENT" | md5sum | cut -d' ' -f1)

    FOUND=0

    while read -r WORD; do
        # Skip blank lines and comments
        [[ -z "$WORD" || "$WORD" == \#* ]] && continue

        # Ensure leading slash
        [[ "$WORD" != /* ]] && WORD="/$WORD"

        TARGET="$URL$WORD"

        # Get HTTP status code
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
            --connect-timeout 3 --max-time 6 "$TARGET" 2>/dev/null)

        # Only report 200 OK
        case "$HTTP_CODE" in
            200) ;;
            *) continue ;;
        esac

        # Get content for 200s — hash and compare against custom 404
        if [ "$HTTP_CODE" = "200" ]; then
            CONTENT=$(curl -s --connect-timeout 3 --max-time 6 "$TARGET" 2>/dev/null)
            CONTENT_HASH=$(echo -n "$CONTENT" | md5sum | cut -d' ' -f1)
            # Skip if response body matches custom 404
            [ "$CONTENT_HASH" = "$CUSTOM_404_HASH" ] && continue
            SIZE=$(echo -n "$CONTENT" | wc -c)
        else
            SIZE="-"
        fi

        echo "[FOUND] [$HTTP_CODE] $TARGET (Size: $SIZE)"
        echo "$HTTP_CODE $TARGET" >> "$OUTPUT_FILE"
        FOUND=$((FOUND + 1))

    done < "$WORDLIST"

    echo "[+] $URL — $FOUND paths found"

done < "$ALIVE_LIST"

echo "------------------------------------------------"
TOTAL=$(wc -l < "$OUTPUT_FILE" 2>/dev/null || echo 0)
echo "[+] Scan complete. Total paths found: $TOTAL"
echo "[+] Results saved to: $OUTPUT_FILE"
