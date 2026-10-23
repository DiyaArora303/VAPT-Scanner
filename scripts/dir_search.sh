#!/bin/bash

if [ -z "$1" ] || [ ! -f "$1" ]; then
    echo "Usage: $0 <alive_subdomains.txt>"
    exit 1
fi

ALIVE_LIST=$1
OUTPUT_FILE="exposed_secrets.txt"

SENSITIVE_PATHS=(
    "/.env"
    "/.git/HEAD"
    "/.svn/entries"
    "/composer.json"
    "/package.json"
    "/config.php"
    "/wp-config.php"
)

# Single temp file reused for all curl body reads — cleaned up automatically on exit
TMP_BODY=$(mktemp)
trap "rm -f $TMP_BODY" EXIT

echo "[+] Starting Advanced Structural File Analyzer..."
echo "[+] Target List: $ALIVE_LIST"
echo "[+] Valid findings will be saved to: $OUTPUT_FILE"
echo "------------------------------------------------"

> "$OUTPUT_FILE"

while read -r URL; do
    URL=$(echo "$URL" | sed 's/\/$//')
    echo "[*] Auditing: $URL"

    # --- 1 REQUEST: custom-404 fingerprint ---
    RANDOM_PATH="/detect_fp_$(date +%s%N | md5sum | head -c 8)"
    CUSTOM_404_CONTENT=$(curl -s --connect-timeout 4 --max-time 7 "$URL$RANDOM_PATH" 2>/dev/null)
    CUSTOM_404_HASH=$(echo -n "$CUSTOM_404_CONTENT" | md5sum | cut -d' ' -f1)

    for PATH_CHECK in "${SENSITIVE_PATHS[@]}"; do

        # --- 1 REQUEST per path: body → temp file, status code → variable ---
        HTTP_CODE=$(curl -s \
            --connect-timeout 4 \
            --max-time 7 \
            -o "$TMP_BODY" \
            -w "%{http_code}" \
            "$URL$PATH_CHECK" 2>/dev/null)
        CONTENT=$(cat "$TMP_BODY")

        # Skip non-200 and empty
        if [ "$HTTP_CODE" != "200" ] || [ -z "$CONTENT" ]; then
            continue
        fi

        # Skip if matches custom-404 fingerprint
        CURRENT_HASH=$(echo -n "$CONTENT" | md5sum | cut -d' ' -f1)
        if [ "$CURRENT_HASH" = "$CUSTOM_404_HASH" ]; then
            continue
        fi

        IS_VALID=false

        # --- STRUCTURAL SIGNATURE VALIDATION ---
        case "$PATH_CHECK" in
            "/.env")
                if [[ "$CONTENT" =~ [A-Za-z_][A-Za-z0-9_]*= ]]; then
                    if [[ ! "$CONTENT" =~ "<html" ]] && [[ ! "$CONTENT" =~ "<body" ]] && [[ ! "$CONTENT" =~ "<!DOCTYPE" ]]; then
                        IS_VALID=true
                    fi
                fi
                ;;
            "/.git/HEAD")
                if [[ "$CONTENT" =~ ^"ref:" ]] || [[ "$CONTENT" =~ ^[0-9a-f]{40} ]]; then
                    IS_VALID=true
                fi
                ;;
            "/.svn/entries")
                if [[ "$CONTENT" =~ "dir" ]] || [[ "$CONTENT" =~ "svn:" ]]; then
                    IS_VALID=true
                fi
                ;;
            "/composer.json"|"/package.json")
                CLEAN_START=$(echo "$CONTENT" | tr -d '[:space:]' | head -c 1)
                if [[ "$CLEAN_START" == "{" ]]; then
                    if [[ ! "$CONTENT" =~ "<html" ]] && [[ ! "$CONTENT" =~ "<body" ]] && [[ ! "$CONTENT" =~ "<!DOCTYPE" ]]; then
                        if [[ "$CONTENT" =~ "name" ]] || \
                           [[ "$CONTENT" =~ "version" ]] || \
                           [[ "$CONTENT" =~ "dependencies" ]] || \
                           [[ "$CONTENT" =~ "devDependencies" ]] || \
                           [[ "$CONTENT" =~ "scripts" ]] || \
                           [[ "$CONTENT" =~ "require" ]] || \
                           [[ "$CONTENT" =~ "engines" ]] || \
                           [[ "$CONTENT" =~ "license" ]] || \
                           [[ "$CONTENT" =~ "main" ]] || \
                           [[ "$CONTENT" =~ "private" ]] || \
                           [[ "$CONTENT" =~ "description" ]] || \
                           [[ "$CONTENT" =~ "autoload" ]]; then
                            IS_VALID=true
                        fi
                    fi
                fi
                ;;
            "/config.php"|"/wp-config.php")
                if [[ "$CONTENT" =~ "<?php" ]] || [[ "$CONTENT" =~ "DB_NAME" ]] || \
                   [[ "$CONTENT" =~ "DB_USER" ]] || [[ "$CONTENT" =~ "DB_PASSWORD" ]] || \
                   [[ "$CONTENT" =~ "database_" ]] || [[ "$CONTENT" =~ "define(" ]]; then
                    IS_VALID=true
                fi
                ;;
        esac

        if [ "$IS_VALID" = true ]; then
            SIZE_BYTES=$(echo -n "$CONTENT" | wc -c)
            echo -e "[\033[0;32mEXPOSED\033[0m] $URL$PATH_CHECK (Verified True Positive, Size: $SIZE_BYTES)"
            echo "$URL$PATH_CHECK" >> "$OUTPUT_FILE"
        fi
    done
done < <(sort -u "$ALIVE_LIST")

echo "------------------------------------------------"
echo "[+] Scan complete. Total verified exposures saved: $(wc -l < "$OUTPUT_FILE" 2>/dev/null || echo 0)"
