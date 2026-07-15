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

echo "[+] Starting Advanced Structural File Analyzer..."
echo "[+] Target List: $ALIVE_LIST"
echo "[+] Valid findings will be saved to: $OUTPUT_FILE"
echo "------------------------------------------------"

> "$OUTPUT_FILE"

while read -r URL; do
    URL=$(echo "$URL" | sed 's/\/$//')
    echo "[*] Auditing: $URL"

    # --- COLLECT UNIQUE 404 SIGNATURE PER DOMAIN ---
    RANDOM_PATH="/detect_false_positive_$(date +%s)"
    CUSTOM_404_CONTENT=$(curl -s --connect-timeout 3 --max-time 5 "$URL$RANDOM_PATH")
    CUSTOM_404_HASH=$(echo -n "$CUSTOM_404_CONTENT" | md5sum | cut -d' ' -f1)

    for PATH_CHECK in "${SENSITIVE_PATHS[@]}"; do
        # Fetch actual content
        CONTENT=$(curl -s --connect-timeout 4 --max-time 6 "$URL$PATH_CHECK")
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 "$URL$PATH_CHECK")

        # 1. Clean out generic drops
        if [ "$HTTP_CODE" -ne 200 ] || [ -z "$CONTENT" ]; then
            continue
        fi

        # 2. Check if the page content matches the domain's custom 404 page body exactly
        CURRENT_HASH=$(echo -n "$CONTENT" | md5sum | cut -d' ' -f1)
        if [ "$CURRENT_HASH" == "$CUSTOM_404_HASH" ]; then
            continue
        fi

        IS_VALID=false

        # --- STRUCTURAL SIGNATURE VALIDATION ---
        case "$PATH_CHECK" in
            "/.env")
                # Must look like KEY=VALUE pairs, not HTML
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
                # Must be a JSON object (starts with {) — not an HTML page
                CLEAN_START=$(echo "$CONTENT" | tr -d '[:space:]' | head -c 1)
                if [[ "$CLEAN_START" == "{" ]]; then
                    # Must not be an HTML error page
                    if [[ ! "$CONTENT" =~ "<html" ]] && [[ ! "$CONTENT" =~ "<body" ]] && [[ ! "$CONTENT" =~ "<!DOCTYPE" ]]; then
                        # Must contain at least one common JSON package field
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
done < "$ALIVE_LIST"

echo "------------------------------------------------"
echo "[+] Scan complete. Total verified exposures saved: $(wc -l < "$OUTPUT_FILE" 2>/dev/null || echo 0)"
