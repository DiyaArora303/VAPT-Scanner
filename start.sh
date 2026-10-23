#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

echo "============================================================"
echo "  VAPT Universal Reconnaissance Suite v2.1"
echo "============================================================"

# Find python interpreter
PY=""
for cand in python3 python; do
    if command -v "$cand" >/dev/null 2>&1; then
        PY="$cand"
        break
    fi
done

if [ -z "$PY" ]; then
    echo "[!] Python 3 not found on PATH."
    exit 1
fi

echo "[*] Using interpreter: $PY"

# Create venv if missing
if [ ! -x "venv/bin/python" ]; then
    echo "[*] Creating virtual environment..."
    "$PY" -m venv venv
fi

# Verify dependencies
if ! ./venv/bin/python -c "import flask, flask_cors, requests, bs4, dns.resolver" >/dev/null 2>&1; then
    echo "[*] Installing requirements..."
    ./venv/bin/python -m pip install --upgrade pip
    ./venv/bin/python -m pip install -r requirements.txt
fi

echo "[*] Starting VAPT Web App at http://127.0.0.1:5000"
echo "[*] Press Ctrl+C to stop."
echo
exec ./venv/bin/python app.py