#!/bin/bash
# Starts the VAPT Web App
cd "$(dirname "$0")"

if [ ! -d "venv" ]; then
    echo "[*] Virtual environment not found. Creating one..."
    python3 -m venv venv
    echo "[*] Installing requirements..."
    ./venv/bin/pip install -r requirements.txt
fi

echo "[*] Starting VAPT Scanner Web App..."
echo "[*] Open your browser at: http://127.0.0.1:5000"
./venv/bin/python app.py
