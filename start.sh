#!/bin/bash
# Starts the VAPT Web App
cd "$(dirname "$0")"
echo "[*] Starting VAPT Scanner Web App..."
echo "[*] Open your browser at: http://127.0.0.1:5000"
./venv/bin/python app.py
