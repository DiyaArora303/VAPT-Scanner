@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ============================================================
echo   VAPT Universal Reconnaissance Suite v2.1
echo ============================================================

REM --- Locate Python ---
set "PY_CMD="
where python >nul 2>nul && set "PY_CMD=python"
if not defined PY_CMD (
    if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" (
        set "PY_CMD=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
    ) else if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
        set "PY_CMD=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    ) else if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
        set "PY_CMD=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    )
)

if not defined PY_CMD (
    echo [!] Python not found on PATH or in %%LOCALAPPDATA%%\Programs\Python.
    echo     Install Python 3.11 - 3.13 and re-run.
    pause
    exit /b 1
)

echo [*] Using Python: %PY_CMD%

REM --- Create venv if missing ---
if not exist "venv\Scripts\python.exe" (
    echo [*] Virtual environment not found. Creating...
    %PY_CMD% -m venv venv
    if errorlevel 1 (
        echo [!] venv creation failed.
        pause
        exit /b 1
    )
)

REM --- Verify requirements installed ---
"venv\Scripts\python.exe" -c "import flask, flask_cors, requests, bs4, dns.resolver" >nul 2>nul
if errorlevel 1 (
    echo [*] Dependencies missing. Installing...
    "venv\Scripts\python.exe" -m pip install --upgrade pip
    "venv\Scripts\python.exe" -m pip install -r requirements.txt
    if errorlevel 1 (
        echo [!] pip install failed.
        pause
        exit /b 1
    )
)

echo [*] Starting VAPT Web App at http://127.0.0.1:5000
echo [*] Press Ctrl+C to stop.
echo.
"venv\Scripts\python.exe" app.py

endlocal
pause