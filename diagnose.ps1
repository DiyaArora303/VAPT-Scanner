# diagnose.ps1 — Windows diagnostic wrapper for the VAPT Recon Suite.
# Run from the project root:   .\diagnose.ps1
# Produces _diagnostics.zip you can send me.

$ErrorActionPreference = "Continue"
$ProjectRoot = $PWD.Path
$OutputDir   = Join-Path $ProjectRoot "_diagnostics"

Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "  VAPT Recon Suite — Windows Diagnostic" -ForegroundColor Cyan
Write-Host "  Project: $ProjectRoot" -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan

if (Test-Path $OutputDir) { Remove-Item $OutputDir -Recurse -Force }
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

# -------- 1. Environment snapshot --------
Write-Host "[*] 1/6 Environment snapshot..." -ForegroundColor Yellow
$envLines = New-Object System.Collections.Generic.List[string]
$envLines.Add("=== OS ===")
try {
    $os = Get-CimInstance Win32_OperatingSystem
    $envLines.Add("Caption : $($os.Caption)")
    $envLines.Add("Version : $($os.Version)")
    $envLines.Add("Arch    : $($os.OSArchitecture)")
} catch { $envLines.Add("OS info failed: $_") }
$envLines.Add("")
$envLines.Add("=== PowerShell ===")
$envLines.Add("Version : $($PSVersionTable.PSVersion)")
$envLines.Add("Edition : $($PSVersionTable.PSEdition)")
$envLines.Add("")
$envLines.Add("=== Python detection ===")
$pythonExe = $null
foreach ($cand in @("python", "python3", "py")) {
    $cmd = Get-Command $cand -ErrorAction SilentlyContinue
    if ($cmd) {
        $envLines.Add("$cand -> $($cmd.Source)")
        try { $envLines.Add("  version: $(& $cand --version 2>&1)") } catch { $envLines.Add("  version: ERROR") }
        if (-not $pythonExe) { $pythonExe = $cmd.Source }
    } else {
        $envLines.Add("$cand -> NOT FOUND")
    }
}
$envLines.Add("")
$envLines.Add("=== PATH (first 10 entries) ===")
($env:PATH -split ";") | Select-Object -First 10 | ForEach-Object { $envLines.Add("  $_") }

$envLines | Out-File -FilePath (Join-Path $OutputDir "01_environment.txt") -Encoding utf8
Write-Host "    -> 01_environment.txt"

# -------- 2. File tree --------
Write-Host "[*] 2/6 File tree..." -ForegroundColor Yellow
$treeLines = New-Object System.Collections.Generic.List[string]
Get-ChildItem -Recurse -Force -File | Where-Object {
    $_.FullName -notmatch "\\\.git\\" -and
    $_.FullName -notmatch "\\venv\\" -and
    $_.FullName -notmatch "\\__pycache__\\" -and
    $_.FullName -notmatch "\\node_modules\\" -and
    $_.FullName -notmatch "\\_diagnostics\\"
} | ForEach-Object {
    $rel = $_.FullName.Substring($ProjectRoot.Length + 1)
    $treeLines.Add(("{0,10}  {1}" -f $_.Length, $rel))
}
$treeLines | Out-File -FilePath (Join-Path $OutputDir "02_filetree.txt") -Encoding utf8
Write-Host "    -> 02_filetree.txt"

# -------- 3. Copy key files verbatim --------
Write-Host "[*] 3/6 Copying source files verbatim..." -ForegroundColor Yellow
$copyTargets = @(
    "requirements.txt",
    "start.bat",
    "start.sh",
    "README.md",
    "app.py"
)
foreach ($f in $copyTargets) {
    $src = Join-Path $ProjectRoot $f
    if (Test-Path $src) {
        $dst = Join-Path $OutputDir ("03_src_" + ($f -replace "[\\/]", "_"))
        Copy-Item $src $dst -Force
        Write-Host "    copied $f"
    } else {
        Write-Host "    [skip] $f not found" -ForegroundColor DarkGray
    }
}

# -------- 4. pip freeze + pip check --------
if ($pythonExe) {
    Write-Host "[*] 4/6 pip freeze / pip check..." -ForegroundColor Yellow
    try {
        & $pythonExe -m pip freeze 2>&1 |
            Out-File -FilePath (Join-Path $OutputDir "04_pip_freeze.txt") -Encoding utf8
        & $pythonExe -m pip check 2>&1 |
            Out-File -FilePath (Join-Path $OutputDir "05_pip_check.txt") -Encoding utf8
        Write-Host "    -> 04_pip_freeze.txt, 05_pip_check.txt"
    } catch {
        Write-Host "    pip commands failed: $_" -ForegroundColor Red
    }

    # -------- 5. Python diagnostic --------
    Write-Host "[*] 5/6 Python diagnostic (_diagnose.py)..." -ForegroundColor Yellow
    if (Test-Path (Join-Path $ProjectRoot "_diagnose.py")) {
        & $pythonExe (Join-Path $ProjectRoot "_diagnose.py") 2>&1 |
            Out-File -FilePath (Join-Path $OutputDir "06_diagnose_output.txt") -Encoding utf8
        if (Test-Path (Join-Path $ProjectRoot "_diagnostics_report.json")) {
            Copy-Item (Join-Path $ProjectRoot "_diagnostics_report.json") `
                      (Join-Path $OutputDir "07_diagnostics_report.json") -Force
        }
        Write-Host "    -> 06_diagnose_output.txt, 07_diagnostics_report.json"
    } else {
        Write-Host "    [skip] _diagnose.py not found next to diagnose.ps1" -ForegroundColor Red
    }
} else {
    Write-Host "[!] No Python interpreter found - skipping pip + python diagnostics." -ForegroundColor Red
}

# -------- 6. Zip --------
Write-Host "[*] 6/6 Zipping..." -ForegroundColor Yellow
$zipPath = Join-Path $ProjectRoot "_diagnostics.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path "$OutputDir\*" -DestinationPath $zipPath -Force

Write-Host ""
Write-Host "=============================================================" -ForegroundColor Green
Write-Host "  Diagnostic complete." -ForegroundColor Green
Write-Host "  Send me: $zipPath" -ForegroundColor Green
Write-Host "=============================================================" -ForegroundColor Green