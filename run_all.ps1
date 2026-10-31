# =============================================================================
# run_all.ps1 — Master Launcher for DB-IDS/IPS Platform on Port 1234
# =============================================================================

$ErrorActionPreference = "Continue"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "   DB-IDS/IPS ULTRA — DEDICATED CONSOLE ON PORT 1234             " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

$localIp = "10.30.201.26"
try {
    $ipConfig = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "Wi-Fi*" -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
    if ($ipConfig) { $localIp = $ipConfig }
} catch {
    $localIp = "10.30.201.26"
}

Write-Host "[*] Host Machine IP (Laptop A): " -NoNewline
Write-Host "$localIp" -ForegroundColor Green
Write-Host "[*] Target Console URL:         " -NoNewline
Write-Host "http://$localIp:1234" -ForegroundColor Yellow
Write-Host "-----------------------------------------------------------------" -ForegroundColor Cyan

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

# Start API Backend on Port 1234
Write-Host "[1/2] Launching Dedicated UI & Flask API on Port 1234..." -ForegroundColor Green
$env:PORT = "1234"
$apiJob = Start-Process -FilePath "python" -ArgumentList "app.py" -WorkingDirectory "$projectRoot\api" -PassThru

# Start Socket Engine
Write-Host "[2/2] Launching In-Database Socket Engine (PL/pgSQL Trigger Brain)..." -ForegroundColor Green
$engineJob = Start-Process -FilePath "python" -ArgumentList "pure_db_socket_bridge.py" -WorkingDirectory "$projectRoot\engine" -PassThru

# Launch Browser
Write-Host "[+] Launching Dashboard on http://localhost:1234..." -ForegroundColor Green
Start-Process "http://localhost:1234" -ErrorAction SilentlyContinue

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "   DEDICATED CONSOLE IS ONLINE & INTERCEPTING PACKETS!           " -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "1. Local Console:      http://localhost:1234" -ForegroundColor White
Write-Host "2. Network Console:    http://${localIp}:1234" -ForegroundColor White
Write-Host "3. Laptop B Folder:    $projectRoot\laptop_b\" -ForegroundColor Yellow
Write-Host "-----------------------------------------------------------------" -ForegroundColor Cyan
