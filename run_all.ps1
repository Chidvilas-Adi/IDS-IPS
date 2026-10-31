# =============================================================================
# run_all.ps1 — Master 1-Click Automated Launcher for DB-IDS/IPS Platform
# Starts all databases, engines, APIs, and GUI in synchronized harmony.
# =============================================================================

$ErrorActionPreference = "Continue"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "   DB-IDS/IPS ULTRA — 100% DATABASE-DRIVEN PLATFORM LAUNCHER     " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# 1. Get Host IP for Laptop B connection
$localIp = "127.0.0.1"
try {
    $ipConfig = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "Wi-Fi*" -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
    if ($ipConfig) { $localIp = $ipConfig }
    else {
        $adapter = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.*" } | Select-Object -First 1
        if ($adapter) { $localIp = $adapter.IPAddress }
    }
} catch {
    $localIp = "10.30.201.26"
}

Write-Host "[*] Host Machine IP (Laptop A): " -NoNewline
Write-Host "$localIp" -ForegroundColor Green
Write-Host "[*] Target URL for Laptop B:    " -NoNewline
Write-Host "http://$localIp:5000" -ForegroundColor Yellow
Write-Host "-----------------------------------------------------------------" -ForegroundColor Cyan

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

# 2. Check for Docker Compose vs Native Python Mode
$hasDocker = (Get-Command docker -ErrorAction SilentlyContinue)

if ($hasDocker) {
    Write-Host "[+] Docker detected! Booting all 8 container services..." -ForegroundColor Green
    Set-Location $projectRoot
    docker compose up -d
    Write-Host "[+] All containers started successfully!" -ForegroundColor Green
} else {
    Write-Host "[*] Launching in Native Host Mode..." -ForegroundColor Yellow

    # Step A: Install engine dependencies if needed
    Write-Host "[1/4] Checking Python Engine Dependencies..." -ForegroundColor Cyan
    Set-Location "$projectRoot\engine"
    pip install -q -r requirements.txt

    # Step B: Install API dependencies if needed
    Write-Host "[2/4] Checking Flask API Dependencies..." -ForegroundColor Cyan
    Set-Location "$projectRoot\api"
    pip install -q -r requirements.txt

    # Step C: Start API Gateway in background
    Write-Host "[3/4] Launching Flask REST + WebSocket API on :5000..." -ForegroundColor Green
    $apiJob = Start-Process -FilePath "python" -ArgumentList "app.py" -WorkingDirectory "$projectRoot\api" -PassThru

    # Step D: Start 100% In-Database Socket Bridge
    Write-Host "[4/4] Launching In-Database Socket Engine (PL/pgSQL Trigger Brain)..." -ForegroundColor Green
    $engineJob = Start-Process -FilePath "python" -ArgumentList "pure_db_socket_bridge.py" -WorkingDirectory "$projectRoot\engine" -PassThru
}

# 3. Launch Integrated SOC Dashboard GUI
Write-Host "[+] Launching Dashboard on http://localhost:5000..." -ForegroundColor Green
Start-Process "http://localhost:5000" -ErrorAction SilentlyContinue

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "   ALL DB-IDS/IPS COMPONENTS ARE RUNNING & INTERCEPTING PACKETS! " -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "1. Dashboard URL (Local):    http://localhost:5000" -ForegroundColor White
Write-Host "2. Dashboard URL (Laptop B): http://${localIp}:5000" -ForegroundColor White
Write-Host "3. Default SOC Login:        admin / admin123" -ForegroundColor White
Write-Host "4. Laptop B Testing Suite:   Inside folder '\laptop_b'" -ForegroundColor Yellow
Write-Host "-----------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to terminate all services when finished.`n"
