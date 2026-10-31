@echo off
setlocal
title DB-IDS/IPS Automated Master Launcher
color 0B

set DIR=%~dp0
cd /d "%DIR%"

echo =================================================================
echo    DB-IDS/IPS ULTRA — 100% DATABASE-DRIVEN PLATFORM LAUNCHER
echo =================================================================

where docker >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [+] Docker detected! Launching all services with Docker Compose...
    docker compose up -d
    echo [+] System is live! Opening Dashboard...
    timeout /t 3 >nul
    start http://localhost:5000
    pause
    exit /b 0
)

echo [*] Launching Native Python Services...

echo [1/2] Starting Flask API Backend & Web Dashboard (Port 5000)...
start "DB-IDS/IPS Dashboard & API" cmd /k "cd /d ""%DIR%api"" && python app.py"

echo [2/2] Starting In-Database Socket Engine (PL/pgSQL Trigger Brain)...
start "DB-IDS/IPS Socket Engine" cmd /k "cd /d ""%DIR%engine"" && python pure_db_socket_bridge.py"

echo [*] Opening Real-Time SOC Web Dashboard...
timeout /t 3 >nul
start http://localhost:5000

echo =================================================================
echo   SYSTEM ONLINE & INTERCEPTING PACKETS!
echo =================================================================
echo Local Dashboard:    http://localhost:5000
echo Network Dashboard:  http://10.30.201.26:5000
echo Laptop B Folder:    %DIR%laptop_b\ (or laptop_b.zip)
echo =================================================================
pause
