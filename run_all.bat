@echo off
setlocal
title DB-IDS/IPS Dedicated Console (Port 1234)
color 0B

set DIR=%~dp0
cd /d "%DIR%"

echo =================================================================
echo    DB-IDS/IPS ULTRA — DEDICATED CONSOLE ON PORT 1234
echo =================================================================

where docker >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [+] Docker detected! Launching services...
    docker compose up -d
    echo [+] System is live! Opening Dashboard on Port 1234...
    timeout /t 3 >nul
    start http://localhost:1234
    pause
    exit /b 0
)

echo [*] Launching Native Python Services...

echo [1/2] Starting Flask API Backend & Dedicated UI (Port 1234)...
start "DB-IDS/IPS Dedicated Console :1234" cmd /k "cd /d ""%DIR%api"" && set PORT=1234 && python app.py"

echo [2/2] Starting In-Database Socket Engine (PL/pgSQL Trigger Brain)...
start "DB-IDS/IPS Socket Engine" cmd /k "cd /d ""%DIR%engine"" && python pure_db_socket_bridge.py"

echo [*] Opening Dedicated Web Console on Port 1234...
timeout /t 3 >nul
start http://localhost:1234

echo =================================================================
echo   ALL DB-IDS/IPS COMPONENTS ARE ONLINE & INTERCEPTING PACKETS!
echo =================================================================
echo Local Console:      http://localhost:1234
echo Network Console:    http://10.30.201.26:1234
echo Laptop B Folder:    %DIR%laptop_b\ (or laptop_b.zip)
echo =================================================================
pause
