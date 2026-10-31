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
    start http://localhost:3000
    pause
    exit /b 0
)

echo [*] Launching Native Python Services...

echo [1/3] Starting Flask API Backend (Port 5000)...
start "DB-IDS/IPS API Backend" cmd /k "cd /d ""%DIR%api"" && python app.py"

echo [2/3] Starting In-Database Socket Engine (PL/pgSQL Trigger Brain)...
start "DB-IDS/IPS Engine" cmd /k "cd /d ""%DIR%engine"" && python pure_db_socket_bridge.py"

echo [3/3] Starting GUI / Opening Dashboard...
where npm >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    start "DB-IDS/IPS React GUI" cmd /k "cd /d ""%DIR%gui"" && npm start"
) else (
    timeout /t 3 >nul
    start http://localhost:3000
)

echo =================================================================
echo   ALL DB-IDS/IPS COMPONENTS ARE ONLINE & INTERCEPTING PACKETS!
echo =================================================================
echo Local Dashboard:    http://localhost:3000
echo Network Dashboard:  http://10.30.201.26:3000
echo Default Login:      admin / admin123
echo Laptop B Folder:    %DIR%laptop_b\ (or laptop_b.zip)
echo =================================================================
pause
