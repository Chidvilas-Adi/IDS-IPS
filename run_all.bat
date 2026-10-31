@echo off
setlocal
title DB-IDS/IPS Automated Master Launcher
color 0B

echo =================================================================
echo    DB-IDS/IPS ULTRA — 100% DATABASE-DRIVEN PLATFORM LAUNCHER
echo =================================================================

where docker >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [+] Docker detected! Launching all services with Docker Compose...
    docker compose up -d
    echo [+] System is live!
    start http://localhost:3000
    pause
    exit /b 0
)

echo [*] Launching Native Python Services...
echo [1/3] Starting Flask API Backend (Port 5000)...
start "DB-IDS/IPS API" cmd /k "cd api && python app.py"

echo [2/3] Starting In-Database Socket Engine (PL/pgSQL Trigger Brain)...
start "DB-IDS/IPS Engine" cmd /k "cd engine && python pure_db_socket_bridge.py"

echo [3/3] Opening Web Dashboard...
timeout /t 3 >nul
start http://localhost:3000

echo =================================================================
echo   SYSTEM ONLINE & INTERCEPTING PACKETS!
echo =================================================================
echo Local Dashboard:    http://localhost:3000
echo Network Dashboard:  http://10.30.201.26:3000
echo Default Login:      admin / admin123
echo Laptop B Scripts:   Located in '\laptop_b'
echo =================================================================
pause
