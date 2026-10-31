@echo off
setlocal
title DB-IDS/IPS Dedicated Console (Port 1234)
color 0B

set DIR=%~dp0
cd /d "%DIR%"

echo =================================================================
echo    DB-IDS/IPS ULTRA — DEDICATED CONSOLE ON PORT 1234
echo =================================================================

echo [1/2] Starting Dedicated Web Dashboard on Port 1234...
start "DB-IDS/IPS Console :1234" python "%DIR%api\app.py"

echo [2/2] Starting In-Database Socket Engine...
start "DB-IDS/IPS Socket Engine" python "%DIR%engine\pure_db_socket_bridge.py"

echo [*] Opening Web Console in your browser...
timeout /t 2 >nul
start http://localhost:1234

echo =================================================================
echo   ALL DB-IDS/IPS COMPONENTS ARE LIVE & INTERCEPTING PACKETS!
echo =================================================================
echo Local Console:      http://localhost:1234
echo Network Console:    http://10.30.201.26:1234
echo Laptop B Folder:    %DIR%laptop_b\ (or laptop_b.zip)
echo =================================================================
pause
