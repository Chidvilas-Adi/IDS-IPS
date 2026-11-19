@echo off
setlocal
title DB-IDS/IPS Promiscuous Sniffer (Admin Required)
color 0C

:: Auto-elevate to Administrator for Windows Raw Socket Promiscuous Mode
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Requesting Administrator privileges for full network packet capture...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
cls
color 0A
echo =================================================================
echo   DB-IDS/IPS PROMISCUOUS PACKET SNIFFER (RUNNING AS ADMIN)
echo =================================================================
echo [*] Promiscuous Mode enables capturing ALL outgoing & incoming:
echo     - Website connections (Firefox, Chrome, Edge, Safari)
echo     - DNS queries, TCP, UDP, ICMP, and HTTP payloads
echo     - External attacks from Laptop B on LAN / Wi-Fi
echo [*] Inserting all packets directly into database for analysis...
echo =================================================================
echo.

python "%~dp0engine\pure_db_socket_bridge.py"
pause
