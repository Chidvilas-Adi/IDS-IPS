@echo off
setlocal
title DB-IDS/IPS (PostgreSQL detection engine)
cd /d "%~dp0"

if not exist ".env" (
    echo [!] .env is missing. Copy .env.example to .env and configure it first.
    exit /b 1
)

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Administrator access is required for packet capture and firewall actions.
    powershell -NoProfile -Command "Start-Process -FilePath $env:ComSpec -ArgumentList '/c', '""%~f0""' -Verb RunAs"
    if errorLevel 1 (
        echo [!] Could not request administrator access. Open PowerShell as Administrator and run .\run_all.bat.
        exit /b 1
    )
    exit /b
)

set "POSTGRES_HOST=localhost"
set "DATABASE_URL="
set "MONGO_HOST=localhost"
set "REDIS_HOST=localhost"
set "API_PORT=1234"

echo [*] Starting PostgreSQL, MongoDB, and Redis...
docker compose up -d --wait postgres mongodb redis
if errorLevel 1 (
    echo [!] Database services failed to start. See: docker compose logs postgres mongodb redis
    exit /b 1
)

echo [*] Applying the PostgreSQL schema and migrations...
docker compose run --rm schema
if errorLevel 1 (
    echo [!] PostgreSQL schema application failed.
    exit /b 1
)

docker compose up -d --no-deps --wait api
if errorLevel 1 (
    echo [!] API failed to start. See: docker compose logs api
    exit /b 1
)

echo [*] Building and starting the React dashboard and HTTPS gateway...
docker compose up -d --build --wait gui nginx
if errorLevel 1 (
    echo [!] Dashboard or gateway failed to start. See: docker compose logs gui nginx
    exit /b 1
)

if not exist "engine\.venv\Scripts\python.exe" (
    echo [*] Creating the packet-adapter Python environment...
    py -3 -m venv "engine\.venv"
    if errorLevel 1 (
        echo [!] Python 3 is required to create engine\.venv.
        exit /b 1
    )
)

"engine\.venv\Scripts\python.exe" -m pip install -r "engine\requirements-bridge.txt"
if errorLevel 1 (
    echo [!] Could not install the packet-adapter requirements.
    exit /b 1
)

echo [*] Starting the packet adapter. Detection and correlation execute in PostgreSQL.
start "DB-IDS/IPS Packet Adapter" cmd /k "cd /d ""%~dp0engine"" && .venv\Scripts\python.exe pure_db_socket_bridge.py"

timeout /t 2 >nul
start https://localhost:8443
echo [+] Dashboard: https://localhost:8443
echo [+] Local-only API: http://127.0.0.1:1234
echo [+] PostgreSQL triggers own packet classification and response decisions.
echo [*] Stop the database containers with: docker compose down
