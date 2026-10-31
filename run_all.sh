#!/usr/bin/env bash
# =============================================================================
# run_all.sh — Linux/macOS/WSL 1-Click Automated Launcher for DB-IDS/IPS
# =============================================================================

echo "================================================================="
echo "   DB-IDS/IPS ULTRA — 100% DATABASE-DRIVEN PLATFORM LAUNCHER     "
echo "================================================================="

if command -v docker &> /dev/null && docker compose version &> /dev/null; then
    echo "[+] Starting all containers with Docker Compose..."
    docker compose up -d
    echo "[+] System online at http://localhost:5000"
    exit 0
fi

echo "[*] Starting Flask API Backend..."
(cd api && python3 app.py) &
API_PID=$!

echo "[*] Starting In-Database Socket Bridge (Root/Sudo required for raw socket)..."
(cd engine && sudo python3 pure_db_socket_bridge.py) &
ENGINE_PID=$!

echo "================================================================="
echo "   SYSTEM ONLINE & INTERCEPTING PACKETS!                        "
echo "================================================================="
echo "API PID: $API_PID | Engine PID: $ENGINE_PID"
echo "Dashboard: http://localhost:5000"
echo "Laptop B Scripts located in: ./laptop_b/"

trap "kill $API_PID $ENGINE_PID 2>/dev/null; exit" SIGINT SIGTERM
wait
