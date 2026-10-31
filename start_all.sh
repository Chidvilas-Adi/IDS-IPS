#!/usr/bin/env bash
# =============================================================================
# start_all.sh — Universal 1-Click Startup Script for DB-IDS/IPS Platform
# Works on Linux, macOS, WSL, and Git Bash on Windows.
# =============================================================================

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

echo "================================================================="
echo "   DB-IDS/IPS ULTRA — 100% DATABASE-DRIVEN PLATFORM LAUNCHER     "
echo "================================================================="

HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || ip route get 1 2>/dev/null | awk '{print $7}' || echo "10.30.201.26")
echo "[*] Host Machine IP (Laptop A): $HOST_IP"
echo "[*] Target Dashboard URL:       http://$HOST_IP:5000"
echo "-----------------------------------------------------------------"

# Check if Docker Compose is available
if command -v docker &> /dev/null && docker compose version &> /dev/null; then
    echo "[+] Docker Compose detected! Booting all 8 container services..."
    docker compose up -d
    echo "[+] System online at http://localhost:5000"
    exit 0
fi

echo "[*] Starting Flask API Backend & Real-Time Dashboard (Port 5000)..."
(cd "$DIR/api" && python3 app.py 2>&1 | sed 's/^/[API] /') &
API_PID=$!

echo "[*] Starting In-Database Socket Bridge (Root/Admin raw socket access)..."
if [ "$EUID" -ne 0 ] && command -v sudo &> /dev/null; then
    sudo python3 "$DIR/engine/pure_db_socket_bridge.py" &
    ENGINE_PID=$!
else
    python3 "$DIR/engine/pure_db_socket_bridge.py" &
    ENGINE_PID=$!
fi

echo "================================================================="
echo "   ALL DB-IDS/IPS COMPONENTS ARE RUNNING & INTERCEPTING PACKETS! "
echo "================================================================="
echo "1. Local Dashboard:   http://localhost:5000"
echo "2. Network Dashboard: http://$HOST_IP:5000"
echo "3. Laptop B Folder:   $DIR/laptop_b/ (or $DIR/laptop_b.zip)"
echo "-----------------------------------------------------------------"
echo "Press Ctrl+C to terminate all services."

cleanup() {
    echo ""
    echo "[*] Shutting down services..."
    kill $API_PID $ENGINE_PID 2>/dev/null || true
    exit 0
}

trap cleanup SIGINT SIGTERM
wait
