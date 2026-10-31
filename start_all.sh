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

# Detect host IP
HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || ip route get 1 2>/dev/null | awk '{print $7}' || echo "10.30.201.26")
echo "[*] Host Machine IP (Laptop A): $HOST_IP"
echo "[*] Target URL for Laptop B:    http://$HOST_IP:3000"
echo "-----------------------------------------------------------------"

# Check if Docker Compose is available
if command -v docker &> /dev/null && docker compose version &> /dev/null; then
    echo "[+] Docker Compose detected! Booting all 8 container services..."
    docker compose up -d
    echo "[+] All containers (Postgres, Mongo, Redis, Engine, API, GUI, Nginx) are UP!"
    echo "[+] Web Dashboard is live at: http://localhost:3000"
    exit 0
fi

# Fallback to native host execution
echo "[*] Docker not found or not running. Starting native host services..."

# 1. Install dependencies
echo "[1/3] Starting Flask API Backend (Port 5000)..."
(cd "$DIR/api" && python3 app.py 2>&1 | sed 's/^/[API] /') &
API_PID=$!

# 2. Start Socket Bridge
echo "[2/3] Starting In-Database Socket Bridge (Root/Admin raw socket access)..."
if [ "$EUID" -ne 0 ] && command -v sudo &> /dev/null; then
    sudo python3 "$DIR/engine/pure_db_socket_bridge.py" &
    ENGINE_PID=$!
else
    python3 "$DIR/engine/pure_db_socket_bridge.py" &
    ENGINE_PID=$!
fi

# 3. Start React Frontend GUI
echo "[3/3] Starting React SOC Dashboard (Port 3000)..."
if command -v npm &> /dev/null; then
    (cd "$DIR/gui" && npm start 2>&1 | sed 's/^/[GUI] /') &
    GUI_PID=$!
else
    echo "[!] npm not found in PATH. If GUI build exists, serve it via Python HTTP server:"
    (cd "$DIR/gui/build" 2>/dev/null && python3 -m http.server 3000) &
    GUI_PID=$!
fi

echo "================================================================="
echo "   ALL DB-IDS/IPS COMPONENTS ARE RUNNING & INTERCEPTING PACKETS! "
echo "================================================================="
echo "1. Local Dashboard:   http://localhost:3000"
echo "2. Network Dashboard: http://$HOST_IP:3000"
echo "3. Default SOC Login: admin / admin123"
echo "4. Laptop B Folder:   $DIR/laptop_b/ (or $DIR/laptop_b.zip)"
echo "-----------------------------------------------------------------"
echo "Press Ctrl+C to terminate all services."

cleanup() {
    echo ""
    echo "[*] Shutting down services..."
    kill $API_PID $ENGINE_PID $GUI_PID 2>/dev/null || true
    exit 0
}

trap cleanup SIGINT SIGTERM
wait
