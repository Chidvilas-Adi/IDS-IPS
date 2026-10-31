#!/usr/bin/env bash
# =============================================================================
# start_all.sh — Dedicated Console Launcher on Port 1234
# =============================================================================

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

echo "================================================================="
echo "   DB-IDS/IPS ULTRA — DEDICATED CONSOLE ON PORT 1234             "
echo "================================================================="

HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "10.30.201.26")
echo "[*] Host Machine IP (Laptop A): $HOST_IP"
echo "[*] Target Dashboard URL:       http://$HOST_IP:1234"
echo "-----------------------------------------------------------------"

export PORT=1234

echo "[*] Starting Dedicated UI & Flask API (Port 1234)..."
(cd "$DIR/api" && python3 app.py 2>&1 | sed 's/^/[API] /') &
API_PID=$!

echo "[*] Starting In-Database Socket Bridge..."
if [ "$EUID" -ne 0 ] && command -v sudo &> /dev/null; then
    sudo python3 "$DIR/engine/pure_db_socket_bridge.py" &
    ENGINE_PID=$!
else
    python3 "$DIR/engine/pure_db_socket_bridge.py" &
    ENGINE_PID=$!
fi

echo "================================================================="
echo "   ALL DB-IDS/IPS COMPONENTS ARE RUNNING ON PORT 1234!           "
echo "================================================================="
echo "1. Local Console:   http://localhost:1234"
echo "2. Network Console: http://$HOST_IP:1234"
echo "3. Laptop B Folder: $DIR/laptop_b/ (or $DIR/laptop_b.zip)"
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
