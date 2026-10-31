#!/usr/bin/env bash
# =============================================================================
# run_all.sh — Dedicated Console Launcher on Port 1234
# =============================================================================

export PORT=1234
echo "================================================================="
echo "   DB-IDS/IPS ULTRA — DEDICATED CONSOLE ON PORT 1234             "
echo "================================================================="

(cd api && python3 app.py) &
API_PID=$!

(cd engine && python3 pure_db_socket_bridge.py) &
ENGINE_PID=$!

echo "[+] Dedicated Console Live at: http://localhost:1234"
echo "API PID: $API_PID | Engine PID: $ENGINE_PID"

trap "kill $API_PID $ENGINE_PID 2>/dev/null; exit" SIGINT SIGTERM
wait
