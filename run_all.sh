#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [[ ! -f .env ]]; then
    echo "[!] .env is missing. Copy .env.example to .env and configure it first." >&2
    exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
    echo "[!] Run with sudo for packet capture and firewall actions." >&2
    exit 1
fi

export POSTGRES_HOST=localhost
export DATABASE_URL=
export MONGO_HOST=localhost
export REDIS_HOST=localhost
export API_PORT=1234

echo "[*] Starting PostgreSQL, MongoDB, and Redis..."
docker compose up -d --wait postgres mongodb redis
echo "[*] Applying the PostgreSQL schema and migrations..."
docker compose run --rm schema
docker compose up -d --no-deps --wait api
docker compose up -d --build --wait gui nginx

if [[ ! -x "$ROOT/engine/.venv/bin/python" ]]; then
    python3 -m venv "$ROOT/engine/.venv"
fi
"$ROOT/engine/.venv/bin/python" -m pip install -r "$ROOT/engine/requirements-bridge.txt"

(cd "$ROOT/engine" && .venv/bin/python -u pure_db_socket_bridge.py) &
BRIDGE_PID=$!

cleanup() {
    kill "$BRIDGE_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "[+] Dashboard: https://localhost:8443"
echo "[+] PostgreSQL owns packet detection and correlation."
wait
