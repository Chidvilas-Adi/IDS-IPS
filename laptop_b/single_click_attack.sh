#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3 is required. On Arch Linux install it with: sudo pacman -S --needed python" >&2
    exit 1
fi

exec python3 run_demo.py "$@"
