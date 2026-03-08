#!/usr/bin/env bash
# Orchestration script for the SDN threat detection demo.
# Must be run as root from the project root directory.

# Fail on error, unset variables, and pipefail.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT_ROOT"
export PYTHONPATH="$PROJECT_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

RYU_PID=""
SURICATA_PID_FILE="/var/run/suricata.pid"

# Stopping of suricata process is handled by bash not Python
kill_suricata() {
    if [[ -f "$SURICATA_PID_FILE" ]]; then
        local suricata_pid
        suricata_pid="$(<"$SURICATA_PID_FILE")"
        if [[ -n "$suricata_pid" ]] && kill -0 "$suricata_pid" 2>/dev/null; then
            kill "$suricata_pid" 2>/dev/null || true
        fi
        rm -f "$SURICATA_PID_FILE"
    fi
    pkill -x suricata 2>/dev/null || true
}

cleanup() {
    echo "[start.sh] Cleaning up ..."
    kill_suricata
    [[ -n "$RYU_PID" ]] && kill "$RYU_PID" 2>/dev/null || true
    mn -c 2>/dev/null || true
    echo "[start.sh] Done."
}
trap cleanup EXIT

# Sudo check
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "[start.sh] This script must be run as root."
    echo "[start.sh] Use: sudo ./src/scripts/start.sh"
    exit 1
fi

if [[ -x "$PROJECT_ROOT/.venv/bin/ryu-manager" ]]; then
    RYU_MANAGER="$PROJECT_ROOT/.venv/bin/ryu-manager"
elif command -v ryu-manager >/dev/null 2>&1; then
    RYU_MANAGER="$(command -v ryu-manager)"
else
    echo "[start.sh] ryu-manager not found."
    echo "[start.sh] Install dependencies or create .venv with ryu-manager."
    exit 1
fi

echo "[start.sh] Cleaning stale state ..."
mn -c 2>/dev/null || true
kill_suricata

echo "[start.sh] Creating logs directory ..."
mkdir -p logs
: > logs/eve.json

echo "[start.sh] Starting Ryu controller ..."
"$RYU_MANAGER" controller.app &
RYU_PID=$!
sleep 3
if ! kill -0 "$RYU_PID" 2>/dev/null; then
    echo "[start.sh] Ryu controller exited unexpectedly. Check controller logs."
    exit 1
fi

echo "[start.sh] Launching Mininet topology ..."
python3 src/topology/network.py
