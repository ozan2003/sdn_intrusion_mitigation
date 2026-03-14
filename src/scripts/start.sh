#!/usr/bin/env bash
# Orchestration script for the SDN threat detection demo.
# Must be run as root from the project root directory.

# Fail on error, unset variables, and pipefail.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT_ROOT"
export PYTHONPATH="$PROJECT_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

RYU_PID=""
RYU_CMD=()
PYTHON_CMD=()
RYU_LOG_FILE="logs/ryu.log"

cleanup() {
    echo "[start.sh] Cleaning up ..."
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

if [[ -x "$PROJECT_ROOT/.venv/bin/python3" ]] && \
    "$PROJECT_ROOT/.venv/bin/python3" -c "import ryu.cmd.manager" >/dev/null 2>&1; then
    # Use python -m to avoid stale/broken shebang paths inside ryu-manager entrypoint.
    RYU_CMD=("$PROJECT_ROOT/.venv/bin/python3" -m ryu.cmd.manager)
elif command -v ryu-manager >/dev/null 2>&1; then
    RYU_CMD=("$(command -v ryu-manager)")
else
    echo "[start.sh] ryu-manager not found."
    echo "[start.sh] Install dependencies or create .venv with ryu-manager."
    exit 1
fi

if [[ -x "$PROJECT_ROOT/.venv/bin/python3" ]]; then
    PYTHON_CMD=("$PROJECT_ROOT/.venv/bin/python3")
else
    PYTHON_CMD=("python3")
fi

echo "[start.sh] Cleaning stale state ..."
mn -c 2>/dev/null || true

echo "[start.sh] Creating logs directory ..."
mkdir -p logs
: > logs/eve.json
: > logs/suricata_stderr.log
: > "$RYU_LOG_FILE"

echo "[start.sh] Starting Ryu controller (log file: $RYU_LOG_FILE) ..."
"${RYU_CMD[@]}" \
    --log-file "$RYU_LOG_FILE" \
    --default-log-level 20 \
    --nouse-stderr \
    controller.app &
RYU_PID=$!
sleep 3
if ! kill -0 "$RYU_PID" 2>/dev/null; then
    echo "[start.sh] Ryu controller exited unexpectedly. Check controller logs."
    exit 1
fi

echo "[start.sh] Launching Mininet topology ..."
"${PYTHON_CMD[@]}" src/topology/network.py
