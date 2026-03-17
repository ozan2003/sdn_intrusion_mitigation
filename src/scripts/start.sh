#!/usr/bin/env bash
# Orchestration script for the SDN threat detection demo.
# Must be run as root from the project root directory.

# Fail on error, unset variables, and pipefail.
set -euo pipefail

SCRIPT_NAME="${0##*/}"

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT_ROOT"
export PYTHONPATH="$PROJECT_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

RYU_PID=""
RYU_CMD=()
PYTHON_CMD=()
RYU_LOG_FILE="logs/ryu.log"

cleanup() {
    echo "[$SCRIPT_NAME] Cleaning up ..."
    [[ -n "$RYU_PID" ]] && kill "$RYU_PID" 2>/dev/null || true
    mn -c 2>/dev/null || true
    echo "[$SCRIPT_NAME] Done."
}
trap cleanup EXIT

# Sudo check
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "[$SCRIPT_NAME] This script must be run as root."
    echo "[$SCRIPT_NAME] Use: sudo ${0}"
    exit 1
fi

if [[ -x "$PROJECT_ROOT/.venv/bin/python3" ]] && \
    "$PROJECT_ROOT/.venv/bin/python3" -c "import ryu.cmd.manager" >/dev/null 2>&1; then
    # Use python -m to avoid stale/broken shebang paths inside ryu-manager entrypoint.
    RYU_CMD=("$PROJECT_ROOT/.venv/bin/python3" -m ryu.cmd.manager)
elif command -v ryu-manager >/dev/null 2>&1; then
    RYU_CMD=("$(command -v ryu-manager)")
else
    echo "[$SCRIPT_NAME] ryu-manager not found."
    echo "[$SCRIPT_NAME] Install dependencies or create .venv with ryu-manager."
    exit 1
fi

if [[ -x "$PROJECT_ROOT/.venv/bin/python3" ]]; then
    PYTHON_CMD=("$PROJECT_ROOT/.venv/bin/python3")
else
    PYTHON_CMD=("python3")
fi

echo "[$SCRIPT_NAME] Cleaning stale state ..."
mn -c 2>/dev/null || true

echo "[$SCRIPT_NAME] Creating logs directory ..."
mkdir -p logs
# these are truncated (assuming they exist) every invocation
: > logs/eve.json
: > logs/suricata_stderr.log
: > "$RYU_LOG_FILE"

echo "[$SCRIPT_NAME] Starting Ryu controller (log file: $RYU_LOG_FILE) ..."
"${RYU_CMD[@]}" \
    --log-file "$RYU_LOG_FILE" \
    --default-log-level 20 \
    --nouse-stderr \
    controller.app &
RYU_PID=$!
sleep 3
if ! kill -0 "$RYU_PID" 2>/dev/null; then
    echo "[$SCRIPT_NAME] Ryu controller exited unexpectedly. Check controller logs."
    exit 1
fi

echo "[$SCRIPT_NAME] Launching Mininet topology ..."
"${PYTHON_CMD[@]}" src/topology/network.py
