#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PY="$ROOT/.venv_ubuntu2204/bin/python"
if [[ ! -x "$PY" ]]; then
  PY="$ROOT/.venv_wsl/bin/python"
fi

export PAD_K="${PAD_K:-4}"
export PYTHONPATH="$ROOT:${PYTHONPATH:-}"

exec "$PY" scripts/sim_demo_state.py "$@"
