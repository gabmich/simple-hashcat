#!/usr/bin/env bash
set -euo pipefail

# Launch the GUI from the project virtualenv.
# Creates and bootstraps the venv on first run.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_DIR="${ROOT_DIR}/env"

if [[ ! -x "${ENV_DIR}/bin/python" ]]; then
  echo "[run] Creating virtualenv in ${ENV_DIR}..."
  python3 -m venv "${ENV_DIR}"
  "${ENV_DIR}/bin/python" -m pip install --upgrade pip
  "${ENV_DIR}/bin/pip" install -r "${ROOT_DIR}/requirements.txt"
fi

# If john env helper exists (from install.sh), source it so *2john scripts are on PATH.
if [[ -f "${ENV_DIR}/john_env.sh" ]]; then
  # shellcheck source=/dev/null
  source "${ENV_DIR}/john_env.sh"
fi

echo "[run] Launching Simple Cracker..."
exec "${ENV_DIR}/bin/python" "${ROOT_DIR}/main.py"
