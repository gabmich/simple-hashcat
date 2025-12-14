#!/usr/bin/env bash
set -euo pipefail

# Installation complète pour Debian/Ubuntu : dépendances système,
# environnement Python, téléchargement/compilation de John the Ripper Jumbo.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JTR_BRANCH="bleeding-jumbo"
JTR_ARCHIVE_URL="https://github.com/openwall/john/archive/refs/heads/${JTR_BRANCH}.tar.gz"
JTR_ROOT="${ROOT_DIR}/resources/john-jumbo"
JTR_SRC_DIR="${JTR_ROOT}/john-${JTR_BRANCH}"
JTR_RUN_DIR="${JTR_SRC_DIR}/run"

log() {
  echo "[install] $*"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Commande requise absente: $1" >&2
    exit 1
  }
}

log "Vérification des commandes de base..."
need_cmd apt-get
if command -v sudo >/dev/null 2>&1; then
  APT_GET_CMD=(sudo apt-get)
else
  APT_GET_CMD=(apt-get)
fi

if [[ "${EUID:-$(id -u)}" -ne 0 ]] && [[ "${APT_GET_CMD[0]}" != "sudo" ]]; then
  echo "Cette installation nécessite sudo ou un shell root pour apt-get." >&2
  exit 1
fi

log "Installation des dépendances système (apt-get)..."
"${APT_GET_CMD[@]}" update
"${APT_GET_CMD[@]}" install -y \
  python3 python3-venv python3-pip \
  build-essential libssl-dev zlib1g-dev libgmp-dev libpcap-dev pkg-config \
  libbz2-dev libzstd-dev yasm curl git hashcat \
  ocl-icd-opencl-dev pocl-opencl-icd

log "Création/activation de l'environnement virtuel Python..."
python3 -m venv "${ROOT_DIR}/env"
source "${ROOT_DIR}/env/bin/activate"
pip install --upgrade pip
pip install -r "${ROOT_DIR}/requirements.txt"

if [[ ! -x "${JTR_RUN_DIR}/john" ]]; then
  log "Téléchargement de John the Ripper (${JTR_BRANCH})..."
  rm -rf "${JTR_ROOT}"
  mkdir -p "${JTR_ROOT}"
  curl -L "${JTR_ARCHIVE_URL}" | tar xz -C "${JTR_ROOT}"

  log "Compilation de John (peut prendre quelques minutes)..."
  (cd "${JTR_SRC_DIR}/src" && ./configure && make -sj"$(nproc)")
else
  log "John déjà présent dans ${JTR_RUN_DIR}, téléchargement/compilation sautés."
fi

log "Configuration des chemins John..."
mkdir -p "${ROOT_DIR}/env"
cat > "${ROOT_DIR}/env/john_env.sh" <<'EOF'
# A sourcer après activation du venv pour exposer john + scripts *2john
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export JOHN_JUMBO_RUN_PATH="${ROOT_DIR}/resources/john-jumbo/john-bleeding-jumbo/run"
export PATH="${JOHN_JUMBO_RUN_PATH}:${PATH}"
EOF

# Symlink du binaire john dans le venv pour que la détection fonctionne via PATH activé.
ln -sf "${JTR_RUN_DIR}/john" "${ROOT_DIR}/env/bin/john"

log "Installation terminée."
log "Activez l'environnement puis lancez l'app :"
log "  source env/bin/activate"
log "  source env/john_env.sh"
log "  python main.py"
