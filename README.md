# Simple Cracker

Outil GUI (PySide6) pour extraire des empreintes de fichiers protégés puis lancer une attaque avec John the Ripper ou Hashcat.

## Prérequis rapides (Debian/Ubuntu)
- Internet actif (téléchargement des sources John Jumbo).
- Paquets système : `python3`, `python3-venv`, `python3-pip`, `build-essential`, `libssl-dev`, `zlib1g-dev`, `libgmp-dev`, `libpcap-dev`, `pkg-config`, `libbz2-dev`, `libzstd-dev`, `yasm`, `curl`, `git`, `hashcat`, `ocl-icd-opencl-dev`, `pocl-opencl-icd`.
- GPU/driver OpenCL optionnel pour Hashcat, sinon CPU.

## Installation automatique
1. Exécuter le script depuis la racine du projet :
   ```bash
   chmod +x install.sh
   ./install.sh
   ```
   Le script va :
   - installer les dépendances système (via `apt-get`) ;
   - créer l’environnement virtuel Python `env/` et installer `PySide6` ;
   - télécharger et compiler la branche `bleeding-jumbo` de John the Ripper dans `resources/john-jumbo/john-bleeding-jumbo` ;
   - ajouter des raccourcis (`env/bin/john`, `env/john_env.sh`) pour que la GUI trouve les scripts *2john et le binaire `john`.

2. Activer l’environnement et lancer l’application :
   ```bash
   source env/bin/activate
   source env/john_env.sh   # exporte JOHN_JUMBO_RUN_PATH + PATH
   python main.py
   ```

## Notes d’utilisation
- L’onglet « Dictionary » nécessite un wordlist existant (ex. `/usr/share/wordlists/rockyou.txt`).
- Hashcat doit être installé via `apt` (géré par `install.sh`). Si vous utilisez un GPU, assurez-vous que les pilotes OpenCL/NVIDIA/AMD sont en place.
- Pour mettre à jour John Jumbo, supprimez `resources/john-jumbo` et relancez `./install.sh`.

## Structure utile
- `main.py` : bootstrap de l’application.
- `gui/main_window.py` : interface et logique utilisateur.
- `core/hash_extractor.py` : extraction de hash via scripts *2john.
- `core/john_backend.py` / `core/hashcat_backend.py` : lancement des attaques.
