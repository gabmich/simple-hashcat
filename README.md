# Simple Cracker

Outil GUI (PySide6) pour extraire des empreintes de fichiers protégés par mot de passe, puis lancer une attaque avec John the Ripper ou Hashcat.

## Fonctionnalités

- **Extraction automatique de hash** depuis des fichiers chiffrés (ZIP, 7z, RAR, PDF, Office, KeePass, etc.)
- **Deux backends** : John the Ripper et Hashcat (GPU)
- **Modes d'attaque** :
  - Dictionnaire (wordlist)
  - Brute force avec charset configurable
  - Masque personnalisé
  - Dictionnaire + rules
- **Custom charset** : définir précisément les caractères autorisés (ex: `wk`, `a-z`, `A-Z0-9`)
- **Interface moderne** en 3 colonnes avec log collapsible

## Formats supportés

| Format | Extensions | Mode Hashcat |
|--------|-----------|--------------|
| ZIP | .zip | 17200 |
| 7-Zip | .7z | 11600 |
| RAR | .rar | 13000, 23700 |
| PDF | .pdf | 10500, 10600 |
| MS Office | .doc, .docx, .xls, .xlsx, .ppt, .pptx | 9600, 9700 |
| OpenDocument | .odt, .ods, .odp, .odg | 18400 |
| KeePass | .kdbx, .kdb | 13400 |
| Clés SSH | - | 22911 |
| GPG | .gpg, .pgp | 17010 |

## Prérequis (Debian/Ubuntu)

- Python 3.7+
- Paquets système :
  ```bash
  sudo apt install python3 python3-venv python3-pip build-essential \
    libssl-dev zlib1g-dev libgmp-dev libpcap-dev pkg-config \
    libbz2-dev libzstd-dev yasm curl git hashcat \
    ocl-icd-opencl-dev pocl-opencl-icd
  ```
- GPU/driver OpenCL optionnel pour Hashcat (sinon CPU via `--force`)

## Installation

1. Cloner le projet et exécuter le script d'installation :
   ```bash
   git clone <repo-url> simple-hashcat
   cd simple-hashcat
   chmod +x install.sh
   ./install.sh
   ```

   Le script va :
   - Installer les dépendances système (via `apt-get`)
   - Créer l'environnement virtuel Python `env/` et installer PySide6
   - Télécharger et compiler John the Ripper (branche bleeding-jumbo)
   - Configurer les chemins pour les scripts *2john

2. Lancer l'application :
   ```bash
   ./run.sh
   ```

   Ou manuellement :
   ```bash
   source env/bin/activate
   source env/john_env.sh
   python main.py
   ```

## Utilisation

### 1. Sélectionner un fichier chiffré

Cliquez sur **Browse** et sélectionnez un fichier protégé par mot de passe. Le hash sera extrait automatiquement.

### 2. Choisir le backend

- **John the Ripper** : CPU, bon pour les attaques dictionary/rules
- **Hashcat** : GPU (beaucoup plus rapide si disponible)

### 3. Configurer l'attaque

#### Mode Dictionary
- Sélectionnez une wordlist (ex: `/usr/share/wordlists/rockyou.txt`)
- Optionnel : activez les rules pour générer des variantes

#### Mode Brute Force
- **Character Set** : choisissez un charset prédéfini ou "Custom"
- **Custom Characters** : définissez vos propres caractères autorisés
  - Explicite : `wk` (seulement 'w' et 'k')
  - Ranges : `a-z`, `A-Z`, `0-9`
  - Combiné : `a-zA-Z0-9`, `a-f0-9` (hex)
- **Password Length** : min et max
- **Increment mode** : teste d'abord les longueurs courtes

#### Mode Mask
- Pattern avec placeholders :
  - `?l` = minuscule (a-z)
  - `?u` = majuscule (A-Z)
  - `?d` = chiffre (0-9)
  - `?s` = spécial (!@#$...)
  - `?a` = tous les caractères imprimables
- Exemple : `?u?l?l?l?d?d?d` = "Abcd123"

### 4. Lancer l'attaque

Cliquez sur **Start Cracking**. La progression, vitesse et ETA s'affichent en temps réel.

## Exemples de commandes générées

```bash
# Dictionary attack
hashcat -m 17200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt

# Brute force avec custom charset "wk", longueur 6
hashcat -m 17200 -a 3 -1 wk ?1?1?1?1?1?1 hash.txt

# Brute force a-z, longueur 1-8 (increment)
hashcat -m 17200 -a 3 --increment --increment-min 1 --increment-max 8 ?l?l?l?l?l?l?l?l hash.txt

# Mask attack
hashcat -m 17200 -a 3 ?u?l?l?l?d?d?d hash.txt
```

## Structure du projet

```
simple-hashcat/
├── main.py                 # Point d'entrée
├── run.sh                  # Script de lancement
├── install.sh              # Installation automatique
├── requirements.txt        # Dépendances Python (PySide6)
├── core/
│   ├── cracker_base.py     # Classes abstraites et config
│   ├── john_backend.py     # Backend John the Ripper
│   ├── hashcat_backend.py  # Backend Hashcat
│   ├── hash_extractor.py   # Extraction de hash via *2john
│   └── john_jumbo_manager.py
├── gui/
│   └── main_window.py      # Interface graphique
└── resources/
    └── john-jumbo/         # John the Ripper (installé)
```

## Mise à jour de John the Ripper

Pour mettre à jour John Jumbo vers la dernière version :
```bash
rm -rf resources/john-jumbo
./install.sh
```

## Dépannage

### Hashcat "No devices found"
Installez les drivers OpenCL pour votre GPU, ou utilisez `pocl-opencl-icd` pour le CPU.

### Permission denied sur /dev/kvm
```bash
sudo chmod 666 /dev/kvm
```

### John ne trouve pas les scripts *2john
Vérifiez que `env/john_env.sh` est sourcé avant de lancer l'application.

## Licence

MIT
