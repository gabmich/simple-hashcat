"""
John Jumbo resource manager.
Downloads and manages john-jumbo scripts for hash extraction.
"""

import os
import subprocess
import tarfile
import zipfile
import shutil
import stat
from pathlib import Path
from typing import Optional, Callable, List
import urllib.request
import ssl


# John Jumbo GitHub release info
JOHN_JUMBO_REPO = "openwall/john"
JOHN_JUMBO_BRANCH = "bleeding-jumbo"
JOHN_JUMBO_ARCHIVE_URL = f"https://github.com/{JOHN_JUMBO_REPO}/archive/refs/heads/{JOHN_JUMBO_BRANCH}.zip"

# Scripts we need from john-jumbo
REQUIRED_SCRIPTS = [
    "7z2john.pl",
    "zip2john",  # This is compiled, we'll use the .py version
    "rar2john",
    "pdf2john.pl",
    "office2john.py",
    "keepass2john.py",
    "ssh2john.py",
    "gpg2john.py",
    "bitlocker2john.py",
    "dmg2john.py",
    "ethereum2john.py",
    "filezilla2john.py",
    "keepass2john.py",
    "kwallet2john.py",
    "lastpass2john.py",
    "libreoffice2john.py",
    "mozilla2john.py",
    "multibit2john.py",
    "pem2john.py",
    "pfx2john.py",
    "putty2john.py",
    "signal2john.py",
    "telegram2john.py",
    "tezos2john.py",
    "truecrypt2john.py",
    "vdi2john.py",
    "vmx2john.py",
    "winhello2john.py",
]


class JohnJumboManager:
    """Manages john-jumbo resources for hash extraction."""

    def __init__(self, base_dir: Optional[str] = None, run_dir: Optional[str] = None):
        # Default to resources/ in the project directory
        default_base = Path(__file__).resolve().parent.parent / "resources"
        self.base_dir = Path(base_dir) if base_dir else default_base
        self.john_dir = self.base_dir / "john-jumbo"
        self.run_dir = Path(run_dir) if run_dir else self.john_dir / f"john-{JOHN_JUMBO_BRANCH}" / "run"

        # Try to find an existing john source tree before attempting downloads.
        self._bootstrap_run_dir()

    def _bootstrap_run_dir(self):
        """Auto-detect an existing john-jumbo run directory."""
        env_run = os.environ.get("JOHN_JUMBO_RUN_PATH")
        project_root = Path(__file__).resolve().parent.parent

        candidates: List[Path] = []
        if env_run:
            candidates.append(Path(env_run))

        # Common local source layout (user downloaded sources)
        candidates.append(project_root / "john-1.9.0-jumbo-1" / "run")
        candidates.append(project_root / "john-1.9.0-jumbo-1" / "john-bleeding-jumbo" / "run")
        candidates.append(project_root / "john" / "run")

        # Existing default download location
        candidates.append(self.run_dir)

        for candidate in candidates:
            if not candidate:
                continue
            if candidate.exists() and (candidate / "7z2john.pl").exists():
                self.run_dir = candidate
                self.john_dir = candidate.parent
                return

    def is_installed(self) -> bool:
        """Check if john-jumbo is installed."""
        if not self.run_dir or not self.run_dir.exists():
            return False

        # Check for at least one key script
        return (self.run_dir / "7z2john.pl").exists()

    def get_script_path(self, script_name: str) -> Optional[str]:
        """Get full path to a john script."""
        if not self.run_dir:
            return None

        # Try exact name
        script_path = self.run_dir / script_name
        if script_path.exists():
            return str(script_path)

        # Try with .pl extension
        script_path = self.run_dir / f"{script_name}.pl"
        if script_path.exists():
            return str(script_path)

        # Try with .py extension
        script_path = self.run_dir / f"{script_name}.py"
        if script_path.exists():
            return str(script_path)

        return None

    def download(self, progress_callback: Optional[Callable[[int, int], None]] = None) -> bool:
        """
        Download and extract john-jumbo.

        Args:
            progress_callback: Optional callback(downloaded_bytes, total_bytes)

        Returns:
            True if successful
        """
        try:
            # Create directories
            self.base_dir.mkdir(parents=True, exist_ok=True)

            # Download archive
            archive_path = self.base_dir / "john-jumbo.zip"

            # Create SSL context that doesn't verify (for systems with cert issues)
            ssl_context = ssl.create_default_context()

            # Download with progress
            req = urllib.request.Request(
                JOHN_JUMBO_ARCHIVE_URL,
                headers={'User-Agent': 'Mozilla/5.0'}
            )

            with urllib.request.urlopen(req, context=ssl_context) as response:
                total_size = int(response.headers.get('Content-Length', 0))
                downloaded = 0
                chunk_size = 8192

                with open(archive_path, 'wb') as f:
                    while True:
                        chunk = response.read(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded += len(chunk)

                        if progress_callback:
                            progress_callback(downloaded, total_size)

            # Extract archive
            if self.john_dir.exists():
                shutil.rmtree(self.john_dir)

            self.john_dir.mkdir(parents=True, exist_ok=True)

            with zipfile.ZipFile(archive_path, 'r') as zf:
                zf.extractall(self.john_dir)

            # Make scripts executable
            self._make_scripts_executable()

            # Clean up archive
            archive_path.unlink()

            return True

        except Exception as e:
            print(f"Error downloading john-jumbo: {e}")
            return False

    def _make_scripts_executable(self):
        """Make all scripts in run directory executable."""
        if not self.run_dir.exists():
            return

        for script in self.run_dir.iterdir():
            if script.suffix in ['.pl', '.py', '.rb'] or script.name.endswith('2john'):
                try:
                    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                except Exception:
                    pass

    def run_script(self, script_name: str, file_path: str) -> tuple[bool, str, Optional[str]]:
        """
        Run a john script on a file.

        Args:
            script_name: Name of the script (e.g., "7z2john")
            file_path: Path to the file to process

        Returns:
            (success, output_or_error, command_line)
        """
        if not self.is_installed():
            return False, "john-jumbo not installed. Set JOHN_JUMBO_RUN_PATH to your run/ directory.", None

        script_path = self.get_script_path(script_name)
        if not script_path:
            return False, f"Script {script_name} not found in {self.run_dir}", None

        # Determine interpreter
        if script_path.endswith('.pl'):
            cmd = ['perl', script_path, file_path]
        elif script_path.endswith('.py'):
            cmd = ['python3', script_path, file_path]
        elif script_path.endswith('.rb'):
            cmd = ['ruby', script_path, file_path]
        else:
            cmd = [script_path, file_path]

        command_line = " ".join(cmd)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(self.run_dir)
            )

            output = result.stdout.strip()
            if output:
                return True, output, command_line

            if result.stderr:
                # Some scripts print tracebacks when file is not actually encrypted
                if "UnboundLocalError" in result.stderr and "libreoffice2john" in script_name:
                    return False, "Le fichier ODF ne semble pas chiffré ou est invalide.", command_line
                return False, result.stderr.strip(), command_line

            return False, "No output from script", command_line

        except subprocess.TimeoutExpired:
            return False, "Script timed out", command_line
        except FileNotFoundError as e:
            return False, f"Interpreter not found: {e}", command_line
        except Exception as e:
            return False, str(e), command_line

    def get_available_scripts(self) -> list[str]:
        """Get list of available *2john scripts."""
        if not self.run_dir or not self.run_dir.exists():
            return []

        scripts = []
        for script in self.run_dir.iterdir():
            if '2john' in script.name:
                scripts.append(script.name)

        return sorted(scripts)

    def get_disk_usage(self) -> int:
        """Get disk usage of john-jumbo in bytes."""
        if not self.john_dir or not self.john_dir.exists():
            return 0

        total = 0
        for path in self.john_dir.rglob('*'):
            if path.is_file():
                total += path.stat().st_size

        return total

    def uninstall(self) -> bool:
        """Remove john-jumbo installation."""
        try:
            # Avoid deleting user-supplied trees; only clean our download location
            default_root = Path(__file__).resolve().parent.parent / "resources"
            if self.john_dir.exists() and self.base_dir == default_root:
                shutil.rmtree(self.john_dir)
            return True
        except Exception:
            return False


# Global instance
_manager: Optional[JohnJumboManager] = None


def get_manager() -> JohnJumboManager:
    """Get the global JohnJumboManager instance."""
    global _manager
    if _manager is None:
        _manager = JohnJumboManager()
    return _manager
