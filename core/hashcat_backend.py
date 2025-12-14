"""
Hashcat backend for password cracking.
"""

import subprocess
import os
import re
import threading
import time
import shlex
from typing import Optional
from pathlib import Path
from tempfile import NamedTemporaryFile
import select
import copy

from .cracker_base import (
    CrackerBackend, CrackConfig, CrackProgress, CrackStatus, AttackMode
)


class HashcatBackend(CrackerBackend):
    """Hashcat password cracking backend."""

    # Hashcat attack modes
    ATTACK_MODES = {
        AttackMode.DICTIONARY: 0,
        AttackMode.BRUTE_FORCE: 3,
        AttackMode.RULES: 0,  # Dictionary with rules
        AttackMode.MASK: 3,
        AttackMode.HYBRID: 6,  # Wordlist + Mask
    }

    def __init__(self):
        super().__init__()
        self.hashcat_path = self._find_hashcat()
        self.temp_hash_file: Optional[str] = None
        self.session_name: Optional[str] = None
        self.outfile: Optional[str] = None
        self.potfile: Optional[str] = None
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_monitoring = threading.Event()
        self._current_config: Optional[CrackConfig] = None
        self._found_password: Optional[str] = None
        self._last_status: dict = {}
        self._error_lines: list[str] = []
        self._data_dir = Path(__file__).resolve().parent.parent / ".hashcat_data"
        self._last_error: Optional[str] = None
        self._data_dir.mkdir(parents=True, exist_ok=True)
        (self._data_dir / "cache").mkdir(parents=True, exist_ok=True)

    def _find_hashcat(self) -> Optional[str]:
        """Find Hashcat executable."""
        paths = ["hashcat", "/usr/bin/hashcat", "/usr/local/bin/hashcat", "hashcat64.bin"]

        for path in paths:
            try:
                result = subprocess.run(
                    [path, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    return path
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue

        return None

    def is_available(self) -> bool:
        """Check if Hashcat is available."""
        return self.hashcat_path is not None

    def get_version(self) -> Optional[str]:
        """Get Hashcat version."""
        if not self.hashcat_path:
            return None

        try:
            result = subprocess.run(
                [self.hashcat_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout.strip()
        except Exception:
            return None

    def start_crack(self, config: CrackConfig) -> bool:
        """Start cracking with Hashcat."""
        if not self.hashcat_path:
            self.status = CrackStatus.FAILED
            return False

        self._current_config = config
        self._found_password = None
        self._stop_monitoring.clear()
        self._last_status = {}
        self._last_error = None
        self._error_lines = []

        # Create temp file for hash
        with NamedTemporaryFile(delete=False, suffix=".hash", mode="w") as tmp_hash:
            self.temp_hash_file = tmp_hash.name

        # Clean hash string (remove filename prefix if present)
        hash_string = self._sanitize_hash(config.hash_string)

        with open(self.temp_hash_file, 'w') as f:
            f.write(hash_string)

        # Create session and output files
        self.session_name = f"simple_cracker_{os.getpid()}"
        with NamedTemporaryFile(delete=False, suffix=".out") as tmp_out:
            self.outfile = tmp_out.name
        with NamedTemporaryFile(delete=False, suffix=".pot") as tmp_pot:
            self.potfile = tmp_pot.name

        # Build command
        cmd = [self.hashcat_path]

        # Hash type (mode)
        if config.hash_type:
            cmd.extend(["-m", config.hash_type])

        # Attack mode
        attack_mode = self.ATTACK_MODES.get(config.attack_mode, 0)
        cmd.extend(["-a", str(attack_mode)])

        # Session and output
        cmd.extend(["--session", self.session_name])
        cmd.extend(["-o", self.outfile])
        cmd.extend(["--potfile-path", self.potfile])

        # Status and machine readable output
        cmd.extend(["--status", "--status-timer=1"])
        cmd.append("--machine-readable")
        cmd.append("--quiet")

        # Force CPU if no GPU (fallback)
        cmd.append("--force")

        # Optimizations
        cmd.extend(["-O"])  # Optimized kernels

        # Add hash file
        cmd.append(self.temp_hash_file)

        # Attack mode specific options
        if config.attack_mode == AttackMode.DICTIONARY:
            if config.wordlist_path and os.path.exists(config.wordlist_path):
                cmd.append(config.wordlist_path)
            else:
                # No wordlist specified
                self.status = CrackStatus.FAILED
                return False

            if config.rules_file:
                cmd.extend(["-r", config.rules_file])

        elif config.attack_mode == AttackMode.BRUTE_FORCE or config.attack_mode == AttackMode.MASK:
            # Build mask
            mask = config.mask if config.mask else self._build_mask(config)
            cmd.append(mask)

            if config.increment:
                cmd.append("--increment")
                cmd.extend(["--increment-min", str(config.min_length)])
                cmd.extend(["--increment-max", str(config.max_length)])

        elif config.attack_mode == AttackMode.RULES:
            if config.wordlist_path:
                cmd.append(config.wordlist_path)
            cmd.extend(["-r", config.rules_file or "/usr/share/hashcat/rules/best64.rule"])

        elif config.attack_mode == AttackMode.HYBRID:
            if config.wordlist_path:
                cmd.append(config.wordlist_path)
            mask = config.mask if config.mask else "?d?d?d"
            cmd.append(mask)

        try:
            self.last_command = shlex.join(cmd)
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=self._build_env()
            )
            self.status = CrackStatus.RUNNING

            # Start monitoring thread
            self._monitor_thread = threading.Thread(target=self._monitor_process)
            self._monitor_thread.daemon = True
            self._monitor_thread.start()

            return True

        except Exception as e:
            self.status = CrackStatus.FAILED
            self._cleanup()
            return False

    def _build_mask(self, config: CrackConfig) -> str:
        """Build a hashcat mask from config."""
        # Map our charset to hashcat
        charset_map = {
            "?l": "?l",  # lowercase
            "?u": "?u",  # uppercase
            "?d": "?d",  # digits
            "?s": "?s",  # special
            "?a": "?a",  # all printable
        }

        char = charset_map.get(config.charset, "?a")
        return char * config.max_length

    def _sanitize_hash(self, hash_string: str) -> str:
        """
        Normalize *2john output for hashcat.

        Many *2john scripts emit "filename:HASH:::::filepath" which hashcat rejects.
        Keep only the hash part after the first colon and drop trailing metadata.
        """
        cleaned = hash_string.strip()

        # If it already starts with a $type$, leave leading part intact.
        if cleaned.startswith('$'):
            return cleaned

        # Drop leading filename/label before the first colon.
        if ':' in cleaned:
            _, cleaned = cleaned.split(':', 1)

        # Remove trailing metadata separators (:::::something)
        if ':::::' in cleaned:
            cleaned = cleaned.split(':::::', 1)[0]

        return cleaned.strip()

    def _monitor_process(self):
        """Monitor the cracking process in background."""
        while not self._stop_monitoring.is_set():
            if self.process is None:
                break

            # Read any available status output (stdout or stderr)
            try:
                streams = [s for s in (self.process.stdout, self.process.stderr) if s]
                if streams:
                    ready, _, _ = select.select(streams, [], [], 0.1)
                    for stream in ready:
                        line = stream.readline()
                        if line:
                            if stream is self.process.stderr:
                                self._error_lines.append(line.strip())
                            self._parse_status_line(line.strip())
            except Exception:
                pass

            # Check if process is still running
            poll = self.process.poll()
            if poll is not None:
                try:
                    out, err = self.process.communicate(timeout=0.5)
                    if err:
                        self._error_lines.append(err.strip())
                except Exception:
                    pass
                # Process finished
                self._check_result()
                if poll != 0 and not self._found_password:
                    self.status = CrackStatus.FAILED
                    if self._error_lines:
                        self._last_error = "\n".join(
                            [l for l in self._error_lines if l.strip()]
                        )
                else:
                    self.status = CrackStatus.COMPLETED
                    self._last_status.setdefault('progress', 100.0)
                self._notify_progress(self.get_progress())
                break

            # Check for cracked password
            self._check_result()
            if self._found_password:
                self.status = CrackStatus.COMPLETED
                self._notify_progress(self.get_progress())
                break

            # Notify progress
            self._notify_progress(self.get_progress())
            time.sleep(0.5)

    def _parse_status_line(self, line: str):
        """Parse hashcat status output."""
        # Machine readable format: STATUS\t...\tvalue
        if line.startswith("STATUS"):
            parts = line.split('\t')
            for i, part in enumerate(parts):
                if part == "PROGRESS" and i + 1 < len(parts):
                    try:
                        progress_parts = parts[i + 1].split('/')
                        if len(progress_parts) >= 2:
                            done = int(progress_parts[0])
                            total = int(progress_parts[1])
                            if total > 0:
                                self._last_status['progress'] = (done / total) * 100
                    except ValueError:
                        pass
                elif part == "SPEED" and i + 1 < len(parts):
                    self._last_status['speed'] = parts[i + 1]
                elif part in ("ETA", "TIME_EST", "TIME.REMAINING") and i + 1 < len(parts):
                    self._last_status['eta'] = parts[i + 1]
                elif part == "EXEC_RUNTIME" and i + 1 < len(parts):
                    self._last_status['runtime'] = parts[i + 1]

    def _check_result(self):
        """Check if password was found in output file."""
        if self.outfile and os.path.exists(self.outfile):
            try:
                with open(self.outfile, 'r') as f:
                    content = f.read().strip()
                    if content:
                        # Format is hash:password
                        for line in content.split('\n'):
                            if ':' in line:
                                parts = line.rsplit(':', 1)
                                if len(parts) == 2:
                                    self._found_password = parts[1]
                                    return
            except Exception:
                pass

    def stop_crack(self) -> bool:
        """Stop Hashcat."""
        self._stop_monitoring.set()

        if self.process:
            try:
                # Send quit command via stdin if possible
                self.process.terminate()
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            except Exception:
                pass

        self.status = CrackStatus.CANCELLED
        self._cleanup()
        return True

    def pause_crack(self) -> bool:
        """Pause Hashcat (checkpoint and stop)."""
        if self.process and self.status == CrackStatus.RUNNING:
            try:
                # Hashcat uses 'p' key for pause, but in non-interactive mode
                # we need to use checkpoint
                subprocess.run(
                    [self.hashcat_path, "--session", self.session_name, "--checkpoint-disable=0"],
                    capture_output=True,
                    timeout=5
                )
                self.process.terminate()
                self.status = CrackStatus.PAUSED
                return True
            except Exception:
                pass
        return False

    def resume_crack(self) -> bool:
        """Resume Hashcat from checkpoint."""
        if self.status == CrackStatus.PAUSED and self.session_name:
            try:
                self.process = subprocess.Popen(
                    [self.hashcat_path, "--session", self.session_name, "--restore"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                self.status = CrackStatus.RUNNING

                # Restart monitoring
                self._stop_monitoring.clear()
                self._monitor_thread = threading.Thread(target=self._monitor_process)
                self._monitor_thread.daemon = True
                self._monitor_thread.start()

                return True
            except Exception:
                pass
        return False

    def get_progress(self) -> CrackProgress:
        """Get current progress from Hashcat."""
        pct = self._last_status.get('progress', 0.0)
        if self.status == CrackStatus.COMPLETED and pct < 100.0:
            pct = 100.0

        progress = CrackProgress(
            status=self.status,
            progress_percent=pct,
            speed=self._last_status.get('speed', 'N/A'),
            estimated_time=self._last_status.get('eta', 'N/A'),
            candidates_tried=0,
            current_candidate="",
            password_found=self._found_password,
            error_message=self._last_error
        )

        return progress

    def _cleanup(self):
        """Clean up temporary files."""
        for f in [self.temp_hash_file]:
            if f and os.path.exists(f):
                try:
                    os.remove(f)
                except Exception:
                    pass
        for f in [self.outfile, self.potfile]:
            if f and os.path.exists(f):
                try:
                    os.remove(f)
                except Exception:
                    pass

        self.process = None

    def _build_env(self):
        """Build a safe environment for hashcat (sessions/potfile in workspace)."""
        env = copy.deepcopy(os.environ)
        env["XDG_DATA_HOME"] = str(self._data_dir)
        env["HOME"] = str(self._data_dir)  # Some builds look at HOME for session files
        env["XDG_CACHE_HOME"] = str(self._data_dir / "cache")
        return env

    def benchmark(self, hash_type: str) -> Optional[str]:
        """Run benchmark for a specific hash type."""
        if not self.hashcat_path:
            return None

        try:
            result = subprocess.run(
                [self.hashcat_path, "-b", "-m", hash_type],
                capture_output=True,
                text=True,
                timeout=120
            )
            return result.stdout
        except Exception:
            return None

    def list_hash_types(self) -> list:
        """List supported hash types."""
        if not self.hashcat_path:
            return []

        try:
            result = subprocess.run(
                [self.hashcat_path, "--help"],
                capture_output=True,
                text=True,
                timeout=10
            )

            # Parse hash modes from help
            modes = []
            in_modes = False
            for line in result.stdout.split('\n'):
                if 'Hash modes' in line or '- [ Hash Mode' in line:
                    in_modes = True
                    continue
                if in_modes:
                    match = re.match(r'\s*(\d+)\s*\|\s*(.+)', line)
                    if match:
                        modes.append((match.group(1), match.group(2).strip()))

            return modes[:100]  # Limit output
        except Exception:
            return []

    def get_rules_files(self) -> list:
        """Find available rules files."""
        rules = []
        rules_dirs = [
            "/usr/share/hashcat/rules",
            "/usr/local/share/hashcat/rules",
            os.path.expanduser("~/.hashcat/rules"),
        ]

        for rules_dir in rules_dirs:
            if os.path.exists(rules_dir):
                for f in os.listdir(rules_dir):
                    if f.endswith('.rule'):
                        rules.append(os.path.join(rules_dir, f))

        return rules
