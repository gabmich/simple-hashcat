"""
John the Ripper backend for password cracking.
"""

import subprocess
import tempfile
import os
import re
import signal
import threading
import time
import shlex
from typing import Optional
from pathlib import Path

from .cracker_base import (
    CrackerBackend, CrackConfig, CrackProgress, CrackStatus, AttackMode
)


class JohnBackend(CrackerBackend):
    """John the Ripper password cracking backend."""

    def __init__(self):
        super().__init__()
        self.john_path = self._find_john()
        self.temp_hash_file: Optional[str] = None
        self.session_name: Optional[str] = None
        self.pot_file: Optional[str] = None
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_monitoring = threading.Event()
        self._current_config: Optional[CrackConfig] = None
        self._found_password: Optional[str] = None

    def _find_john(self) -> Optional[str]:
        """Find John the Ripper executable."""
        paths = ["john", "/usr/bin/john", "/usr/sbin/john", "/usr/local/bin/john"]

        for path in paths:
            try:
                # Try common probes; some builds don't support --help/--version.
                probes = [
                    [path, "--help"],
                    [path, "--list=help"],
                    [path],
                ]
                for cmd in probes:
                    try:
                        result = subprocess.run(
                            cmd,
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                    except subprocess.TimeoutExpired:
                        continue

                    output = result.stdout + result.stderr
                    if (
                        result.returncode == 0
                        or "John the Ripper" in output
                        or "usage: john" in output.lower()
                    ):
                        return path
            except FileNotFoundError:
                continue

        return None

    def is_available(self) -> bool:
        """Check if John the Ripper is available."""
        return self.john_path is not None

    def get_version(self) -> Optional[str]:
        """Get John the Ripper version."""
        if not self.john_path:
            return None

        probes = [
            [self.john_path],  # prints banner with version
            [self.john_path, "--version"],
            [self.john_path, "--list=build-info"],
        ]

        for cmd in probes:
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                output = (result.stdout + result.stderr).strip()
                if not output or "Unknown option" in output:
                    continue

                # First non-empty line usually contains the version string.
                for line in output.splitlines():
                    if line.strip():
                        return line.strip()
            except Exception:
                continue

        return None

    def start_crack(self, config: CrackConfig) -> bool:
        """Start cracking with John the Ripper."""
        if not self.john_path:
            self.status = CrackStatus.FAILED
            return False

        self._current_config = config
        self._found_password = None
        self._stop_monitoring.clear()

        # Create temp file for hash
        with tempfile.NamedTemporaryFile(delete=False, suffix=".hash", mode="w") as tmp_hash:
            self.temp_hash_file = tmp_hash.name
            tmp_hash.write(config.hash_string)

        # Create session name and pot file
        self.session_name = f"simple_cracker_{os.getpid()}"
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pot") as tmp_pot:
            self.pot_file = tmp_pot.name

        # Build command
        cmd = [self.john_path]
        cmd.extend([f"--session={self.session_name}"])
        cmd.extend([f"--pot={self.pot_file}"])

        # Attack mode specific options
        if config.attack_mode == AttackMode.DICTIONARY:
            if config.wordlist_path and os.path.exists(config.wordlist_path):
                cmd.extend([f"--wordlist={config.wordlist_path}"])
            if config.rules_file:
                cmd.extend([f"--rules={config.rules_file}"])

        elif config.attack_mode == AttackMode.BRUTE_FORCE:
            cmd.append("--incremental")
            if config.charset:
                # Map charset to John's incremental modes
                charset_map = {
                    "?l": "Lower",
                    "?u": "Upper",
                    "?d": "Digits",
                    "?a": "All",
                }
                mode = charset_map.get(config.charset, "All")
                cmd[-1] = f"--incremental={mode}"

        elif config.attack_mode == AttackMode.MASK:
            if config.mask:
                cmd.extend([f"--mask={config.mask}"])

        elif config.attack_mode == AttackMode.RULES:
            if config.wordlist_path:
                cmd.extend([f"--wordlist={config.wordlist_path}"])
            cmd.extend(["--rules=All"])

        # Add hash file
        cmd.append(self.temp_hash_file)

        try:
            self.last_command = shlex.join(cmd)
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
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

    def _monitor_process(self):
        """Monitor the cracking process in background."""
        while not self._stop_monitoring.is_set():
            if self.process is None:
                break

            # Check if process is still running
            poll = self.process.poll()
            if poll is not None:
                # Process finished
                self._check_result()
                self.status = CrackStatus.COMPLETED
                self._notify_progress(self.get_progress())
                break

            # Check for cracked password periodically
            self._check_result()
            if self._found_password:
                self.status = CrackStatus.COMPLETED
                self._notify_progress(self.get_progress())
                self.stop_crack(mark_cancelled=False)
                break

            # Notify progress
            self._notify_progress(self.get_progress())
            time.sleep(1)

    def _check_result(self):
        """Check if password was found."""
        if self.pot_file and os.path.exists(self.pot_file):
            try:
                with open(self.pot_file, 'r') as f:
                    content = f.read().strip()
                    if content:
                        # Format is hash:password
                        parts = content.split(':')
                        if len(parts) >= 2:
                            self._found_password = ':'.join(parts[1:])
            except Exception:
                pass

        # Also try john --show
        if not self._found_password and self.temp_hash_file:
            try:
                result = subprocess.run(
                    [self.john_path, "--show", f"--pot={self.pot_file}", self.temp_hash_file],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.stdout:
                    # Parse output like: filename:password
                    for line in result.stdout.strip().split('\n'):
                        if ':' in line and 'password hash' not in line.lower():
                            parts = line.split(':')
                            if len(parts) >= 2:
                                self._found_password = parts[1]
                                break
            except Exception:
                pass

    def stop_crack(self, mark_cancelled: bool = True) -> bool:
        """Stop John the Ripper."""
        self._stop_monitoring.set()

        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            except Exception:
                pass

        if mark_cancelled and self.status != CrackStatus.COMPLETED:
            self.status = CrackStatus.CANCELLED
        self._cleanup()
        return True

    def pause_crack(self) -> bool:
        """Pause John the Ripper (send SIGTSTP)."""
        if self.process and self.status == CrackStatus.RUNNING:
            try:
                os.kill(self.process.pid, signal.SIGTSTP)
                self.status = CrackStatus.PAUSED
                return True
            except Exception:
                pass
        return False

    def resume_crack(self) -> bool:
        """Resume John the Ripper."""
        if self.process and self.status == CrackStatus.PAUSED:
            try:
                os.kill(self.process.pid, signal.SIGCONT)
                self.status = CrackStatus.RUNNING
                return True
            except Exception:
                pass
        return False

    def get_progress(self) -> CrackProgress:
        """Get current progress from John."""
        progress = CrackProgress(
            status=self.status,
            progress_percent=0.0,
            speed="N/A",
            estimated_time="N/A",
            candidates_tried=0,
            current_candidate="",
            password_found=self._found_password
        )

        if not self.john_path or not self.session_name:
            return progress

        # Try to get status from John
        try:
            result = subprocess.run(
                [self.john_path, f"--status={self.session_name}"],
                capture_output=True,
                text=True,
                timeout=5
            )

            output = result.stdout + result.stderr

            # Parse progress info
            # Example: "0g 0:00:00:01 3/3 0g/s 1234Kp/s"
            # Example: "0g 0:00:00:05 0.50% (ETA: 12:34:56) 0g/s 5000p/s"
            speed_match = re.search(r'(\d+\.?\d*[KMG]?p/s)', output)
            if speed_match:
                progress.speed = speed_match.group(1)

            # Parse percentage if available
            pct_match = re.search(r'(\d+\.?\d*)%', output)
            if pct_match:
                progress.progress_percent = float(pct_match.group(1))

            # Parse ETA
            eta_match = re.search(r'ETA:\s*([^\s]+)', output)
            if eta_match:
                progress.estimated_time = eta_match.group(1)

            # Parse candidates tried from "Xg" or "Xc" format, or estimate from speed and time
            # John outputs like "0g 0:00:00:05" where time is H:MM:SS:ss or similar
            # Try to estimate candidates from speed * time
            time_match = re.search(r'(\d+):(\d+):(\d+):(\d+)', output)
            if time_match and speed_match:
                try:
                    hours = int(time_match.group(1))
                    mins = int(time_match.group(2))
                    secs = int(time_match.group(3))
                    total_secs = hours * 3600 + mins * 60 + secs

                    speed_str = speed_match.group(1)
                    # Parse speed like "1234Kp/s" or "5.5Mp/s"
                    speed_val = float(re.search(r'[\d.]+', speed_str).group())
                    if 'K' in speed_str:
                        speed_val *= 1000
                    elif 'M' in speed_str:
                        speed_val *= 1000000
                    elif 'G' in speed_str:
                        speed_val *= 1000000000

                    progress.candidates_tried = int(speed_val * total_secs)
                except (ValueError, AttributeError):
                    pass

        except Exception:
            pass

        return progress

    def _cleanup(self):
        """Clean up temporary files."""
        for path in (self.temp_hash_file, self.pot_file):
            if path and os.path.exists(path):
                try:
                    os.remove(path)
                except Exception:
                    pass

        self.process = None

    def restore_session(self, session_name: str) -> bool:
        """Restore a previous John session."""
        if not self.john_path:
            return False

        try:
            self.process = subprocess.Popen(
                [self.john_path, f"--restore={session_name}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            self.status = CrackStatus.RUNNING
            self.session_name = session_name
            return True
        except Exception:
            return False

    def list_formats(self) -> list:
        """List supported hash formats."""
        if not self.john_path:
            return []

        try:
            result = subprocess.run(
                [self.john_path, "--list=formats"],
                capture_output=True,
                text=True,
                timeout=10
            )
            formats = result.stdout.strip().replace('\n', ', ').split(', ')
            return [f.strip() for f in formats if f.strip()]
        except Exception:
            return []
