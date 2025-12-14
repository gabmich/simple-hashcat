"""
Base class for password cracking backends.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Callable, List
import os


class AttackMode(Enum):
    DICTIONARY = "dictionary"
    BRUTE_FORCE = "brute_force"
    RULES = "rules"
    MASK = "mask"
    HYBRID = "hybrid"


class CrackStatus(Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class CrackProgress:
    status: CrackStatus
    progress_percent: float
    speed: str
    estimated_time: str
    candidates_tried: int
    current_candidate: str
    password_found: Optional[str] = None
    error_message: Optional[str] = None


@dataclass
class CrackConfig:
    hash_string: str
    hash_type: Optional[str] = None
    attack_mode: AttackMode = AttackMode.DICTIONARY
    wordlist_path: Optional[str] = None
    rules_file: Optional[str] = None
    mask: Optional[str] = None
    min_length: int = 1
    max_length: int = 8
    charset: str = "?a"  # For brute force: ?l=lower, ?u=upper, ?d=digit, ?s=special, ?a=all
    increment: bool = False


class CrackerBackend(ABC):
    """Abstract base class for password cracking backends."""

    def __init__(self):
        self.status = CrackStatus.IDLE
        self.progress_callback: Optional[Callable[[CrackProgress], None]] = None
        self.process = None

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the cracking tool is available on the system."""
        pass

    @abstractmethod
    def get_version(self) -> Optional[str]:
        """Get the version of the cracking tool."""
        pass

    @abstractmethod
    def start_crack(self, config: CrackConfig) -> bool:
        """Start the cracking process."""
        pass

    @abstractmethod
    def stop_crack(self) -> bool:
        """Stop the cracking process."""
        pass

    @abstractmethod
    def pause_crack(self) -> bool:
        """Pause the cracking process."""
        pass

    @abstractmethod
    def resume_crack(self) -> bool:
        """Resume the cracking process."""
        pass

    @abstractmethod
    def get_progress(self) -> CrackProgress:
        """Get current progress."""
        pass

    def set_progress_callback(self, callback: Callable[[CrackProgress], None]):
        """Set callback for progress updates."""
        self.progress_callback = callback

    def _notify_progress(self, progress: CrackProgress):
        """Notify progress via callback."""
        if self.progress_callback:
            self.progress_callback(progress)

    @staticmethod
    def find_wordlists() -> List[str]:
        """Find common wordlist locations."""
        wordlists = []
        common_paths = [
            "/usr/share/wordlists",
            "/usr/share/john/password.lst",
            "/usr/share/dict/words",
            "/usr/share/seclists",
            os.path.expanduser("~/wordlists"),
            os.path.expanduser("~/.local/share/wordlists"),
        ]

        for path in common_paths:
            if os.path.exists(path):
                if os.path.isfile(path):
                    wordlists.append(path)
                elif os.path.isdir(path):
                    for root, dirs, files in os.walk(path):
                        for f in files:
                            if f.endswith(('.txt', '.lst', '.dic')):
                                wordlists.append(os.path.join(root, f))

        return wordlists[:50]  # Limit to 50 wordlists
