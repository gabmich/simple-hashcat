"""
Hash extraction module for various file formats.
Uses john-jumbo's *2john utilities for reliable hash extraction.
"""

import os
from pathlib import Path
from typing import Optional
from dataclasses import dataclass
from enum import Enum

from .john_jumbo_manager import get_manager, JohnJumboManager
import zipfile


class FileType(Enum):
    ZIP = "zip"
    SEVEN_ZIP = "7z"
    RAR = "rar"
    PDF = "pdf"
    OFFICE_OLD = "office_old"  # .doc, .xls, .ppt (Office 97-2003)
    OFFICE_NEW = "office_new"  # .docx, .xlsx, .pptx (Office 2007+)
    ODF = "odf"  # OpenDocument (odt/ods/odp)
    KEEPASS = "keepass"
    SSH_KEY = "ssh_key"
    GPG = "gpg"
    BITLOCKER = "bitlocker"
    TRUECRYPT = "truecrypt"
    LUKS = "luks"
    UNKNOWN = "unknown"


@dataclass
class HashResult:
    success: bool
    hash_string: Optional[str]
    file_type: FileType
    hash_type: Optional[str]  # For hashcat mode
    command_line: Optional[str] = None
    error_message: Optional[str] = None


class HashExtractor:
    """Extracts password hashes from various encrypted file formats using john-jumbo."""

    # Mapping of file extensions to FileType
    EXTENSION_MAP = {
        '.zip': FileType.ZIP,
        '.7z': FileType.SEVEN_ZIP,
        '.rar': FileType.RAR,
        '.pdf': FileType.PDF,
        '.doc': FileType.OFFICE_OLD,
        '.xls': FileType.OFFICE_OLD,
        '.ppt': FileType.OFFICE_OLD,
        '.docx': FileType.OFFICE_NEW,
        '.xlsx': FileType.OFFICE_NEW,
        '.pptx': FileType.OFFICE_NEW,
        '.odt': FileType.ODF,
        '.ods': FileType.ODF,
        '.odp': FileType.ODF,
        '.kdbx': FileType.KEEPASS,
        '.kdb': FileType.KEEPASS,
        '.gpg': FileType.GPG,
        '.pgp': FileType.GPG,
        '.bek': FileType.BITLOCKER,
        '.tc': FileType.TRUECRYPT,
    }

    # Mapping of FileType to john-jumbo script name
    SCRIPT_MAP = {
        FileType.ZIP: "zip2john",
        FileType.SEVEN_ZIP: "7z2john.pl",
        FileType.RAR: "rar2john",
        FileType.PDF: "pdf2john.pl",
        FileType.OFFICE_OLD: "office2john.py",
        FileType.OFFICE_NEW: "office2john.py",
        FileType.ODF: "libreoffice2john.py",
        FileType.KEEPASS: "keepass2john",
        FileType.SSH_KEY: "ssh2john.py",
        FileType.GPG: "gpg2john.py",
        FileType.BITLOCKER: "bitlocker2john.py",
        FileType.TRUECRYPT: "truecrypt2john.py",
        FileType.LUKS: "luks2john.py",
    }

    # Hashcat mode mapping
    HASHCAT_MODES = {
        FileType.ZIP: "17200",  # PKZIP (Compressed)
        FileType.SEVEN_ZIP: "11600",
        FileType.RAR: "13000",  # RAR3-hp or 23700 for RAR5
        FileType.PDF: "10500",  # PDF 1.4-1.6
        FileType.OFFICE_OLD: "9700",  # MS Office <= 2003
        FileType.OFFICE_NEW: "9600",  # MS Office 2013
        FileType.ODF: "18400",  # OpenDocument Format (SHA-256, AES)
        FileType.KEEPASS: "13400",
        FileType.SSH_KEY: "22911",
        FileType.GPG: "17010",
        FileType.BITLOCKER: "22100",
        FileType.TRUECRYPT: "6211",
    }

    def __init__(self):
        self.john_manager = get_manager()

    def is_ready(self) -> bool:
        """Check if john-jumbo is installed and ready."""
        return self.john_manager.is_installed()

    def detect_file_type(self, file_path: str) -> FileType:
        """Detect the file type based on extension and magic bytes."""
        path = Path(file_path)
        ext = path.suffix.lower()

        if ext in self.EXTENSION_MAP:
            return self.EXTENSION_MAP[ext]

        # Check for SSH keys by content
        try:
            with open(file_path, 'rb') as f:
                header = f.read(100)
                if b'OPENSSH PRIVATE KEY' in header or b'RSA PRIVATE KEY' in header:
                    return FileType.SSH_KEY
                if b'PuTTY-User-Key-File' in header:
                    return FileType.SSH_KEY
        except Exception:
            pass

        # Check for LUKS
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(6)
                if magic == b'LUKS\xba\xbe':
                    return FileType.LUKS
        except Exception:
            pass

        return FileType.UNKNOWN

    def extract_hash(self, file_path: str) -> HashResult:
        """Extract hash from the given file."""
        if not os.path.exists(file_path):
            return HashResult(
                success=False,
                hash_string=None,
                file_type=FileType.UNKNOWN,
                hash_type=None,
                error_message=f"File not found: {file_path}"
            )

        if not self.is_ready():
            return HashResult(
                success=False,
                hash_string=None,
                file_type=FileType.UNKNOWN,
                hash_type=None,
                error_message=(
                    "john-jumbo not installed. Point JOHN_JUMBO_RUN_PATH to your john/run directory "
                    "or place john sources under project root (e.g. john-1.9.0-jumbo-1/run)."
                )
            )

        file_type = self.detect_file_type(file_path)

        if file_type == FileType.UNKNOWN:
            return HashResult(
                success=False,
                hash_string=None,
                file_type=file_type,
                hash_type=None,
                error_message="Unknown or unsupported file type"
            )

        # Get the appropriate script
        script_name = self.SCRIPT_MAP.get(file_type)
        if not script_name:
            return HashResult(
                success=False,
                hash_string=None,
                file_type=file_type,
                hash_type=None,
                error_message=f"No extraction script for {file_type.value}"
            )

        # Early check: common case of Office/ZIP containers that are not encrypted
        if file_type in (FileType.OFFICE_NEW, FileType.ZIP, FileType.SEVEN_ZIP, FileType.RAR, FileType.ODF):
            encrypted = self._is_encrypted_container(file_path, file_type)
            if encrypted is False:
                return HashResult(
                    success=False,
                    hash_string=None,
                    file_type=file_type,
                    hash_type=None,
                error_message="Le fichier ne semble pas protege par mot de passe (conteneur non chiffre)."
            )

        script_path = self.john_manager.get_script_path(script_name)
        if not script_path:
            return HashResult(
                success=False,
                hash_string=None,
                file_type=file_type,
                hash_type=None,
                error_message=(
                    f"Required script '{script_name}' not found in john run directory "
                    f"({self.john_manager.run_dir}). Make sure john is built and scripts are present."
                )
            )

        # Run the script
        success, output, command_line = self.john_manager.run_script(script_name, file_path)

        if success:
            # Detect specific hash type for hashcat
            hash_type = self._detect_hashcat_mode(file_type, output)

            return HashResult(
                success=True,
                hash_string=output,
                file_type=file_type,
                hash_type=hash_type,
                command_line=command_line
            )
        else:
            return HashResult(
                success=False,
                hash_string=None,
                file_type=file_type,
                hash_type=None,
                command_line=command_line,
                error_message=output
            )

    def _detect_hashcat_mode(self, file_type: FileType, hash_output: str) -> str:
        """Detect the specific hashcat mode from hash output."""
        base_mode = self.HASHCAT_MODES.get(file_type, "0")

        # Refine based on hash content
        if file_type == FileType.RAR:
            if "$RAR5$" in hash_output:
                return "23700"
            elif "$RAR3$" in hash_output:
                return "12500"

        elif file_type == FileType.PDF:
            if "$pdf$5" in hash_output:
                return "10600"  # PDF 1.7 Level 3
            elif "$pdf$4" in hash_output or "$pdf$2" in hash_output:
                return "10400"  # PDF 1.1-1.3

        elif file_type == FileType.ODF:
            # LibreOffice hashes typically map to 18400 already; keep override hook here
            if "$odf$*" in hash_output:
                return "18400"

        elif file_type in [FileType.OFFICE_OLD, FileType.OFFICE_NEW]:
            if "$office$*2007" in hash_output:
                return "9400"
            elif "$office$*2010" in hash_output:
                return "9500"
            elif "$office$*2013" in hash_output or "$office$*2016" in hash_output:
                return "9600"
            elif "$oldoffice$" in hash_output:
                return "9700"

        elif file_type == FileType.ZIP:
            if "$pkzip2$" in hash_output:
                return "17200"
            elif "$zip2$" in hash_output:
                return "13600"

        return base_mode

    def get_supported_formats(self) -> list:
        """Return list of supported file formats."""
        return [
            ("ZIP archives", "*.zip"),
            ("7-Zip archives", "*.7z"),
            ("RAR archives", "*.rar"),
            ("PDF documents", "*.pdf"),
            ("Word documents", "*.doc *.docx"),
            ("Excel spreadsheets", "*.xls *.xlsx"),
            ("PowerPoint presentations", "*.ppt *.pptx"),
            ("OpenDocument files", "*.odt *.ods *.odp"),
            ("KeePass databases", "*.kdbx *.kdb"),
            ("SSH private keys", "*"),
            ("GPG encrypted files", "*.gpg *.pgp"),
            ("BitLocker volumes", "*.bek"),
            ("TrueCrypt volumes", "*.tc"),
            ("All files", "*"),
        ]

    def _is_encrypted_container(self, file_path: str, file_type: FileType) -> Optional[bool]:
        """
        Best-effort check to see if the file is encrypted.
        Returns True if encrypted, False if clearly not, None if unknown.
        """
        if file_type in (FileType.OFFICE_NEW, FileType.ZIP):
            try:
                with zipfile.ZipFile(file_path, 'r') as zf:
                    names = {n.lower() for n in zf.namelist()}
                    # Modern Office encryption stores EncryptionInfo + EncryptedPackage
                    if "encryptioninfo" in names or "encryptedpackage" in names:
                        return True
                    # PKZIP flag bit 0 indicates no encryption
                    for info in zf.infolist():
                        if info.flag_bits & 0x1:
                            return True
                    return False
            except zipfile.BadZipFile:
                return None
        if file_type == FileType.ODF:
            try:
                with zipfile.ZipFile(file_path, "r") as zf:
                    try:
                        manifest = zf.read("META-INF/manifest.xml").decode("utf-8", errors="ignore")
                    except KeyError:
                        return None
                    if "encryption-data" in manifest:
                        return True
                    return False
            except zipfile.BadZipFile:
                return None
        return None
