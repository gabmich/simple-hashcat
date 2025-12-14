"""
Main window for the password cracker GUI.
"""

import os
from typing import Optional
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QGroupBox, QLabel, QPushButton, QLineEdit, QComboBox,
    QTextEdit, QProgressBar, QFileDialog, QSpinBox, QCheckBox,
    QRadioButton, QButtonGroup, QMessageBox, QSplitter, QFrame,
    QStatusBar, QToolBar, QSizePolicy
)
from PySide6.QtCore import Qt, QThread, Signal, Slot, QTimer
from PySide6.QtGui import QAction, QFont, QIcon

from core.hash_extractor import HashExtractor, HashResult, FileType
from core.cracker_base import CrackConfig, CrackProgress, CrackStatus, AttackMode, CrackerBackend
from core.john_backend import JohnBackend
from core.hashcat_backend import HashcatBackend


class CrackWorker(QThread):
    """Worker thread for running crack operations."""

    progress_updated = Signal(object)  # CrackProgress
    finished = Signal(bool, str)  # success, message
    command_ready = Signal(str)  # command line used

    def __init__(self, backend: CrackerBackend, config: CrackConfig):
        super().__init__()
        self.backend = backend
        self.config = config
        self._stop_requested = False

    def run(self):
        self.backend.set_progress_callback(self._on_progress)
        success = self.backend.start_crack(self.config)

        if not success:
            self.finished.emit(False, "Failed to start cracking")
            return

        if self.backend.last_command:
            self.command_ready.emit(self.backend.last_command)

        # Wait for completion
        while self.backend.status == CrackStatus.RUNNING and not self._stop_requested:
            self.msleep(500)

        progress = self.backend.get_progress()
        if progress.password_found:
            self.finished.emit(True, f"Password found: {progress.password_found}")
        elif self._stop_requested:
            self.finished.emit(False, "Cracking stopped by user")
        elif progress.error_message:
            self.finished.emit(False, progress.error_message)
        elif self.backend.status == CrackStatus.FAILED:
            self.finished.emit(False, "Cracking failed")
        else:
            self.finished.emit(False, "Password not found")

    def _on_progress(self, progress: CrackProgress):
        self.progress_updated.emit(progress)

    def stop(self):
        self._stop_requested = True
        self.backend.stop_crack()


class MainWindow(QMainWindow):
    """Main application window."""

    def __init__(self):
        super().__init__()

        self.hash_extractor = HashExtractor()
        self.john_backend = JohnBackend()
        self.hashcat_backend = HashcatBackend()
        self.current_backend: Optional[CrackerBackend] = None
        self.crack_worker: Optional[CrackWorker] = None
        self.current_hash_result: Optional[HashResult] = None

        self.setWindowTitle("Simple Cracker - Password Recovery Tool")
        self.setMinimumSize(900, 700)

        self._setup_ui()
        self._setup_menu()
        self._setup_statusbar()
        self._check_backends()

    def _setup_ui(self):
        """Setup the main UI."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Create splitter for resizable sections
        splitter = QSplitter(Qt.Vertical)
        main_layout.addWidget(splitter)

        # Top section: File and Hash
        top_widget = QWidget()
        top_layout = QVBoxLayout(top_widget)
        top_layout.setContentsMargins(0, 0, 0, 0)

        # File selection group
        file_group = QGroupBox("Target File")
        file_layout = QHBoxLayout(file_group)

        self.file_path_edit = QLineEdit()
        self.file_path_edit.setPlaceholderText("Select an encrypted file...")
        file_layout.addWidget(self.file_path_edit)

        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse_file)
        file_layout.addWidget(browse_btn)

        extract_btn = QPushButton("Extract Hash")
        extract_btn.clicked.connect(self._extract_hash)
        file_layout.addWidget(extract_btn)

        top_layout.addWidget(file_group)

        # Hash display group
        hash_group = QGroupBox("Hash Information")
        hash_layout = QVBoxLayout(hash_group)

        hash_info_layout = QHBoxLayout()
        hash_info_layout.addWidget(QLabel("File Type:"))
        self.file_type_label = QLabel("N/A")
        self.file_type_label.setStyleSheet("font-weight: bold;")
        hash_info_layout.addWidget(self.file_type_label)
        hash_info_layout.addSpacing(20)
        hash_info_layout.addWidget(QLabel("Hash Type:"))
        self.hash_type_label = QLabel("N/A")
        self.hash_type_label.setStyleSheet("font-weight: bold;")
        hash_info_layout.addWidget(self.hash_type_label)
        hash_info_layout.addStretch()
        hash_layout.addLayout(hash_info_layout)

        self.hash_edit = QTextEdit()
        self.hash_edit.setMaximumHeight(80)
        self.hash_edit.setPlaceholderText("Hash will appear here after extraction...")
        self.hash_edit.setFont(QFont("Monospace", 9))
        hash_layout.addWidget(self.hash_edit)

        top_layout.addWidget(hash_group)
        splitter.addWidget(top_widget)

        # Middle section: Attack configuration
        middle_widget = QWidget()
        middle_layout = QVBoxLayout(middle_widget)
        middle_layout.setContentsMargins(0, 0, 0, 0)

        # Backend selection
        backend_group = QGroupBox("Cracking Backend")
        backend_layout = QHBoxLayout(backend_group)

        self.backend_group = QButtonGroup()
        self.john_radio = QRadioButton("John the Ripper")
        self.hashcat_radio = QRadioButton("Hashcat")
        self.backend_group.addButton(self.john_radio, 0)
        self.backend_group.addButton(self.hashcat_radio, 1)
        self.john_radio.setChecked(True)

        self.john_status = QLabel()
        self.hashcat_status = QLabel()

        # Place each status label next to its corresponding backend toggle.
        backend_layout.addWidget(self.john_radio)
        backend_layout.addWidget(self.john_status)
        backend_layout.addWidget(self.hashcat_radio)
        backend_layout.addWidget(self.hashcat_status)
        backend_layout.addStretch()

        middle_layout.addWidget(backend_group)

        # Attack mode selection
        attack_group = QGroupBox("Attack Mode")
        attack_layout = QVBoxLayout(attack_group)

        # Attack mode tabs
        self.attack_tabs = QTabWidget()

        # Dictionary attack tab
        dict_tab = QWidget()
        dict_layout = QVBoxLayout(dict_tab)

        wordlist_layout = QHBoxLayout()
        wordlist_layout.addWidget(QLabel("Wordlist:"))
        self.wordlist_edit = QLineEdit()
        self.wordlist_edit.setPlaceholderText("Select a wordlist file...")
        wordlist_layout.addWidget(self.wordlist_edit)
        wordlist_browse = QPushButton("Browse...")
        wordlist_browse.clicked.connect(self._browse_wordlist)
        wordlist_layout.addWidget(wordlist_browse)
        dict_layout.addLayout(wordlist_layout)

        rules_layout = QHBoxLayout()
        self.use_rules_check = QCheckBox("Use rules:")
        rules_layout.addWidget(self.use_rules_check)
        self.rules_combo = QComboBox()
        self.rules_combo.setEnabled(False)
        self.use_rules_check.toggled.connect(self.rules_combo.setEnabled)
        rules_layout.addWidget(self.rules_combo)
        rules_layout.addStretch()
        dict_layout.addLayout(rules_layout)

        self.attack_tabs.addTab(dict_tab, "Dictionary")

        # Brute force tab
        brute_tab = QWidget()
        brute_layout = QVBoxLayout(brute_tab)

        charset_layout = QHBoxLayout()
        charset_layout.addWidget(QLabel("Character set:"))
        self.charset_combo = QComboBox()
        self.charset_combo.addItems([
            "All printable (?a)",
            "Lowercase (?l)",
            "Uppercase (?u)",
            "Digits (?d)",
            "Special (?s)",
            "Lowercase + Digits",
            "Upper + Lower + Digits",
        ])
        charset_layout.addWidget(self.charset_combo)
        charset_layout.addStretch()
        brute_layout.addLayout(charset_layout)

        length_layout = QHBoxLayout()
        length_layout.addWidget(QLabel("Min length:"))
        self.min_length_spin = QSpinBox()
        self.min_length_spin.setRange(1, 20)
        self.min_length_spin.setValue(1)
        length_layout.addWidget(self.min_length_spin)
        length_layout.addWidget(QLabel("Max length:"))
        self.max_length_spin = QSpinBox()
        self.max_length_spin.setRange(1, 20)
        self.max_length_spin.setValue(6)
        length_layout.addWidget(self.max_length_spin)
        self.increment_check = QCheckBox("Increment mode")
        self.increment_check.setChecked(True)
        length_layout.addWidget(self.increment_check)
        length_layout.addStretch()
        brute_layout.addLayout(length_layout)

        self.attack_tabs.addTab(brute_tab, "Brute Force")

        # Mask attack tab
        mask_tab = QWidget()
        mask_layout = QVBoxLayout(mask_tab)

        mask_input_layout = QHBoxLayout()
        mask_input_layout.addWidget(QLabel("Mask:"))
        self.mask_edit = QLineEdit()
        self.mask_edit.setPlaceholderText("e.g., ?u?l?l?l?d?d?d")
        mask_input_layout.addWidget(self.mask_edit)
        mask_layout.addLayout(mask_input_layout)

        mask_help = QLabel(
            "Mask characters: ?l=lowercase, ?u=uppercase, ?d=digit, ?s=special, ?a=all"
        )
        mask_help.setStyleSheet("color: gray; font-size: 10px;")
        mask_layout.addWidget(mask_help)
        mask_layout.addStretch()

        self.attack_tabs.addTab(mask_tab, "Mask")

        attack_layout.addWidget(self.attack_tabs)
        middle_layout.addWidget(attack_group)

        splitter.addWidget(middle_widget)

        # Bottom section: Progress and controls
        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(0, 0, 0, 0)

        # Control buttons
        control_layout = QHBoxLayout()

        self.start_btn = QPushButton("Start Cracking")
        self.start_btn.setMinimumHeight(40)
        self.start_btn.setStyleSheet(
            "QPushButton { background-color: #4CAF50; color: white; font-weight: bold; }"
            "QPushButton:hover { background-color: #45a049; }"
            "QPushButton:disabled { background-color: #cccccc; }"
        )
        self.start_btn.clicked.connect(self._start_crack)
        control_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setMinimumHeight(40)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet(
            "QPushButton { background-color: #f44336; color: white; font-weight: bold; }"
            "QPushButton:hover { background-color: #da190b; }"
            "QPushButton:disabled { background-color: #cccccc; }"
        )
        self.stop_btn.clicked.connect(self._stop_crack)
        control_layout.addWidget(self.stop_btn)

        bottom_layout.addLayout(control_layout)

        # Progress section
        progress_group = QGroupBox("Progress")
        progress_layout = QVBoxLayout(progress_group)

        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%p% - %v")
        progress_layout.addWidget(self.progress_bar)

        stats_layout = QHBoxLayout()
        stats_layout.addWidget(QLabel("Speed:"))
        self.speed_label = QLabel("N/A")
        self.speed_label.setStyleSheet("font-weight: bold;")
        stats_layout.addWidget(self.speed_label)
        stats_layout.addSpacing(20)
        stats_layout.addWidget(QLabel("ETA:"))
        self.eta_label = QLabel("N/A")
        self.eta_label.setStyleSheet("font-weight: bold;")
        stats_layout.addWidget(self.eta_label)
        stats_layout.addSpacing(20)
        stats_layout.addWidget(QLabel("Status:"))
        self.status_label = QLabel("Idle")
        self.status_label.setStyleSheet("font-weight: bold;")
        stats_layout.addWidget(self.status_label)
        stats_layout.addStretch()
        progress_layout.addLayout(stats_layout)

        # Active command display
        cmd_layout = QHBoxLayout()
        cmd_layout.addWidget(QLabel("Command:"))
        self.command_edit = QLineEdit()
        self.command_edit.setReadOnly(True)
        self.command_edit.setStyleSheet("QLineEdit { font-family: Monospace; }")
        self.command_edit.setMinimumWidth(200)
        cmd_layout.addWidget(self.command_edit)
        progress_layout.addLayout(cmd_layout)

        bottom_layout.addWidget(progress_group)

        # Result section
        result_group = QGroupBox("Result")
        result_layout = QVBoxLayout(result_group)

        result_display_layout = QHBoxLayout()
        result_display_layout.addWidget(QLabel("Password:"))
        self.password_edit = QLineEdit()
        self.password_edit.setReadOnly(True)
        self.password_edit.setStyleSheet(
            "QLineEdit { font-size: 14px; font-weight: bold; background-color: #ffffcc; }"
        )
        result_display_layout.addWidget(self.password_edit)

        copy_btn = QPushButton("Copy")
        copy_btn.clicked.connect(self._copy_password)
        result_display_layout.addWidget(copy_btn)

        result_layout.addLayout(result_display_layout)
        bottom_layout.addWidget(result_group)

        # Log output
        log_group = QGroupBox("Log")
        log_layout = QVBoxLayout(log_group)
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setMaximumHeight(100)
        self.log_edit.setFont(QFont("Monospace", 9))
        log_layout.addWidget(self.log_edit)
        bottom_layout.addWidget(log_group)

        splitter.addWidget(bottom_widget)

        # Set splitter proportions
        splitter.setSizes([200, 250, 350])

    def _setup_menu(self):
        """Setup menu bar."""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("File")

        open_action = QAction("Open File...", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self._browse_file)
        file_menu.addAction(open_action)

        file_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Tools menu
        tools_menu = menubar.addMenu("Tools")

        benchmark_action = QAction("Benchmark...", self)
        benchmark_action.triggered.connect(self._run_benchmark)
        tools_menu.addAction(benchmark_action)

        # Help menu
        help_menu = menubar.addMenu("Help")

        about_action = QAction("About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _setup_statusbar(self):
        """Setup status bar."""
        self.statusBar().showMessage("Ready")

    def _check_backends(self):
        """Check availability of cracking backends."""
        if self.john_backend.is_available():
            version = self.john_backend.get_version() or "available"
            self.john_status.setText(f"[{version[:30]}]")
            self.john_status.setStyleSheet("color: green;")
            self.john_radio.setEnabled(True)
        else:
            self.john_status.setText("[Not found]")
            self.john_status.setStyleSheet("color: red;")
            self.john_radio.setEnabled(False)

        if self.hashcat_backend.is_available():
            version = self.hashcat_backend.get_version() or "available"
            self.hashcat_status.setText(f"[{version[:30]}]")
            self.hashcat_status.setStyleSheet("color: green;")
            self.hashcat_radio.setEnabled(True)
        else:
            self.hashcat_status.setText("[Not found]")
            self.hashcat_status.setStyleSheet("color: red;")
            self.hashcat_radio.setEnabled(False)

        # Select first available backend
        if self.hashcat_backend.is_available():
            self.hashcat_radio.setChecked(True)
        elif self.john_backend.is_available():
            self.john_radio.setChecked(True)

        # Load rules for hashcat
        self._load_rules()

    def _load_rules(self):
        """Load available rules files."""
        rules = self.hashcat_backend.get_rules_files()
        self.rules_combo.clear()
        for rule_path in rules:
            self.rules_combo.addItem(os.path.basename(rule_path), rule_path)

        if not rules:
            self.rules_combo.addItem("No rules found", "")

    def _browse_file(self):
        """Browse for target file."""
        formats = self.hash_extractor.get_supported_formats()
        filter_str = "All supported files ("
        filter_str += " ".join([f[1] for f in formats])
        filter_str += ");;All files (*)"

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Encrypted File",
            "",
            filter_str
        )

        if file_path:
            self.file_path_edit.setText(file_path)
            self._extract_hash()

    def _browse_wordlist(self):
        """Browse for wordlist file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Wordlist",
            "/usr/share/wordlists",
            "Text files (*.txt *.lst *.dic);;All files (*)"
        )

        if file_path:
            self.wordlist_edit.setText(file_path)

    def _extract_hash(self):
        """Extract hash from selected file."""
        file_path = self.file_path_edit.text()
        if not file_path:
            return

        self._log(f"Extracting hash from: {file_path}")

        result = self.hash_extractor.extract_hash(file_path)
        self.current_hash_result = result

        if result.command_line:
            self._set_current_command(result.command_line)

        if result.success:
            self.hash_edit.setText(result.hash_string)
            self.file_type_label.setText(result.file_type.value)
            self.hash_type_label.setText(result.hash_type or "Auto-detect")
            self._log(f"Hash extracted successfully. Type: {result.file_type.value}")
            self.statusBar().showMessage("Hash extracted successfully")
        else:
            self.hash_edit.setText("")
            self.file_type_label.setText(result.file_type.value)
            self.hash_type_label.setText("N/A")
            self._log(f"Failed to extract hash: {result.error_message}")
            QMessageBox.warning(
                self,
                "Extraction Failed",
                f"Could not extract hash:\n{result.error_message}"
            )

    def _get_attack_config(self) -> Optional[CrackConfig]:
        """Build attack configuration from UI."""
        hash_string = self.hash_edit.toPlainText().strip()
        if not hash_string:
            QMessageBox.warning(self, "Error", "No hash to crack")
            return None

        hash_type = None
        if self.current_hash_result:
            hash_type = self.current_hash_result.hash_type

        config = CrackConfig(
            hash_string=hash_string,
            hash_type=hash_type
        )

        # Determine attack mode from selected tab
        tab_index = self.attack_tabs.currentIndex()

        if tab_index == 0:  # Dictionary
            config.attack_mode = AttackMode.DICTIONARY
            config.wordlist_path = self.wordlist_edit.text()

            if not config.wordlist_path or not os.path.exists(config.wordlist_path):
                QMessageBox.warning(self, "Error", "Please select a valid wordlist file")
                return None

            if self.use_rules_check.isChecked():
                config.attack_mode = AttackMode.RULES
                config.rules_file = self.rules_combo.currentData()

        elif tab_index == 1:  # Brute force
            config.attack_mode = AttackMode.BRUTE_FORCE
            config.min_length = self.min_length_spin.value()
            config.max_length = self.max_length_spin.value()
            config.increment = self.increment_check.isChecked()

            # Map charset selection
            charset_map = {
                0: "?a",  # All printable
                1: "?l",  # Lowercase
                2: "?u",  # Uppercase
                3: "?d",  # Digits
                4: "?s",  # Special
                5: "?l?d",  # Lower + digits
                6: "?u?l?d",  # Upper + lower + digits
            }
            config.charset = charset_map.get(self.charset_combo.currentIndex(), "?a")

        elif tab_index == 2:  # Mask
            config.attack_mode = AttackMode.MASK
            config.mask = self.mask_edit.text()

            if not config.mask:
                QMessageBox.warning(self, "Error", "Please enter a mask pattern")
                return None

        return config

    def _start_crack(self):
        """Start the cracking process."""
        config = self._get_attack_config()
        if not config:
            return

        # Select backend
        if self.john_radio.isChecked():
            self.current_backend = self.john_backend
            backend_name = "John the Ripper"
        else:
            self.current_backend = self.hashcat_backend
            backend_name = "Hashcat"

        if not self.current_backend.is_available():
            QMessageBox.critical(self, "Error", f"{backend_name} is not available")
            return

        self._log(f"Starting {backend_name} with {config.attack_mode.value} attack...")

        # Update UI
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.password_edit.setText("")
        self.status_label.setText("Running...")
        self._set_current_command("")

        # Start worker thread
        self.crack_worker = CrackWorker(self.current_backend, config)
        self.crack_worker.progress_updated.connect(self._on_progress)
        self.crack_worker.finished.connect(self._on_crack_finished)
        self.crack_worker.command_ready.connect(self._on_command_ready)
        self.crack_worker.start()

    def _stop_crack(self):
        """Stop the cracking process."""
        if self.crack_worker:
            self._log("Stopping...")
            self.crack_worker.stop()

    @Slot(object)
    def _on_progress(self, progress: CrackProgress):
        """Handle progress update."""
        self.progress_bar.setValue(int(progress.progress_percent))
        self.speed_label.setText(progress.speed)
        self.eta_label.setText(progress.estimated_time)
        self.status_label.setText(progress.status.value)

        if progress.password_found:
            self.password_edit.setText(progress.password_found)
        if progress.error_message:
            self._log(progress.error_message)

    @Slot(bool, str)
    def _on_crack_finished(self, success: bool, message: str):
        """Handle crack completion."""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

        if success:
            self.status_label.setText("Found!")
            self.status_label.setStyleSheet("color: green; font-weight: bold;")
            self._log(f"SUCCESS: {message}")
            QMessageBox.information(self, "Password Found!", message)
        else:
            label = "Error" if (self.current_backend and self.current_backend.status == CrackStatus.FAILED) else "Not found"
            self.status_label.setText(label)
            self.status_label.setStyleSheet("color: red; font-weight: bold;")
            self._log(f"FINISHED: {message}")
            if label == "Error":
                QMessageBox.warning(self, "Cracking Failed", message)

        self.crack_worker = None

    @Slot(str)
    def _on_command_ready(self, cmd: str):
        """Display the currently running command."""
        self._set_current_command(cmd)
        if cmd:
            self._log(f"Command: {cmd}")

    def _copy_password(self):
        """Copy password to clipboard."""
        password = self.password_edit.text()
        if password:
            from PySide6.QtWidgets import QApplication
            QApplication.clipboard().setText(password)
            self.statusBar().showMessage("Password copied to clipboard", 3000)

    def _run_benchmark(self):
        """Run benchmark."""
        QMessageBox.information(
            self,
            "Benchmark",
            "Benchmark feature coming soon.\n\n"
            "You can run benchmarks manually:\n"
            "- John: john --test\n"
            "- Hashcat: hashcat -b"
        )

    def _show_about(self):
        """Show about dialog."""
        QMessageBox.about(
            self,
            "About Simple Cracker",
            "Simple Cracker v1.0\n\n"
            "A password recovery tool with GUI.\n\n"
            "Supported backends:\n"
            "- John the Ripper\n"
            "- Hashcat\n\n"
            "Supported formats:\n"
            "- ZIP, 7z, RAR archives\n"
            "- PDF documents\n"
            "- MS Office (doc, docx, xls, xlsx, ppt, pptx)\n"
            "- KeePass databases\n"
            "- SSH keys\n"
            "- GPG encrypted files"
        )

    def _log(self, message: str):
        """Add message to log."""
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_edit.append(f"[{timestamp}] {message}")

    def _set_current_command(self, cmd: str):
        """Show current command line."""
        self.command_edit.setText(cmd)

    def closeEvent(self, event):
        """Handle window close."""
        if self.crack_worker and self.crack_worker.isRunning():
            reply = QMessageBox.question(
                self,
                "Confirm Exit",
                "Cracking is in progress. Stop and exit?",
                QMessageBox.Yes | QMessageBox.No
            )

            if reply == QMessageBox.Yes:
                self.crack_worker.stop()
                self.crack_worker.wait(5000)
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()
