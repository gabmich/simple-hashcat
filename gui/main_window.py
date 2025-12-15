"""
Main window for the password cracker GUI.
Modern 3-column layout with collapsible log panel.
"""

import os
from typing import Optional
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QGroupBox, QLabel, QPushButton, QLineEdit, QComboBox,
    QTextEdit, QProgressBar, QFileDialog, QSpinBox, QCheckBox,
    QRadioButton, QButtonGroup, QMessageBox, QSplitter, QFrame,
    QStatusBar, QSizePolicy, QGridLayout
)
from PySide6.QtCore import Qt, QThread, Signal, Slot, QPropertyAnimation, QEasingCurve
from PySide6.QtGui import QAction, QFont

from core.hash_extractor import HashExtractor, HashResult, FileType
from core.cracker_base import CrackConfig, CrackProgress, CrackStatus, AttackMode, CrackerBackend
from core.john_backend import JohnBackend
from core.hashcat_backend import HashcatBackend


# Modern light theme stylesheet
STYLE_SHEET = """
QMainWindow {
    background-color: #f5f5f5;
}

QGroupBox {
    font-weight: bold;
    font-size: 12px;
    border: 1px solid #e0e0e0;
    border-radius: 8px;
    margin-top: 14px;
    padding: 12px 8px 8px 8px;
    background-color: #ffffff;
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
    color: #333333;
}

QPushButton {
    background-color: #f0f0f0;
    border: 1px solid #cccccc;
    border-radius: 4px;
    padding: 6px 12px;
    font-size: 12px;
}

QPushButton:hover {
    background-color: #e0e0e0;
}

QPushButton:pressed {
    background-color: #d0d0d0;
}

QPushButton:disabled {
    background-color: #f5f5f5;
    color: #aaaaaa;
}

QPushButton#startBtn {
    background-color: #4CAF50;
    color: white;
    font-weight: bold;
    font-size: 13px;
    border: none;
    border-radius: 6px;
    padding: 14px 24px;
}

QPushButton#startBtn:hover {
    background-color: #43A047;
}

QPushButton#startBtn:pressed {
    background-color: #388E3C;
}

QPushButton#startBtn:disabled {
    background-color: #C8E6C9;
    color: #81C784;
}

QPushButton#stopBtn {
    background-color: #f44336;
    color: white;
    font-weight: bold;
    font-size: 13px;
    border: none;
    border-radius: 6px;
    padding: 14px 24px;
}

QPushButton#stopBtn:hover {
    background-color: #E53935;
}

QPushButton#stopBtn:pressed {
    background-color: #D32F2F;
}

QPushButton#stopBtn:disabled {
    background-color: #FFCDD2;
    color: #EF9A9A;
}

QPushButton#toggleLogBtn {
    background-color: transparent;
    border: none;
    color: #666666;
    font-size: 11px;
    padding: 4px 8px;
}

QPushButton#toggleLogBtn:hover {
    color: #333333;
    background-color: #e8e8e8;
    border-radius: 4px;
}

QPushButton#copyBtn {
    background-color: #2196F3;
    color: white;
    border: none;
    border-radius: 4px;
    padding: 8px 16px;
    font-weight: bold;
}

QPushButton#copyBtn:hover {
    background-color: #1E88E5;
}

QLineEdit {
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    padding: 8px;
    background-color: #ffffff;
    font-size: 12px;
}

QLineEdit:focus {
    border-color: #2196F3;
}

QLineEdit:read-only {
    background-color: #fafafa;
}

QLineEdit#passwordResult {
    background-color: #E8F5E9;
    font-size: 15px;
    font-weight: bold;
    padding: 10px;
    border: 2px solid #4CAF50;
    border-radius: 6px;
    color: #2E7D32;
}

QLineEdit#commandDisplay {
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 11px;
    background-color: #263238;
    color: #ECEFF1;
    border: none;
    border-radius: 4px;
    padding: 8px;
}

QTextEdit {
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    background-color: #ffffff;
    font-size: 12px;
}

QTextEdit#hashDisplay {
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 11px;
    background-color: #fafafa;
}

QTextEdit#logDisplay {
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 11px;
    background-color: #263238;
    color: #B0BEC5;
    border: none;
    border-radius: 4px;
}

QComboBox {
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    padding: 6px 10px;
    background-color: #ffffff;
    font-size: 12px;
}

QComboBox:hover {
    border-color: #2196F3;
}

QComboBox::drop-down {
    border: none;
    padding-right: 8px;
}

QSpinBox {
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    padding: 6px;
    background-color: #ffffff;
}

QProgressBar {
    border: none;
    border-radius: 6px;
    background-color: #E0E0E0;
    text-align: center;
    font-weight: bold;
    font-size: 11px;
}

QProgressBar::chunk {
    background-color: #4CAF50;
    border-radius: 6px;
}

QRadioButton {
    font-size: 12px;
    spacing: 8px;
}

QRadioButton::indicator {
    width: 16px;
    height: 16px;
}

QCheckBox {
    font-size: 12px;
    spacing: 8px;
}

QTabWidget::pane {
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    background-color: #ffffff;
    padding: 8px;
}

QTabBar::tab {
    background-color: #f0f0f0;
    border: 1px solid #e0e0e0;
    border-bottom: none;
    padding: 8px 16px;
    margin-right: 2px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
}

QTabBar::tab:selected {
    background-color: #ffffff;
    border-bottom: 1px solid #ffffff;
}

QTabBar::tab:hover:!selected {
    background-color: #e8e8e8;
}

QLabel#statusValue {
    font-weight: bold;
    font-size: 12px;
}

QLabel#sectionTitle {
    font-size: 11px;
    color: #666666;
    font-weight: bold;
    text-transform: uppercase;
}

QSplitter::handle {
    background-color: #e0e0e0;
}

QSplitter::handle:horizontal {
    width: 3px;
}

QSplitter::handle:vertical {
    height: 3px;
}

QSplitter::handle:hover {
    background-color: #2196F3;
}
"""


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
    """Main application window with modern 3-column layout."""

    def __init__(self):
        super().__init__()

        self.hash_extractor = HashExtractor()
        self.john_backend = JohnBackend()
        self.hashcat_backend = HashcatBackend()
        self.current_backend: Optional[CrackerBackend] = None
        self.crack_worker: Optional[CrackWorker] = None
        self.current_hash_result: Optional[HashResult] = None
        self._log_visible = True

        self.setWindowTitle("Simple Cracker - Password Recovery Tool")
        self.setMinimumSize(1000, 650)
        self.resize(1200, 750)

        self.setStyleSheet(STYLE_SHEET)

        self._setup_ui()
        self._setup_menu()
        self._setup_statusbar()
        self._check_backends()

    def _setup_ui(self):
        """Setup the main UI with 3-column layout."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(8)

        # Main vertical splitter (columns + log)
        self.main_splitter = QSplitter(Qt.Vertical)
        main_layout.addWidget(self.main_splitter)

        # Top section: 3 columns
        columns_widget = QWidget()
        columns_layout = QHBoxLayout(columns_widget)
        columns_layout.setContentsMargins(0, 0, 0, 0)
        columns_layout.setSpacing(0)

        # Horizontal splitter for the 3 columns
        self.columns_splitter = QSplitter(Qt.Horizontal)
        columns_layout.addWidget(self.columns_splitter)

        # Create the 3 panels
        left_panel = self._create_source_panel()
        center_panel = self._create_config_panel()
        right_panel = self._create_results_panel()

        self.columns_splitter.addWidget(left_panel)
        self.columns_splitter.addWidget(center_panel)
        self.columns_splitter.addWidget(right_panel)

        # Set column sizes and stretch factors
        self.columns_splitter.setSizes([280, 420, 320])
        self.columns_splitter.setStretchFactor(0, 0)  # Left: fixed
        self.columns_splitter.setStretchFactor(1, 1)  # Center: stretch
        self.columns_splitter.setStretchFactor(2, 0)  # Right: fixed

        self.main_splitter.addWidget(columns_widget)

        # Bottom section: collapsible log
        log_panel = self._create_log_panel()
        self.main_splitter.addWidget(log_panel)

        # Set main splitter proportions
        self.main_splitter.setSizes([500, 150])
        self.main_splitter.setStretchFactor(0, 1)
        self.main_splitter.setStretchFactor(1, 0)

    def _create_source_panel(self) -> QWidget:
        """Create the left panel: file selection and hash display."""
        panel = QWidget()
        panel.setMinimumWidth(250)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(4, 4, 8, 4)
        layout.setSpacing(12)

        # Target File group
        file_group = QGroupBox("Target File")
        file_layout = QVBoxLayout(file_group)
        file_layout.setSpacing(8)

        self.file_path_edit = QLineEdit()
        self.file_path_edit.setPlaceholderText("Select an encrypted file...")
        file_layout.addWidget(self.file_path_edit)

        file_buttons = QHBoxLayout()
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse_file)
        file_buttons.addWidget(browse_btn)

        extract_btn = QPushButton("Extract Hash")
        extract_btn.clicked.connect(self._extract_hash)
        file_buttons.addWidget(extract_btn)
        file_layout.addLayout(file_buttons)

        layout.addWidget(file_group)

        # Hash Information group
        info_group = QGroupBox("Hash Information")
        info_layout = QGridLayout(info_group)
        info_layout.setSpacing(8)

        info_layout.addWidget(QLabel("File Type:"), 0, 0)
        self.file_type_label = QLabel("N/A")
        self.file_type_label.setObjectName("statusValue")
        self.file_type_label.setStyleSheet("color: #1976D2;")
        info_layout.addWidget(self.file_type_label, 0, 1)

        info_layout.addWidget(QLabel("Hash Mode:"), 1, 0)
        self.hash_type_label = QLabel("N/A")
        self.hash_type_label.setObjectName("statusValue")
        self.hash_type_label.setStyleSheet("color: #1976D2;")
        info_layout.addWidget(self.hash_type_label, 1, 1)

        layout.addWidget(info_group)

        # Extracted Hash group
        hash_group = QGroupBox("Extracted Hash")
        hash_layout = QVBoxLayout(hash_group)

        self.hash_edit = QTextEdit()
        self.hash_edit.setObjectName("hashDisplay")
        self.hash_edit.setPlaceholderText("Hash will appear here after extraction...")
        self.hash_edit.setFont(QFont("Consolas", 10))
        hash_layout.addWidget(self.hash_edit)

        layout.addWidget(hash_group)

        # Stretch to fill remaining space
        layout.addStretch()

        return panel

    def _create_config_panel(self) -> QWidget:
        """Create the center panel: backend selection and attack configuration."""
        panel = QWidget()
        panel.setMinimumWidth(320)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(12)

        # Backend Selection group
        backend_group = QGroupBox("Cracking Backend")
        backend_layout = QVBoxLayout(backend_group)
        backend_layout.setSpacing(8)

        self.backend_group = QButtonGroup()

        # John row
        john_row = QHBoxLayout()
        self.john_radio = QRadioButton("John the Ripper")
        self.backend_group.addButton(self.john_radio, 0)
        john_row.addWidget(self.john_radio)
        self.john_status = QLabel()
        self.john_status.setStyleSheet("font-size: 11px;")
        john_row.addWidget(self.john_status)
        john_row.addStretch()
        backend_layout.addLayout(john_row)

        # Hashcat row
        hashcat_row = QHBoxLayout()
        self.hashcat_radio = QRadioButton("Hashcat")
        self.backend_group.addButton(self.hashcat_radio, 1)
        hashcat_row.addWidget(self.hashcat_radio)
        self.hashcat_status = QLabel()
        self.hashcat_status.setStyleSheet("font-size: 11px;")
        hashcat_row.addWidget(self.hashcat_status)
        hashcat_row.addStretch()
        backend_layout.addLayout(hashcat_row)

        self.john_radio.setChecked(True)
        layout.addWidget(backend_group)

        # Attack Configuration group
        attack_group = QGroupBox("Attack Configuration")
        attack_layout = QVBoxLayout(attack_group)

        self.attack_tabs = QTabWidget()

        # Dictionary tab
        dict_tab = QWidget()
        dict_layout = QVBoxLayout(dict_tab)
        dict_layout.setSpacing(12)

        wordlist_label = QLabel("Wordlist:")
        wordlist_label.setObjectName("sectionTitle")
        dict_layout.addWidget(wordlist_label)

        wordlist_row = QHBoxLayout()
        self.wordlist_edit = QLineEdit()
        self.wordlist_edit.setPlaceholderText("Select a wordlist file...")
        wordlist_row.addWidget(self.wordlist_edit)
        wordlist_browse = QPushButton("Browse...")
        wordlist_browse.clicked.connect(self._browse_wordlist)
        wordlist_row.addWidget(wordlist_browse)
        dict_layout.addLayout(wordlist_row)

        rules_row = QHBoxLayout()
        self.use_rules_check = QCheckBox("Apply rules:")
        rules_row.addWidget(self.use_rules_check)
        self.rules_combo = QComboBox()
        self.rules_combo.setEnabled(False)
        self.rules_combo.setMinimumWidth(150)
        self.use_rules_check.toggled.connect(self.rules_combo.setEnabled)
        rules_row.addWidget(self.rules_combo)
        rules_row.addStretch()
        dict_layout.addLayout(rules_row)

        dict_layout.addStretch()
        self.attack_tabs.addTab(dict_tab, "Dictionary")

        # Brute Force tab
        brute_tab = QWidget()
        brute_layout = QVBoxLayout(brute_tab)
        brute_layout.setSpacing(12)

        charset_label = QLabel("Character Set:")
        charset_label.setObjectName("sectionTitle")
        brute_layout.addWidget(charset_label)

        self.charset_combo = QComboBox()
        self.charset_combo.addItems([
            "All printable (?a)",
            "Lowercase (?l)",
            "Uppercase (?u)",
            "Digits (?d)",
            "Special (?s)",
            "Lowercase + Digits",
            "Upper + Lower + Digits",
            "Custom (specify below)",
        ])
        self.charset_combo.currentIndexChanged.connect(self._on_charset_changed)
        brute_layout.addWidget(self.charset_combo)

        # Custom charset input
        custom_charset_label = QLabel("Custom Characters:")
        custom_charset_label.setObjectName("sectionTitle")
        brute_layout.addWidget(custom_charset_label)

        self.custom_charset_edit = QLineEdit()
        self.custom_charset_edit.setPlaceholderText("e.g., wk or a-z or a-zA-Z0-9")
        self.custom_charset_edit.setFont(QFont("Consolas", 11))
        self.custom_charset_edit.setEnabled(False)
        brute_layout.addWidget(self.custom_charset_edit)

        custom_help = QLabel("Supports ranges (a-z, 0-9) or explicit chars (wk@#)")
        custom_help.setStyleSheet("color: #666666; font-size: 10px;")
        brute_layout.addWidget(custom_help)

        length_label = QLabel("Password Length:")
        length_label.setObjectName("sectionTitle")
        brute_layout.addWidget(length_label)

        length_row = QHBoxLayout()
        length_row.addWidget(QLabel("Min:"))
        self.min_length_spin = QSpinBox()
        self.min_length_spin.setRange(1, 20)
        self.min_length_spin.setValue(1)
        length_row.addWidget(self.min_length_spin)

        length_row.addSpacing(16)
        length_row.addWidget(QLabel("Max:"))
        self.max_length_spin = QSpinBox()
        self.max_length_spin.setRange(1, 20)
        self.max_length_spin.setValue(6)
        length_row.addWidget(self.max_length_spin)
        length_row.addStretch()
        brute_layout.addLayout(length_row)

        self.increment_check = QCheckBox("Increment mode (start from min)")
        self.increment_check.setChecked(True)
        brute_layout.addWidget(self.increment_check)

        brute_layout.addStretch()
        self.attack_tabs.addTab(brute_tab, "Brute Force")

        # Mask tab
        mask_tab = QWidget()
        mask_layout = QVBoxLayout(mask_tab)
        mask_layout.setSpacing(12)

        mask_label = QLabel("Mask Pattern:")
        mask_label.setObjectName("sectionTitle")
        mask_layout.addWidget(mask_label)

        self.mask_edit = QLineEdit()
        self.mask_edit.setPlaceholderText("e.g., ?u?l?l?l?d?d?d")
        self.mask_edit.setFont(QFont("Consolas", 11))
        mask_layout.addWidget(self.mask_edit)

        mask_help = QLabel(
            "?l = lowercase  ?u = uppercase  ?d = digit\n"
            "?s = special    ?a = all printable"
        )
        mask_help.setStyleSheet("color: #666666; font-size: 11px;")
        mask_layout.addWidget(mask_help)

        mask_layout.addStretch()
        self.attack_tabs.addTab(mask_tab, "Mask")

        attack_layout.addWidget(self.attack_tabs)
        layout.addWidget(attack_group)

        # Control Buttons
        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(12)

        self.start_btn = QPushButton("Start Cracking")
        self.start_btn.setObjectName("startBtn")
        self.start_btn.clicked.connect(self._start_crack)
        buttons_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_crack)
        buttons_layout.addWidget(self.stop_btn)

        layout.addLayout(buttons_layout)

        # Stretch to push buttons down
        layout.addStretch()

        return panel

    def _create_results_panel(self) -> QWidget:
        """Create the right panel: progress, result, and command display."""
        panel = QWidget()
        panel.setMinimumWidth(280)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(8, 4, 4, 4)
        layout.setSpacing(12)

        # Progress group
        progress_group = QGroupBox("Progress")
        progress_layout = QVBoxLayout(progress_group)
        progress_layout.setSpacing(10)

        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%p%")
        self.progress_bar.setMinimumHeight(24)
        progress_layout.addWidget(self.progress_bar)

        # Stats grid
        stats_grid = QGridLayout()
        stats_grid.setSpacing(8)

        stats_grid.addWidget(QLabel("Speed:"), 0, 0)
        self.speed_label = QLabel("--")
        self.speed_label.setObjectName("statusValue")
        stats_grid.addWidget(self.speed_label, 0, 1)

        stats_grid.addWidget(QLabel("Tried:"), 1, 0)
        self.tried_label = QLabel("--")
        self.tried_label.setObjectName("statusValue")
        stats_grid.addWidget(self.tried_label, 1, 1)

        stats_grid.addWidget(QLabel("ETA:"), 2, 0)
        self.eta_label = QLabel("--")
        self.eta_label.setObjectName("statusValue")
        stats_grid.addWidget(self.eta_label, 2, 1)

        stats_grid.addWidget(QLabel("Status:"), 3, 0)
        self.status_label = QLabel("Idle")
        self.status_label.setObjectName("statusValue")
        self.status_label.setStyleSheet("color: #666666; font-weight: bold;")
        stats_grid.addWidget(self.status_label, 3, 1)

        progress_layout.addLayout(stats_grid)
        layout.addWidget(progress_group)

        # Result group
        result_group = QGroupBox("Result")
        result_layout = QVBoxLayout(result_group)
        result_layout.setSpacing(10)

        pwd_label = QLabel("Password Found:")
        pwd_label.setObjectName("sectionTitle")
        result_layout.addWidget(pwd_label)

        self.password_edit = QLineEdit()
        self.password_edit.setObjectName("passwordResult")
        self.password_edit.setReadOnly(True)
        self.password_edit.setPlaceholderText("No password found yet")
        result_layout.addWidget(self.password_edit)

        copy_btn = QPushButton("Copy to Clipboard")
        copy_btn.setObjectName("copyBtn")
        copy_btn.clicked.connect(self._copy_password)
        result_layout.addWidget(copy_btn)

        layout.addWidget(result_group)

        # Command group
        command_group = QGroupBox("Command")
        command_layout = QVBoxLayout(command_group)

        self.command_edit = QLineEdit()
        self.command_edit.setObjectName("commandDisplay")
        self.command_edit.setReadOnly(True)
        self.command_edit.setPlaceholderText("$ command will appear here...")
        command_layout.addWidget(self.command_edit)

        layout.addWidget(command_group)

        # Stretch to fill remaining space
        layout.addStretch()

        return panel

    def _create_log_panel(self) -> QWidget:
        """Create the bottom collapsible log panel."""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        # Header with toggle button
        header = QHBoxLayout()

        self.toggle_log_btn = QPushButton("Hide Log")
        self.toggle_log_btn.setObjectName("toggleLogBtn")
        self.toggle_log_btn.clicked.connect(self._toggle_log)
        header.addWidget(self.toggle_log_btn)

        header.addStretch()

        clear_btn = QPushButton("Clear")
        clear_btn.setObjectName("toggleLogBtn")
        clear_btn.clicked.connect(lambda: self.log_edit.clear())
        header.addWidget(clear_btn)

        layout.addLayout(header)

        # Log text area
        self.log_edit = QTextEdit()
        self.log_edit.setObjectName("logDisplay")
        self.log_edit.setReadOnly(True)
        self.log_edit.setMinimumHeight(80)
        self.log_edit.setMaximumHeight(200)
        self.log_edit.setFont(QFont("Consolas", 10))
        layout.addWidget(self.log_edit)

        return panel

    def _toggle_log(self):
        """Toggle log panel visibility."""
        self._log_visible = not self._log_visible

        if self._log_visible:
            self.log_edit.show()
            self.toggle_log_btn.setText("Hide Log")
            self.main_splitter.setSizes([500, 150])
        else:
            self.log_edit.hide()
            self.toggle_log_btn.setText("Show Log")
            self.main_splitter.setSizes([650, 30])

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
            self.john_status.setText(f"({version[:25]})")
            self.john_status.setStyleSheet("color: #4CAF50; font-size: 11px;")
            self.john_radio.setEnabled(True)
        else:
            self.john_status.setText("(not found)")
            self.john_status.setStyleSheet("color: #f44336; font-size: 11px;")
            self.john_radio.setEnabled(False)

        if self.hashcat_backend.is_available():
            version = self.hashcat_backend.get_version() or "available"
            self.hashcat_status.setText(f"({version[:25]})")
            self.hashcat_status.setStyleSheet("color: #4CAF50; font-size: 11px;")
            self.hashcat_radio.setEnabled(True)
        else:
            self.hashcat_status.setText("(not found)")
            self.hashcat_status.setStyleSheet("color: #f44336; font-size: 11px;")
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

    def _on_charset_changed(self, index: int):
        """Handle charset combo box change."""
        # Index 7 = "Custom (specify below)"
        is_custom = (index == 7)
        self.custom_charset_edit.setEnabled(is_custom)
        if is_custom:
            self.custom_charset_edit.setFocus()

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

            charset_index = self.charset_combo.currentIndex()

            # Check if custom charset is selected (index 7)
            if charset_index == 7:
                custom = self.custom_charset_edit.text().strip()
                if not custom:
                    QMessageBox.warning(self, "Error", "Please enter custom characters")
                    return None
                config.custom_charset = custom
            else:
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
                config.charset = charset_map.get(charset_index, "?a")

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
        self.password_edit.setPlaceholderText("Cracking in progress...")
        self.status_label.setText("Running...")
        self.status_label.setStyleSheet("color: #FF9800; font-weight: bold;")
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

    def _format_count(self, count: int) -> str:
        """Format a count with K/M/G/T suffix."""
        if count < 1000:
            return str(count)
        elif count < 1_000_000:
            return f"{count / 1000:.1f}K"
        elif count < 1_000_000_000:
            return f"{count / 1_000_000:.2f}M"
        elif count < 1_000_000_000_000:
            return f"{count / 1_000_000_000:.2f}G"
        else:
            return f"{count / 1_000_000_000_000:.2f}T"

    @Slot(object)
    def _on_progress(self, progress: CrackProgress):
        """Handle progress update."""
        self.progress_bar.setValue(int(progress.progress_percent))
        self.speed_label.setText(progress.speed or "--")
        self.tried_label.setText(self._format_count(progress.candidates_tried) if progress.candidates_tried > 0 else "--")
        self.eta_label.setText(progress.estimated_time or "--")
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
        self.password_edit.setPlaceholderText("No password found yet")

        if success:
            self.status_label.setText("Found!")
            self.status_label.setStyleSheet("color: #4CAF50; font-weight: bold;")
            self._log(f"SUCCESS: {message}")
            QMessageBox.information(self, "Password Found!", message)
        else:
            is_error = self.current_backend and self.current_backend.status == CrackStatus.FAILED
            label = "Error" if is_error else "Not found"
            self.status_label.setText(label)
            self.status_label.setStyleSheet("color: #f44336; font-weight: bold;")
            self._log(f"FINISHED: {message}")
            if is_error:
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
