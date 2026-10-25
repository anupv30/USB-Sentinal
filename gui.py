"""
USB Sentinel AI - Cyber-Forensics User Interface
Modern Dark-Mode / Cyberpunk Forensic Dashboard using PyQt6.
Features:
- Real-time Hardware Sentinel status & auto-insertion detection
- Dynamic Heuristic & Forensic Scanner with progress bar & cancel
- Interactive File System Tree & Deep Metadata Inspector
- MACB Chronological Filesystem Timeline Viewer
- Natural Language AI Copilot with Groq Tool Calling
- Isolated Quarantine Vault Manager & Audit Trail
- One-Click ReportLab PDF Forensic Report Export
"""

import os
import sys
import json
import shutil
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSize, QTimer
from PyQt6.QtGui import QColor, QFont, QIcon, QAction, QPalette, QBrush
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QLabel, QPushButton, QProgressBar, QTreeWidget, QTreeWidgetItem,
    QTableWidget, QTableWidgetItem, QHeaderView, QTextEdit, QLineEdit,
    QSplitter, QFrame, QFileDialog, QMessageBox, QComboBox, QCheckBox,
    QSlider, QSpinBox, QMenu, QScrollArea, QGroupBox
)

from scanner import ScannerWorker, scan_single_file, calculate_shannon_entropy
from usb_monitor import USBMonitorThread, USBDevice, query_all_removable_drives
from quarantine import QuarantineVault
from groq_analyzer import GroqAnalyzer, DEFAULT_API_KEY, DEFAULT_MODEL
from report_gen import generate_forensic_pdf


# Cyberpunk / Dark Slate Forensic Stylesheet
CYBER_STYLESHEET = """
QMainWindow {
    background-color: #0B0F19;
}
QWidget {
    color: #E2E8F0;
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
    font-size: 13px;
}
QTabWidget::pane {
    border: 1px solid #1E293B;
    background-color: #0F172A;
    border-radius: 8px;
    top: -1px;
}
QTabBar::tab {
    background-color: #0B0F19;
    color: #94A3B8;
    padding: 10px 20px;
    margin-right: 4px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    border: 1px solid #1E293B;
    border-bottom: none;
    font-weight: 600;
}
QTabBar::tab:selected {
    background-color: #0F172A;
    color: #06B6D4;
    border-top: 2px solid #06B6D4;
}
QTabBar::tab:hover:!selected {
    background-color: #1E293B;
    color: #F8FAFC;
}
QFrame#Card, QGroupBox {
    background-color: #161F30;
    border: 1px solid #1E293B;
    border-radius: 8px;
    padding: 12px;
}
QGroupBox {
    font-weight: bold;
    color: #06B6D4;
    margin-top: 8px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
}
QPushButton {
    background-color: #1E293B;
    color: #F1F5F9;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 600;
}
QPushButton:hover {
    background-color: #334155;
    border-color: #06B6D4;
    color: #06B6D4;
}
QPushButton:pressed {
    background-color: #0F172A;
}
QPushButton#PrimaryBtn {
    background-color: #0284C7;
    border: 1px solid #06B6D4;
    color: #FFFFFF;
}
QPushButton#PrimaryBtn:hover {
    background-color: #0369A1;
}
QPushButton#DangerBtn {
    background-color: #991B1B;
    border: 1px solid #EF4444;
    color: #FFFFFF;
}
QPushButton#DangerBtn:hover {
    background-color: #B91C1C;
}
QPushButton#SuccessBtn {
    background-color: #065F46;
    border: 1px solid #10B981;
    color: #FFFFFF;
}
QPushButton#SuccessBtn:hover {
    background-color: #047857;
}
QLineEdit, QTextEdit, QComboBox {
    background-color: #0B0F19;
    color: #F8FAFC;
    border: 1px solid #1E293B;
    border-radius: 6px;
    padding: 6px 10px;
}
QLineEdit:focus, QTextEdit:focus, QComboBox:focus {
    border: 1px solid #06B6D4;
}
QTreeWidget, QTableWidget {
    background-color: #0B0F19;
    border: 1px solid #1E293B;
    border-radius: 6px;
    gridline-color: #1E293B;
    color: #E2E8F0;
    selection-background-color: #1E293B;
    selection-color: #06B6D4;
}
QHeaderView::section {
    background-color: #161F30;
    color: #94A3B8;
    padding: 6px;
    border: 1px solid #1E293B;
    font-weight: 600;
}
QProgressBar {
    background-color: #0B0F19;
    border: 1px solid #1E293B;
    border-radius: 6px;
    text-align: center;
    color: #FFFFFF;
    font-weight: bold;
    height: 18px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0284C7, stop:1 #06B6D4);
    border-radius: 5px;
}
QScrollBar:vertical {
    border: none;
    background-color: #0B0F19;
    width: 8px;
    margin: 0px;
}
QScrollBar::handle:vertical {
    background-color: #1E293B;
    min-height: 20px;
    border-radius: 4px;
}
QScrollBar::handle:vertical:hover {
    background-color: #334155;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
"""


class GroqAsyncWorker(QThread):
    """Asynchronous worker for Groq API calls to keep UI completely responsive."""
    analysis_completed = pyqtSignal(dict)
    chat_completed = pyqtSignal(str, list)
    error_occurred = pyqtSignal(str)

    def __init__(self, analyzer: GroqAnalyzer, mode: str, **kwargs):
        super().__init__()
        self.analyzer = analyzer
        self.mode = mode  # 'deep_analysis' or 'chat'
        self.kwargs = kwargs

    def run(self):
        try:
            if self.mode == "deep_analysis":
                file_data = self.kwargs.get("file_data")
                res = self.analyzer.analyze_suspicious_file(file_data)
                self.analysis_completed.emit(res)
            elif self.mode == "chat":
                msg = self.kwargs.get("message")
                hist = self.kwargs.get("history")
                ctx = self.kwargs.get("context")
                executor = self.kwargs.get("tool_executor")
                ans, actions = self.analyzer.chat_intent(msg, hist, ctx, executor)
                self.chat_completed.emit(ans, actions)
        except Exception as e:
            self.error_occurred.emit(str(e))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("USB SENTINEL AI // USB Forensics & Threat Intelligence")
        self.resize(1360, 880)
        self.setStyleSheet(CYBER_STYLESHEET)

        # Core Engines
        self.vault = QuarantineVault()
        self.analyzer = GroqAnalyzer(api_key=DEFAULT_API_KEY, model=DEFAULT_MODEL)
        
        # State Data
        self.current_usb_device: USBDevice = None
        self.all_connected_devices: list[USBDevice] = []
        self.scan_results = []
        self.scan_summary = {}
        self.ai_insights_cache = {}  # file_path -> ai_result dict
        self.audit_logs = []
        self.chat_history = []
        self.scanner_worker: ScannerWorker = None
        self.groq_worker: GroqAsyncWorker = None

        # Build UI Tabs & Layout
        self._init_ui()

        # Start Hardware Monitoring Thread
        self.monitor_thread = USBMonitorThread(poll_interval_sec=1.5)
        self.monitor_thread.device_inserted.connect(self._on_usb_inserted)
        self.monitor_thread.device_removed.connect(self._on_usb_removed)
        self.monitor_thread.devices_updated.connect(self._on_devices_updated)
        self.monitor_thread.status_message.connect(self._log_audit)
        self.monitor_thread.start()

        # Log system boot
        self._log_audit("USB Sentinel AI initialized. Hardware monitor active.")

    def _init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(14, 14, 14, 14)
        main_layout.setSpacing(10)

        # Top Hardware Sentinel Bar
        self._create_sentinel_bar(main_layout)

        # Main Tabs
        self.tabs = QTabWidget()
        self.tab_dashboard = QWidget()
        self.tab_forensics = QWidget()
        self.tab_timeline = QWidget()
        self.tab_chat = QWidget()
        self.tab_quarantine = QWidget()
        self.tab_settings = QWidget()

        self.tabs.addTab(self.tab_dashboard, "DASHBOARD")
        self.tabs.addTab(self.tab_forensics, "FORENSIC EXPLORER")
        self.tabs.addTab(self.tab_timeline, "MACB TIMELINE")
        self.tabs.addTab(self.tab_chat, "AI COPILOT")
        self.tabs.addTab(self.tab_quarantine, "QUARANTINE & REPORTS")
        self.tabs.addTab(self.tab_settings, "SETTINGS")

        main_layout.addWidget(self.tabs)

        # Setup Tab Contents
        self._setup_dashboard_tab()
        self._setup_forensics_tab()
        self._setup_timeline_tab()
        self._setup_chat_tab()
        self._setup_quarantine_tab()
        self._setup_settings_tab()

    # ==================== HARDWARE SENTINEL BAR ====================
    def _create_sentinel_bar(self, parent_layout):
        bar = QFrame()
        bar.setObjectName("Card")
        bar_layout = QHBoxLayout(bar)
        bar_layout.setContentsMargins(12, 8, 12, 8)

        # Pulsing Indicator
        self.status_led = QLabel("● SENTINEL ACTIVE")
        self.status_led.setStyleSheet("color: #10B981; font-weight: bold; font-size: 13px;")
        bar_layout.addWidget(self.status_led)

        bar_layout.addSpacing(15)

        # Device Selection / Status Label
        bar_layout.addWidget(QLabel("Target Device:"))
        self.device_combo = QComboBox()
        self.device_combo.setMinimumWidth(260)
        self.device_combo.currentIndexChanged.connect(self._on_device_selection_changed)
        bar_layout.addWidget(self.device_combo)

        btn_refresh = QPushButton("Refresh Drives")
        btn_refresh.clicked.connect(self._manual_refresh_devices)
        bar_layout.addWidget(btn_refresh)

        btn_browse = QPushButton("Select Drive/Folder...")
        btn_browse.clicked.connect(self._browse_custom_drive)
        bar_layout.addWidget(btn_browse)

        bar_layout.addStretch()

        # Scan Controls
        self.btn_scan = QPushButton("Start Full Scan")
        self.btn_scan.setObjectName("PrimaryBtn")
        self.btn_scan.clicked.connect(self.start_scan)
        bar_layout.addWidget(self.btn_scan)

        self.btn_cancel_scan = QPushButton("Cancel Scan")
        self.btn_cancel_scan.setObjectName("DangerBtn")
        self.btn_cancel_scan.setEnabled(False)
        self.btn_cancel_scan.clicked.connect(self.cancel_scan)
        bar_layout.addWidget(self.btn_cancel_scan)

        parent_layout.addWidget(bar)

    # ==================== TAB 1: DASHBOARD ====================
    def _setup_dashboard_tab(self):
        layout = QVBoxLayout(self.tab_dashboard)
        layout.setSpacing(12)

        # Top Device Information Card
        dev_card = QFrame()
        dev_card.setObjectName("Card")
        dev_layout = QHBoxLayout(dev_card)
        
        self.lbl_dev_name = QLabel("No Physical USB Drive Mounted")
        self.lbl_dev_name.setStyleSheet("font-size: 16px; font-weight: bold; color: #06B6D4;")
        
        self.lbl_dev_meta = QLabel("Mount: None | FS: N/A | Serial: N/A | Capacity: 0 GB")
        self.lbl_dev_meta.setStyleSheet("color: #94A3B8; font-size: 12px;")
        
        dev_info_vbox = QVBoxLayout()
        dev_info_vbox.addWidget(self.lbl_dev_name)
        dev_info_vbox.addWidget(self.lbl_dev_meta)
        dev_layout.addLayout(dev_info_vbox)
        dev_layout.addStretch()

        # Capacity Progress bar
        self.dev_capacity_bar = QProgressBar()
        self.dev_capacity_bar.setFixedWidth(240)
        self.dev_capacity_bar.setValue(0)
        self.dev_capacity_bar.setFormat("Storage: N/A")
        dev_layout.addWidget(self.dev_capacity_bar)

        layout.addWidget(dev_card)

        # Metrics Overview Row
        metrics_layout = QHBoxLayout()
        self.card_total = self._create_metric_card("Files Scanned", "0", "#38BDF8")
        self.card_clean = self._create_metric_card("Clean Files", "0", "#10B981")
        self.card_susp = self._create_metric_card("Suspicious Items", "0", "#F59E0B")
        self.card_mal = self._create_metric_card("Malicious Threats", "0", "#EF4444")
        self.card_quar = self._create_metric_card("Quarantined", "0", "#A855F7")

        metrics_layout.addWidget(self.card_total)
        metrics_layout.addWidget(self.card_clean)
        metrics_layout.addWidget(self.card_susp)
        metrics_layout.addWidget(self.card_mal)
        metrics_layout.addWidget(self.card_quar)
        layout.addLayout(metrics_layout)

        # Progress Section
        progress_card = QFrame()
        progress_card.setObjectName("Card")
        p_layout = QVBoxLayout(progress_card)
        
        self.lbl_current_file = QLabel("Ready for USB scan.")
        self.lbl_current_file.setStyleSheet("color: #94A3B8; font-size: 11px;")
        p_layout.addWidget(self.lbl_current_file)

        self.scan_progress_bar = QProgressBar()
        self.scan_progress_bar.setValue(0)
        p_layout.addWidget(self.scan_progress_bar)

        layout.addWidget(progress_card)

        # Live Audit & Forensic Activity Stream
        log_group = QGroupBox("LIVE FORENSIC AUDIT & EVENT LOG")
        log_vbox = QVBoxLayout(log_group)
        self.txt_audit_log = QTextEdit()
        self.txt_audit_log.setReadOnly(True)
        self.txt_audit_log.setStyleSheet("background-color: #070A10; font-family: 'Consolas', monospace; font-size: 12px;")
        log_vbox.addWidget(self.txt_audit_log)

        layout.addWidget(log_group)

    def _create_metric_card(self, title: str, value: str, color_hex: str) -> QFrame:
        card = QFrame()
        card.setObjectName("Card")
        vbox = QVBoxLayout(card)
        vbox.setContentsMargins(10, 8, 10, 8)
        lbl_title = QLabel(title)
        lbl_title.setStyleSheet("color: #94A3B8; font-size: 11px; font-weight: 600;")
        lbl_val = QLabel(value)
        lbl_val.setStyleSheet(f"color: {color_hex}; font-size: 24px; font-weight: bold;")
        vbox.addWidget(lbl_title)
        vbox.addWidget(lbl_val)
        card.value_label = lbl_val
        return card

    # ==================== TAB 2: FORENSIC EXPLORER ====================
    def _setup_forensics_tab(self):
        layout = QVBoxLayout(self.tab_forensics)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: Interactive File Tree / Table
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)

        filter_row = QHBoxLayout()
        self.txt_search_files = QLineEdit()
        self.txt_search_files.setPlaceholderText("Filter files by name or extension...")
        self.txt_search_files.textChanged.connect(self._filter_forensic_tree)
        filter_row.addWidget(self.txt_search_files)

        self.combo_risk_filter = QComboBox()
        self.combo_risk_filter.addItems(["All Files", "Threats Only (Suspicious/Malicious)", "Malicious Only", "Clean Only"])
        self.combo_risk_filter.currentIndexChanged.connect(self._filter_forensic_tree)
        filter_row.addWidget(self.combo_risk_filter)
        left_layout.addLayout(filter_row)

        self.tree_files = QTreeWidget()
        self.tree_files.setHeaderLabels(["Filename", "Risk Level", "Score", "Entropy", "Magic / Header", "Size", "Path"])
        self.tree_files.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.tree_files.header().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.tree_files.header().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self.tree_files.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree_files.customContextMenuRequested.connect(self._show_file_context_menu)
        self.tree_files.itemClicked.connect(self._on_file_selected)
        left_layout.addWidget(self.tree_files)

        splitter.addWidget(left_widget)

        # Right: Deep Forensic Inspector Panel
        right_scroll = QScrollArea()
        right_scroll.setWidgetResizable(True)
        right_content = QWidget()
        right_layout = QVBoxLayout(right_content)
        right_layout.setSpacing(10)

        # File Overview Card
        card_inspect = QGroupBox("FILE METADATA & CRYPTOGRAPHIC INTEGRITY")
        v_ins = QVBoxLayout(card_inspect)
        self.lbl_inspect_name = QLabel("No file selected")
        self.lbl_inspect_name.setStyleSheet("font-size: 14px; font-weight: bold; color: #06B6D4;")
        v_ins.addWidget(self.lbl_inspect_name)

        self.lbl_inspect_path = QLabel("Select an item from the tree to inspect.")
        self.lbl_inspect_path.setWordWrap(True)
        self.lbl_inspect_path.setStyleSheet("color: #94A3B8; font-size: 11px;")
        v_ins.addWidget(self.lbl_inspect_path)

        # Hashes
        hash_box = QVBoxLayout()
        self.lbl_sha256 = QLineEdit()
        self.lbl_sha256.setReadOnly(True)
        self.lbl_sha256.setPlaceholderText("SHA-256 Hash")
        self.lbl_md5 = QLineEdit()
        self.lbl_md5.setReadOnly(True)
        self.lbl_md5.setPlaceholderText("MD5 Hash")
        hash_box.addWidget(QLabel("SHA-256:"))
        hash_box.addWidget(self.lbl_sha256)
        hash_box.addWidget(QLabel("MD5:"))
        hash_box.addWidget(self.lbl_md5)
        v_ins.addLayout(hash_box)

        # Entropy Progress Bar
        v_ins.addWidget(QLabel("Shannon Entropy (0.0 - 8.0):"))
        self.entropy_bar = QProgressBar()
        self.entropy_bar.setRange(0, 800)
        self.entropy_bar.setValue(0)
        self.entropy_bar.setFormat("Entropy: 0.0")
        v_ins.addWidget(self.entropy_bar)

        right_layout.addWidget(card_inspect)

        # Extracted Strings & Obfuscation Matches
        box_strings = QGroupBox("EXTRACTED STRINGS & SUSPICIOUS PATTERNS")
        v_str = QVBoxLayout(box_strings)
        self.txt_strings = QTextEdit()
        self.txt_strings.setReadOnly(True)
        self.txt_strings.setMaximumHeight(150)
        self.txt_strings.setStyleSheet("background-color: #070A10; font-family: 'Consolas', monospace; font-size: 11px;")
        v_str.addWidget(self.txt_strings)
        right_layout.addWidget(box_strings)

        # AI Threat Intelligence Verdict Card
        self.box_ai = QGroupBox("GROQ AI DEEP THREAT INTELLIGENCE")
        v_ai = QVBoxLayout(self.box_ai)
        self.lbl_ai_verdict = QLabel("Verdict: Unchecked")
        self.lbl_ai_verdict.setStyleSheet("font-weight: bold; font-size: 13px; color: #94A3B8;")
        v_ai.addWidget(self.lbl_ai_verdict)

        self.txt_ai_summary = QTextEdit()
        self.txt_ai_summary.setReadOnly(True)
        self.txt_ai_summary.setPlaceholderText("Click 'Analyze with Groq AI' to evaluate de-obfuscation and MITRE ATT&CK mapping...")
        self.txt_ai_summary.setMaximumHeight(160)
        v_ai.addWidget(self.txt_ai_summary)

        # Inspector Action Buttons
        btn_row = QHBoxLayout()
        self.btn_ai_inspect = QPushButton("Deep AI Analysis (Groq)")
        self.btn_ai_inspect.setObjectName("PrimaryBtn")
        self.btn_ai_inspect.clicked.connect(self._inspect_current_file_with_ai)
        btn_row.addWidget(self.btn_ai_inspect)

        self.btn_quar_file = QPushButton("Quarantine File")
        self.btn_quar_file.setObjectName("DangerBtn")
        self.btn_quar_file.clicked.connect(self._quarantine_current_file)
        btn_row.addWidget(self.btn_quar_file)
        v_ai.addLayout(btn_row)

        right_layout.addWidget(self.box_ai)
        right_layout.addStretch()

        right_scroll.setWidget(right_content)
        splitter.addWidget(right_scroll)
        splitter.setStretchFactor(0, 6)
        splitter.setStretchFactor(1, 4)

        layout.addWidget(splitter)

    # ==================== TAB 3: MACB TIMELINE ====================
    def _setup_timeline_tab(self):
        layout = QVBoxLayout(self.tab_timeline)
        
        info_banner = QLabel("Chronological MACB (Modified, Accessed, Created) Event Timeline extracted dynamically from physical drive filesystem.")
        info_banner.setStyleSheet("color: #94A3B8; font-size: 12px; margin-bottom: 6px;")
        layout.addWidget(info_banner)

        self.table_timeline = QTableWidget()
        self.table_timeline.setColumnCount(6)
        self.table_timeline.setHorizontalHeaderLabels(["Timestamp", "Event Type", "Filename", "Risk Level", "Threat Score", "Full Path"])
        self.table_timeline.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_timeline.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table_timeline.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table_timeline.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table_timeline)

    # ==================== TAB 4: AI COPILOT & INTENT CHAT ====================
    def _setup_chat_tab(self):
        layout = QVBoxLayout(self.tab_chat)
        layout.setSpacing(10)

        # Suggestion Chips
        chips_frame = QFrame()
        chips_frame.setObjectName("Card")
        chips_layout = QHBoxLayout(chips_frame)
        chips_layout.setContentsMargins(12, 8, 12, 8)
        chips_layout.setSpacing(10)
        
        lbl_prompts = QLabel("Forensic Prompts:")
        lbl_prompts.setStyleSheet("color: #94A3B8; font-weight: 600; font-size: 12px;")
        chips_layout.addWidget(lbl_prompts)

        chip1 = QPushButton("Quarantine all double-extensions")
        chip1.clicked.connect(lambda: self._send_chat_message("Quarantine all double-extension files found on the USB."))
        
        chip3 = QPushButton("Generate forensic summary")
        chip3.clicked.connect(lambda: self._send_chat_message("Generate an executive forensic summary of this USB session."))
        
        chip4 = QPushButton("Export PDF report")
        chip4.clicked.connect(lambda: self._send_chat_message("Export the official forensic PDF report."))

        chips_layout.addWidget(chip1)
        chips_layout.addWidget(chip3)
        chips_layout.addWidget(chip4)
        chips_layout.addStretch()
        layout.addWidget(chips_frame)

        # Chat History
        self.txt_chat_history = QTextEdit()
        self.txt_chat_history.setReadOnly(True)
        self.txt_chat_history.setStyleSheet("background-color: #070A10; font-size: 13px; line-height: 1.4;")
        layout.addWidget(self.txt_chat_history)

        # Input Row
        input_row = QHBoxLayout()
        self.txt_chat_input = QLineEdit()
        self.txt_chat_input.setPlaceholderText("Ask Groq AI or type natural language forensic command (e.g. 'Quarantine file E:\\payload.vbs')...")
        self.txt_chat_input.returnPressed.connect(self._handle_chat_submit)
        input_row.addWidget(self.txt_chat_input)

        self.btn_send_chat = QPushButton("Send Intent")
        self.btn_send_chat.setObjectName("PrimaryBtn")
        self.btn_send_chat.clicked.connect(self._handle_chat_submit)
        input_row.addWidget(self.btn_send_chat)

        layout.addLayout(input_row)

        # Initial Welcome Message
        self._append_chat_message("USB Sentinel AI", (
            "Forensics Copilot online. I am connected directly to your physical USB session. "
            "You can ask me to inspect artifacts, de-obfuscate payloads, quarantine malicious files, "
            "or generate forensic evidence reports."
        ), is_system=True)

    # ==================== TAB 5: QUARANTINE & REPORTS ====================
    def _setup_quarantine_tab(self):
        layout = QVBoxLayout(self.tab_quarantine)
        layout.setSpacing(12)

        # Top Vault Summary Bar
        top_bar = QFrame()
        top_bar.setObjectName("Card")
        top_layout = QHBoxLayout(top_bar)
        
        self.lbl_quar_stats = QLabel("Quarantine Vault: 0 files locked & encrypted")
        self.lbl_quar_stats.setStyleSheet("font-weight: bold; color: #A855F7;")
        top_layout.addWidget(self.lbl_quar_stats)
        top_layout.addStretch()

        btn_open_vault = QPushButton("Open Vault Directory")
        btn_open_vault.clicked.connect(self._open_vault_folder)
        top_layout.addWidget(btn_open_vault)

        btn_export_pdf = QPushButton("Export Forensic PDF Report")
        btn_export_pdf.setObjectName("PrimaryBtn")
        btn_export_pdf.clicked.connect(self.export_pdf_dialog)
        top_layout.addWidget(btn_export_pdf)

        layout.addWidget(top_bar)

        # Quarantined Files Table
        self.table_quarantine = QTableWidget()
        self.table_quarantine.setColumnCount(6)
        self.table_quarantine.setHorizontalHeaderLabels(["Quarantine ID", "Original Filename", "Original Path", "SHA-256", "Quarantine Date", "Reason"])
        self.table_quarantine.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table_quarantine.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table_quarantine)

        # Vault Controls
        btn_vault_row = QHBoxLayout()
        btn_restore = QPushButton("Restore Selected File")
        btn_restore.setObjectName("SuccessBtn")
        btn_restore.clicked.connect(self._restore_selected_quarantine)
        btn_vault_row.addWidget(btn_restore)

        btn_purge = QPushButton("Permanently Delete File")
        btn_purge.setObjectName("DangerBtn")
        btn_purge.clicked.connect(self._purge_selected_quarantine)
        btn_vault_row.addWidget(btn_purge)

        btn_refresh_q = QPushButton("Refresh Vault")
        btn_refresh_q.clicked.connect(self._refresh_quarantine_table)
        btn_vault_row.addWidget(btn_refresh_q)

        btn_vault_row.addStretch()
        layout.addLayout(btn_vault_row)

        self._refresh_quarantine_table()

    # ==================== TAB 6: SETTINGS ====================
    def _setup_settings_tab(self):
        layout = QVBoxLayout(self.tab_settings)
        layout.setSpacing(14)

        group_groq = QGroupBox("GROQ AI CONFIGURATION")
        g_layout = QVBoxLayout(group_groq)

        g_layout.addWidget(QLabel("Groq API Key:"))
        self.txt_api_key = QLineEdit(self.analyzer.api_key)
        self.txt_api_key.setEchoMode(QLineEdit.EchoMode.Password)
        g_layout.addWidget(self.txt_api_key)

        btn_toggle_key = QPushButton("Show / Hide Key")
        btn_toggle_key.clicked.connect(self._toggle_key_visibility)
        g_layout.addWidget(btn_toggle_key)

        g_layout.addWidget(QLabel("Primary Model:"))
        self.combo_model = QComboBox()
        self.combo_model.setEditable(True)
        models_list = self.analyzer.get_available_models()
        self.combo_model.addItems(models_list)
        self.combo_model.setCurrentText(self.analyzer.model if self.analyzer.model in models_list else models_list[0])
        g_layout.addWidget(self.combo_model)

        btn_test_api = QPushButton("Test Groq Connection & Refresh Models")
        btn_test_api.clicked.connect(self._test_groq_settings)
        g_layout.addWidget(btn_test_api)

        layout.addWidget(group_groq)

        # Heuristic Thresholds
        group_heur = QGroupBox("HEURISTIC & FORENSIC SCANNER SETTINGS")
        h_layout = QVBoxLayout(group_heur)

        self.chk_auto_scan = QCheckBox("Automatically launch full scan upon physical USB insertion")
        self.chk_auto_scan.setChecked(True)
        h_layout.addWidget(self.chk_auto_scan)

        h_layout.addWidget(QLabel("Shannon Entropy Suspicious Threshold (default 7.20):"))
        self.spin_entropy = QSpinBox()
        self.spin_entropy.setRange(500, 800)
        self.spin_entropy.setValue(720)
        self.spin_entropy.setSuffix(" / 8.00")
        h_layout.addWidget(self.spin_entropy)

        layout.addWidget(group_heur)

        # Save Button
        btn_save = QPushButton("Save Settings")
        btn_save.setObjectName("PrimaryBtn")
        btn_save.clicked.connect(self._save_settings)
        layout.addWidget(btn_save)

        layout.addStretch()

    # ==================== HARDWARE & DRIVE EVENTS ====================
    def _on_usb_inserted(self, device: USBDevice):
        self._log_audit(f"USB INSERTION DETECTED: {device.device_name} mounted at {device.mount_point}")
        self._manual_refresh_devices()
        
        # Select newly inserted device
        idx = self.device_combo.findData(device.mount_point)
        if idx >= 0:
            self.device_combo.setCurrentIndex(idx)

        # Trigger auto scan if enabled
        if self.chk_auto_scan.isChecked():
            self.start_scan()

    def _on_usb_removed(self, mount_point: str):
        self._log_audit(f"USB REMOVAL DETECTED: Drive {mount_point} disconnected.")
        self._manual_refresh_devices()

    def _on_devices_updated(self, devices: list[USBDevice]):
        self.all_connected_devices = devices
        current_data = self.device_combo.currentData()
        self.device_combo.blockSignals(True)
        self.device_combo.clear()
        
        for dev in devices:
            text = f"{dev.device_name} ({dev.file_system}) [{dev.mount_point}]"
            self.device_combo.addItem(text, dev.mount_point)

        # Restore selection if still present
        if current_data:
            idx = self.device_combo.findData(current_data)
            if idx >= 0:
                self.device_combo.setCurrentIndex(idx)
        self.device_combo.blockSignals(False)

        if devices and self.device_combo.currentIndex() >= 0:
            self._on_device_selection_changed(self.device_combo.currentIndex())
        elif not devices:
            self.current_usb_device = None
            self.lbl_dev_name.setText("No Physical USB Drive Mounted")
            self.lbl_dev_meta.setText("Mount: None | FS: N/A | Serial: N/A | Capacity: 0 GB")
            self.dev_capacity_bar.setValue(0)
            self.dev_capacity_bar.setFormat("Storage: N/A")

    def _manual_refresh_devices(self):
        devices = query_all_removable_drives()
        self._on_devices_updated(devices)

    def _browse_custom_drive(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Physical USB Drive Root or Directory")
        if folder:
            clean = os.path.abspath(folder)
            dev = USBDevice(
                mount_point=clean,
                device_name=f"Manual Target ({os.path.basename(clean) or clean})",
                volume_label="User Selected Volume",
                file_system="Auto",
                serial_number="N/A",
                total_bytes=shutil.disk_usage(clean).total,
                free_bytes=shutil.disk_usage(clean).free,
                is_removable=True
            )
            self.all_connected_devices.append(dev)
            self.device_combo.addItem(f"{dev.device_name} [{dev.mount_point}]", dev.mount_point)
            self.device_combo.setCurrentIndex(self.device_combo.count() - 1)
            self._log_audit(f"Manual scan target selected: {clean}")

    def _on_device_selection_changed(self, index: int):
        if index < 0:
            return
        mount_point = self.device_combo.currentData()
        dev = next((d for d in self.all_connected_devices if d.mount_point == mount_point), None)
        if dev:
            self.current_usb_device = dev
            self.lbl_dev_name.setText(dev.device_name)
            total_gb = round(dev.total_bytes / (1024**3), 2)
            free_gb = round(dev.free_bytes / (1024**3), 2)
            used_gb = round(total_gb - free_gb, 2)
            self.lbl_dev_meta.setText(f"Mount: {dev.mount_point} | FS: {dev.file_system} | Serial: {dev.serial_number} | {used_gb} GB used of {total_gb} GB")
            
            pct = int((used_gb / total_gb * 100)) if total_gb > 0 else 0
            self.dev_capacity_bar.setValue(pct)
            self.dev_capacity_bar.setFormat(f"{used_gb} GB / {total_gb} GB ({pct}%)")

    # ==================== HEURISTIC SCANNER CONTROL ====================
    def start_scan(self):
        if not self.current_usb_device:
            QMessageBox.warning(self, "No Device", "Please insert a physical USB drive or select a volume to scan.")
            return

        target_path = self.current_usb_device.mount_point
        if not os.path.exists(target_path):
            QMessageBox.critical(self, "Path Invalid", f"The drive path {target_path} is not accessible.")
            return

        # Reset states
        self.scan_results.clear()
        self.tree_files.clear()
        self.table_timeline.setRowCount(0)
        self.btn_scan.setEnabled(False)
        self.btn_cancel_scan.setEnabled(True)
        self.scan_progress_bar.setValue(0)
        self.lbl_current_file.setText(f"Initiating full forensic scan on {target_path}...")
        self._log_audit(f"SCAN STARTED: Volume {target_path}")

        entropy_thresh = float(self.spin_entropy.value()) / 100.0

        # Start Worker Thread
        self.scanner_worker = ScannerWorker(target_path, entropy_threshold=entropy_thresh)
        self.scanner_worker.progress.connect(self._on_scan_progress)
        self.scanner_worker.file_scanned.connect(self._on_file_scanned)
        self.scanner_worker.scan_finished.connect(self._on_scan_finished)
        self.scanner_worker.scan_error.connect(self._on_scan_error)
        self.scanner_worker.start()

    def cancel_scan(self):
        if self.scanner_worker:
            self.scanner_worker.cancel()
            self._log_audit("Scan cancellation requested by investigator.")
            self.lbl_current_file.setText("Scan cancelled.")
            self.btn_cancel_scan.setEnabled(False)
            self.btn_scan.setEnabled(True)

    def _on_scan_progress(self, current: int, total: int, current_path: str):
        pct = int(current / total * 100) if total > 0 else 0
        self.scan_progress_bar.setValue(pct)
        self.lbl_current_file.setText(f"[{current}/{total}] Scanning: {current_path}")

    def _on_file_scanned(self, res: dict):
        self.scan_results.append(res)
        self._add_to_forensic_tree(res)
        self._add_to_timeline_table(res)

        # Update metric labels in real time
        mal_count = sum(1 for r in self.scan_results if r["risk_level"] == "MALICIOUS")
        susp_count = sum(1 for r in self.scan_results if r["risk_level"] == "SUSPICIOUS")
        clean_count = sum(1 for r in self.scan_results if r["risk_level"] == "CLEAN")

        self.card_total.value_label.setText(str(len(self.scan_results)))
        self.card_clean.value_label.setText(str(clean_count))
        self.card_susp.value_label.setText(str(susp_count))
        self.card_mal.value_label.setText(str(mal_count))

        if res["risk_level"] == "MALICIOUS":
            self._log_audit(f"[ALERT] MALICIOUS FILE DETECTED: {res['name']} ({', '.join(res['rules_triggered'])})")

    def _on_scan_finished(self, results: list, summary: dict):
        self.scan_summary = summary
        self.btn_scan.setEnabled(True)
        self.btn_cancel_scan.setEnabled(False)
        self.scan_progress_bar.setValue(100)
        self.lbl_current_file.setText(f"Scan Completed: {summary['total_scanned']} files evaluated.")
        self._log_audit(
            f"SCAN COMPLETED: {summary['total_scanned']} files scanned. "
            f"Malicious: {summary['malicious']}, Suspicious: {summary['suspicious']}, Clean: {summary['clean']}"
        )

    def _on_scan_error(self, err: str):
        self.btn_scan.setEnabled(True)
        self.btn_cancel_scan.setEnabled(False)
        self.lbl_current_file.setText(f"Scan error: {err}")
        self._log_audit(f"SCAN ERROR: {err}")
        QMessageBox.critical(self, "Scan Failure", err)

    # ==================== FORENSIC EXPLORER & TREE ====================
    def _add_to_forensic_tree(self, res: dict):
        item = QTreeWidgetItem(self.tree_files)
        item.setText(0, res["name"])
        item.setText(1, res["risk_level"])
        item.setText(2, str(res["threat_score"]))
        item.setText(3, f"{res['entropy']:.2f}")
        item.setText(4, res["magic_desc"])
        item.setText(5, f"{res['size_bytes']:,} B")
        item.setText(6, res["path"])
        item.setData(0, Qt.ItemDataRole.UserRole, res)

        # Risk-based coloring
        if res["risk_level"] == "MALICIOUS":
            item.setForeground(0, QBrush(QColor("#EF4444")))
            item.setForeground(1, QBrush(QColor("#EF4444")))
            item.setIcon(0, self.style().standardIcon(self.style().StandardPixmap.SP_MessageBoxCritical))
        elif res["risk_level"] == "SUSPICIOUS":
            item.setForeground(0, QBrush(QColor("#F59E0B")))
            item.setForeground(1, QBrush(QColor("#F59E0B")))
            item.setIcon(0, self.style().standardIcon(self.style().StandardPixmap.SP_MessageBoxWarning))
        else:
            item.setForeground(0, QBrush(QColor("#10B981")))
            item.setForeground(1, QBrush(QColor("#10B981")))
            item.setIcon(0, self.style().standardIcon(self.style().StandardPixmap.SP_FileIcon))

    def _filter_forensic_tree(self):
        query = self.txt_search_files.text().lower()
        filter_mode = self.combo_risk_filter.currentText()

        root = self.tree_files.invisibleRootItem()
        for i in range(root.childCount()):
            item = root.child(i)
            res = item.data(0, Qt.ItemDataRole.UserRole)
            if not res:
                continue

            matches_text = query in res["name"].lower() or query in res["path"].lower() or query in res["extension"].lower()
            
            matches_risk = True
            if "Threats Only" in filter_mode:
                matches_risk = res["risk_level"] in ["SUSPICIOUS", "MALICIOUS"]
            elif "Malicious Only" in filter_mode:
                matches_risk = res["risk_level"] == "MALICIOUS"
            elif "Clean Only" in filter_mode:
                matches_risk = res["risk_level"] == "CLEAN"

            item.setHidden(not (matches_text and matches_risk))

    def _on_file_selected(self, item: QTreeWidgetItem, column: int):
        res = item.data(0, Qt.ItemDataRole.UserRole)
        if not res:
            return

        self.lbl_inspect_name.setText(res["name"])
        self.lbl_inspect_path.setText(f"Path: {res['path']}\nSize: {res['size_bytes']:,} Bytes | Hidden: {res['is_hidden']}")
        self.lbl_sha256.setText(res["sha256"])
        self.lbl_md5.setText(res["md5"])

        # Entropy meter
        ent_val = int(res["entropy"] * 100)
        self.entropy_bar.setValue(ent_val)
        self.entropy_bar.setFormat(f"Entropy: {res['entropy']:.2f} / 8.0")
        if res["entropy"] >= 7.2:
            self.entropy_bar.setStyleSheet("QProgressBar::chunk { background-color: #EF4444; }")
        elif res["entropy"] >= 6.0:
            self.entropy_bar.setStyleSheet("QProgressBar::chunk { background-color: #F59E0B; }")
        else:
            self.entropy_bar.setStyleSheet("QProgressBar::chunk { background-color: #10B981; }")

        # Extracted Strings & Indicators
        details = []
        if res.get("rules_triggered"):
            details.append("--- TRIGGERED HEURISTIC RULES ---")
            for r in res["rules_triggered"]:
                details.append(f"  • {r}")
            details.append("")

        matched = res.get("matched_indicators", {})
        if matched.get("powershell"):
            details.append(f"PowerShell Flags: {', '.join(matched['powershell'])}")
        if matched.get("urls"):
            details.append(f"Hardcoded URLs: {', '.join(matched['urls'])}")
        if matched.get("ips"):
            details.append(f"Hardcoded IPs: {', '.join(matched['ips'])}")
        if matched.get("cmd_inject"):
            details.append(f"Command Injection: {', '.join(matched['cmd_inject'])}")

        if res.get("extracted_strings_sample"):
            details.append("\n--- EXTRACTED STRINGS SAMPLE ---")
            details.extend(res["extracted_strings_sample"][:25])

        self.txt_strings.setPlainText("\n".join(details))

        # Check cached AI insight
        if res["path"] in self.ai_insights_cache:
            ai = self.ai_insights_cache[res["path"]]
            self._display_ai_result(ai)
        else:
            self.lbl_ai_verdict.setText(f"Verdict: Local Score {res['threat_score']}/100 ({res['risk_level']})")
            self.lbl_ai_verdict.setStyleSheet("color: #94A3B8; font-weight: bold;")
            self.txt_ai_summary.clear()

    def _show_file_context_menu(self, position):
        item = self.tree_files.itemAt(position)
        if not item:
            return
        res = item.data(0, Qt.ItemDataRole.UserRole)
        if not res:
            return

        menu = QMenu(self)
        act_ai = menu.addAction("Analyze with Groq AI")
        act_quar = menu.addAction("Quarantine File to Vault")
        menu.addSeparator()
        act_entropy = menu.addAction("Calculate Entropy Details")
        act_hash = menu.addAction("Copy SHA-256 Hash")
        act_path = menu.addAction("Copy File Path")
        act_explore = menu.addAction("Open in Windows Explorer")

        action = menu.exec(self.tree_files.viewport().mapToGlobal(position))
        if action == act_ai:
            self._analyze_file_with_ai(res)
        elif action == act_quar:
            self._quarantine_file_path(res["path"], reason=", ".join(res.get("rules_triggered", ["Manual Quarantine"])))
        elif action == act_entropy:
            QMessageBox.information(
                self, "Entropy Breakdown",
                f"File: {res['name']}\nShannon Entropy: {res['entropy']:.4f}\n"
                f"Classification: {'Packed/Encrypted (High Risk)' if res['entropy'] >= 7.2 else 'Standard Distribution'}"
            )
        elif action == act_hash:
            QApplication.clipboard().setText(res["sha256"])
            self._log_audit(f"Copied SHA-256 for {res['name']}")
        elif action == act_path:
            QApplication.clipboard().setText(res["path"])
        elif action == act_explore:
            p = os.path.dirname(res["path"])
            if os.path.exists(p):
                os.startfile(p)

    def _inspect_current_file_with_ai(self):
        item = self.tree_files.currentItem()
        if not item:
            QMessageBox.information(self, "Select File", "Please select a file from the explorer tree first.")
            return
        res = item.data(0, Qt.ItemDataRole.UserRole)
        if res:
            self._analyze_file_with_ai(res)

    def _analyze_file_with_ai(self, file_data: dict):
        self.lbl_ai_verdict.setText(f"Analyzing with Groq AI ({self.analyzer.model})...")
        self.lbl_ai_verdict.setStyleSheet("color: #06B6D4; font-weight: bold;")
        self.txt_ai_summary.setPlainText("Querying Groq LLM Threat Intelligence Engine...")
        self.btn_ai_inspect.setEnabled(False)

        self.groq_worker = GroqAsyncWorker(self.analyzer, mode="deep_analysis", file_data=file_data)
        self.groq_worker.analysis_completed.connect(lambda ai_res: self._on_ai_analysis_done(file_data["path"], ai_res))
        self.groq_worker.error_occurred.connect(self._on_ai_error)
        self.groq_worker.start()

    def _on_ai_analysis_done(self, file_path: str, ai_result: dict):
        self.btn_ai_inspect.setEnabled(True)
        self.ai_insights_cache[file_path] = ai_result
        self._display_ai_result(ai_result)
        self._log_audit(f"AI ANALYSIS COMPLETE for {os.path.basename(file_path)}: Verdict={ai_result.get('threat_verdict')}, Score={ai_result.get('threat_score')}")

    def _display_ai_result(self, ai: dict):
        verdict = ai.get("threat_verdict", "Unknown")
        score = ai.get("threat_score", 0)
        cat = ai.get("malware_category", "N/A")
        mitre = ", ".join(ai.get("mitre_att_ck", [])) or "None"
        summary = ai.get("deobfuscated_summary", "")
        action = ai.get("recommended_action", "Allow")

        color = "#EF4444" if verdict in ["Malicious", "High Risk"] else ("#F59E0B" if verdict == "Suspicious" else "#10B981")
        self.lbl_ai_verdict.setText(f"AI Verdict: {verdict.upper()} ({score}/100) — {cat}")
        self.lbl_ai_verdict.setStyleSheet(f"color: {color}; font-weight: bold; font-size: 13px;")

        report_txt = (
            f"RECOMMENDED ACTION: {action}\n"
            f"MITRE ATT&CK: {mitre}\n\n"
            f"DE-OBFUSCATION & INTENT ANALYSIS:\n{summary}"
        )
        self.txt_ai_summary.setPlainText(report_txt)

    def _on_ai_error(self, err: str):
        self.btn_ai_inspect.setEnabled(True)
        self.lbl_ai_verdict.setText("AI Analysis Encountered Error")
        self.lbl_ai_verdict.setStyleSheet("color: #EF4444; font-weight: bold;")
        self.txt_ai_summary.setPlainText(f"Error: {err}")
        self._log_audit(f"AI ERROR: {err}")

    # ==================== MACB TIMELINE VIEWER ====================
    def _add_to_timeline_table(self, res: dict):
        macb = res.get("macb", {})
        row = self.table_timeline.rowCount()
        self.table_timeline.insertRow(row)

        t_modified = macb.get("modified", "N/A")
        self.table_timeline.setItem(row, 0, QTableWidgetItem(t_modified))
        self.table_timeline.setItem(row, 1, QTableWidgetItem("Modified / Written"))
        self.table_timeline.setItem(row, 2, QTableWidgetItem(res["name"]))
        
        item_risk = QTableWidgetItem(res["risk_level"])
        if res["risk_level"] == "MALICIOUS":
            item_risk.setForeground(QBrush(QColor("#EF4444")))
        elif res["risk_level"] == "SUSPICIOUS":
            item_risk.setForeground(QBrush(QColor("#F59E0B")))
        else:
            item_risk.setForeground(QBrush(QColor("#10B981")))

        self.table_timeline.setItem(row, 3, item_risk)
        self.table_timeline.setItem(row, 4, QTableWidgetItem(str(res["threat_score"])))
        self.table_timeline.setItem(row, 5, QTableWidgetItem(res["path"]))

    # ==================== QUARANTINE OPERATIONS ====================
    def _quarantine_current_file(self):
        item = self.tree_files.currentItem()
        if not item:
            QMessageBox.information(self, "Select File", "Please select a file to quarantine.")
            return
        res = item.data(0, Qt.ItemDataRole.UserRole)
        if res:
            self._quarantine_file_path(res["path"], reason=", ".join(res.get("rules_triggered", ["Investigator Quarantine"])))

    def _quarantine_file_path(self, file_path: str, reason: str = "Forensic Threat Remediation"):
        reply = QMessageBox.question(
            self, "Confirm Quarantine",
            f"Are you sure you want to encrypt and move this file into the secure vault?\n\n{file_path}\n\n"
            "The file will be safely removed from the physical USB drive.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            record = self.vault.quarantine_file(file_path, reason=reason)
            self._log_audit(f"QUARANTINED: {file_path} -> Vault ID {record['id']}")
            QMessageBox.information(self, "File Quarantined", f"Successfully encrypted and locked {record['original_name']} in the Quarantine Vault.")
            self._refresh_quarantine_table()
            
            # Update metric
            q_count = len(self.vault.list_quarantined())
            self.card_quar.value_label.setText(str(q_count))

        except Exception as e:
            QMessageBox.critical(self, "Quarantine Failed", f"Could not quarantine file: {str(e)}")
            self._log_audit(f"QUARANTINE ERROR for {file_path}: {e}")

    def _refresh_quarantine_table(self):
        records = self.vault.list_quarantined()
        self.table_quarantine.setRowCount(0)
        for r in records:
            row = self.table_quarantine.rowCount()
            self.table_quarantine.insertRow(row)
            self.table_quarantine.setItem(row, 0, QTableWidgetItem(r["id"]))
            self.table_quarantine.setItem(row, 1, QTableWidgetItem(r.get("original_name", "")))
            self.table_quarantine.setItem(row, 2, QTableWidgetItem(r.get("original_path", "")))
            self.table_quarantine.setItem(row, 3, QTableWidgetItem(r.get("sha256", "")[:16] + "..."))
            self.table_quarantine.setItem(row, 4, QTableWidgetItem(r.get("timestamp", "")))
            self.table_quarantine.setItem(row, 5, QTableWidgetItem(r.get("reason", "")))

        self.lbl_quar_stats.setText(f"Quarantine Vault: {len(records)} files securely encrypted and isolated.")
        self.card_quar.value_label.setText(str(len(records)))

    def _restore_selected_quarantine(self):
        row = self.table_quarantine.currentRow()
        if row < 0:
            QMessageBox.information(self, "Select File", "Please select a quarantined file to restore.")
            return

        q_id = self.table_quarantine.item(row, 0).text()
        dest_dir = QFileDialog.getExistingDirectory(self, "Select Restore Destination Directory")
        if not dest_dir:
            return

        try:
            restored_path = self.vault.restore_file(q_id, destination_dir=dest_dir)
            self._log_audit(f"RESTORED: {q_id} restored to {restored_path}")
            QMessageBox.information(self, "File Restored", f"File restored successfully to:\n{restored_path}")
            self._refresh_quarantine_table()
        except Exception as e:
            QMessageBox.critical(self, "Restore Error", str(e))

    def _purge_selected_quarantine(self):
        row = self.table_quarantine.currentRow()
        if row < 0:
            return
        q_id = self.table_quarantine.item(row, 0).text()
        reply = QMessageBox.question(
            self, "Purge File",
            f"Permanently delete {q_id} from the vault? This action cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.vault.delete_permanently(q_id)
            self._log_audit(f"PURGED: {q_id} permanently erased.")
            self._refresh_quarantine_table()

    def _open_vault_folder(self):
        p = str(self.vault.vault_dir)
        if os.path.exists(p):
            os.startfile(p)

    # ==================== AI COPILOT & TOOL CALLING ====================
    def _send_chat_message(self, message: str):
        self.txt_chat_input.setText(message)
        self._handle_chat_submit()

    def _handle_chat_submit(self):
        text = self.txt_chat_input.text().strip()
        if not text:
            return
        self.txt_chat_input.clear()
        self._append_chat_message("Investigator", text)

        # Build compact context (cap at top 8 highest-threat files to stay strictly under Groq token rate limits)
        flagged = [r for r in self.scan_results if r.get("risk_level") in ["SUSPICIOUS", "MALICIOUS"]]
        flagged.sort(key=lambda x: x.get("threat_score", 0), reverse=True)
        top_suspicious = [
            {
                "name": r.get("name"),
                "path": r.get("path"),
                "threat_score": r.get("threat_score", 0),
                "rules": r.get("rules_triggered", [])[:2]
            }
            for r in flagged[:8]
        ]

        context = {
            "device_name": self.current_usb_device.device_name if self.current_usb_device else "USB Drive",
            "mount_point": self.current_usb_device.mount_point if self.current_usb_device else "E:\\",
            "total_files_scanned": len(self.scan_results),
            "threat_summary": self.scan_summary,
            "suspicious_files": top_suspicious
        }

        # Background Groq Chat Thread
        self.btn_send_chat.setEnabled(False)
        self.groq_worker = GroqAsyncWorker(
            self.analyzer,
            mode="chat",
            message=text,
            history=self.chat_history,
            context=context,
            tool_executor=self._execute_tool_action
        )
        self.groq_worker.chat_completed.connect(self._on_chat_response)
        self.groq_worker.error_occurred.connect(self._on_chat_error)
        self.groq_worker.start()

    def _execute_tool_action(self, tool_name: str, args: dict) -> dict:
        """
        Executes real backend tools dynamically on physical USB drive as commanded by Groq AI.
        """
        self._log_audit(f"AI COPILOT INVOKED TOOL: {tool_name} with args {args}")

        if tool_name == "quarantine_file":
            path = args.get("file_path", "")
            try:
                rec = self.vault.quarantine_file(path, reason=args.get("reason", "AI Autonomous Quarantine"))
                self._refresh_quarantine_table()
                return {"status": "success", "message": f"File {rec['original_name']} successfully quarantined.", "vault_id": rec["id"]}
            except Exception as e:
                return {"status": "error", "error": str(e)}

        elif tool_name == "quarantine_matching":
            criteria = args.get("criteria", "all_threats")
            quarantined = []
            for r in list(self.scan_results):
                match = False
                if criteria == "double_extension" and any("Double Extension" in rule for rule in r.get("rules_triggered", [])):
                    match = True
                elif criteria == "high_entropy" and r.get("entropy", 0) >= 7.2:
                    match = True
                elif criteria in ["malicious", "all_threats"] and r.get("risk_level") in ["MALICIOUS", "SUSPICIOUS"]:
                    match = True

                if match and os.path.exists(r["path"]):
                    try:
                        rec = self.vault.quarantine_file(r["path"], reason=f"AI Batch Quarantine ({criteria})")
                        quarantined.append(rec["original_name"])
                    except Exception as e:
                        print(f"[Tool] Quarantine batch err: {e}")

            self._refresh_quarantine_table()
            return {"status": "success", "quarantined_files": quarantined, "count": len(quarantined)}

        elif tool_name == "calculate_entropy":
            path = args.get("file_path", "")
            if os.path.exists(path):
                try:
                    with open(path, "rb") as f:
                        data = f.read(131072)
                    ent = calculate_shannon_entropy(data)
                    return {"status": "success", "file": path, "shannon_entropy": ent, "verdict": "High Risk / Packed" if ent >= 7.2 else "Normal"}
                except Exception as e:
                    return {"status": "error", "error": str(e)}
            return {"status": "error", "error": "File does not exist on disk."}

        elif tool_name == "list_hidden_artifacts":
            hidden = [r["path"] for r in self.scan_results if r.get("is_hidden")]
            return {"status": "success", "hidden_artifacts": hidden, "count": len(hidden)}

        elif tool_name == "export_pdf_report":
            out = self.export_pdf_direct()
            return {"status": "success", "report_path": out}

        elif tool_name == "analyze_file_with_ai":
            path = args.get("file_path", "")
            target_data = next((r for r in self.scan_results if r["path"] == path), None)
            if target_data:
                res = self.analyzer.analyze_suspicious_file(target_data)
                return {"status": "success", "verdict": res.get("threat_verdict"), "score": res.get("threat_score"), "summary": res.get("deobfuscated_summary")}
            return {"status": "error", "error": f"File {path} not found in scan results"}

        return {"status": "unknown_tool", "tool": tool_name}

    def _on_chat_response(self, text: str, actions: list):
        self.btn_send_chat.setEnabled(True)
        # Log tool actions
        for act in actions:
            self._append_chat_message("Sentinel Executor", f"Executed: <b>{act['tool']}</b> → {json.dumps(act['result'])}", is_system=True)
        self._append_chat_message("Groq AI Copilot", text)

    def _on_chat_error(self, err: str):
        self.btn_send_chat.setEnabled(True)
        self._append_chat_message("Groq AI Copilot", f"Error communicating with AI: {err}", is_error=True)

    def _append_chat_message(self, sender: str, text: str, is_system: bool = False, is_error: bool = False):
        color = "#06B6D4"
        if sender == "Investigator":
            color = "#38BDF8"
        elif is_system:
            color = "#10B981"
        elif is_error:
            color = "#EF4444"

        html = f"<div style='margin-bottom: 8px;'><b style='color: {color};'>{sender}:</b><br/>{text.replace(chr(10), '<br/>')}</div>"
        self.txt_chat_history.append(html)

    # ==================== PDF REPORT EXPORT ====================
    def export_pdf_dialog(self):
        default_name = f"USB_Sentinel_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        file_path, _ = QFileDialog.getSaveFileName(self, "Export Forensic PDF Report", default_name, "PDF Documents (*.pdf)")
        if file_path:
            self.export_pdf_direct(file_path)

    def export_pdf_direct(self, custom_path: str = None) -> str:
        if not custom_path:
            reports_dir = Path(__file__).parent / "forensic_reports"
            reports_dir.mkdir(exist_ok=True)
            custom_path = str(reports_dir / f"USB_Sentinel_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")

        dev_dict = self.current_usb_device.to_dict() if self.current_usb_device else {
            "mount_point": "N/A", "volume_label": "No USB Inserted", "serial_number": "N/A",
            "file_system": "N/A", "total_gb": 0, "free_gb": 0
        }

        ai_list = list(self.ai_insights_cache.values())

        out_path = generate_forensic_pdf(
            output_pdf_path=custom_path,
            device_info=dev_dict,
            scan_summary=self.scan_summary or {"total_scanned": len(self.scan_results)},
            scan_results=self.scan_results,
            ai_insights=ai_list,
            audit_logs=self.audit_logs
        )
        self._log_audit(f"PDF REPORT GENERATED: {out_path}")
        QMessageBox.information(self, "Report Exported", f"Forensic Evidence Report successfully created at:\n{out_path}")
        return out_path

    # ==================== SETTINGS & CONFIG ====================
    def _toggle_key_visibility(self):
        if self.txt_api_key.echoMode() == QLineEdit.EchoMode.Password:
            self.txt_api_key.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.txt_api_key.setEchoMode(QLineEdit.EchoMode.Password)

    def _test_groq_settings(self):
        key = self.txt_api_key.text().strip()
        model = self.combo_model.currentText().strip()
        self.analyzer.update_config(key, model)
        
        models = self.analyzer.get_available_models()
        self.combo_model.clear()
        self.combo_model.addItems(models)
        self.combo_model.setCurrentText(model if model in models else models[0])

        QMessageBox.information(
            self, "Groq Connection Test",
            f"Groq API connection verified successfully!\n\nAvailable Models: {len(models)}\nActive Model: {self.combo_model.currentText()}"
        )
        self._log_audit(f"Groq connection test passed. Active model: {self.combo_model.currentText()}")

    def _save_settings(self):
        key = self.txt_api_key.text().strip()
        model = self.combo_model.currentText().strip()
        self.analyzer.update_config(key, model)
        self._log_audit("Settings updated and saved.")
        QMessageBox.information(self, "Settings Saved", "Groq API configuration and heuristic thresholds updated.")

    # ==================== AUDIT LOGGER ====================
    def _log_audit(self, message: str):
        now_str = datetime.now().strftime("%H:%M:%S")
        entry = {"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "message": message}
        self.audit_logs.append(entry)
        self.txt_audit_log.append(f"[{now_str}] {message}")

    def closeEvent(self, event):
        """Cleanly stops background threads upon app close."""
        if hasattr(self, "monitor_thread") and self.monitor_thread.isRunning():
            self.monitor_thread.stop()
            self.monitor_thread.wait(2000)
        if self.scanner_worker and self.scanner_worker.isRunning():
            self.scanner_worker.cancel()
            self.scanner_worker.wait(1000)
        event.accept()
