"""
CipherPick PyQt5 — Main Application Window
"""
from PyQt5.QtWidgets import QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QSplitter, QStackedWidget, QLabel
from PyQt5.QtCore import Qt

from .sidebar import Sidebar
from .output_pane import OutputPane
from .task_manager import TaskManager
from .screens.network_scanner import NetworkScannerScreen
from .screens.attacks import AttacksScreen
from .screens.steganography import SteganographyScreen
from .screens.forensics import ForensicsScreen
from .screens.sql_injector import SQLInjectorScreen
from .screens.crypto import CryptoScreen
from .screens.osint import OSINTScreen
from .screens.traffic_analyzer import TrafficAnalyzerScreen
from .screens.shodan_intelligence import ShodanIntelligenceScreen

class AppWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CipherPick V2")
        self.resize(1280, 820)

        # Main Widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        # Hidden Output Pane (for background logic) & Task Manager
        self.output_pane = OutputPane()
        self.task_manager = TaskManager(self.output_pane)
        
        # Top Container (Sidebar + Content)
        self.top_container = QWidget()
        self.top_layout = QHBoxLayout(self.top_container)
        self.top_layout.setContentsMargins(0, 0, 0, 0)
        self.top_layout.setSpacing(0)

        # Sidebar
        self.sidebar = Sidebar()
        self.sidebar.setFixedWidth(210)
        self.sidebar.item_selected.connect(self._on_nav_select)
        self.top_layout.addWidget(self.sidebar)

        # Content Area
        self.content_widget = QWidget()
        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        
        # Toggle Sidebar Button and Top Bar
        self.top_bar = QWidget()
        self.top_bar.setStyleSheet("background-color: #080c12; border-bottom: 1px solid #1c2333;")
        self.top_bar_layout = QHBoxLayout(self.top_bar)
        self.top_bar_layout.setContentsMargins(10, 5, 10, 5)
        
        from PyQt5.QtWidgets import QPushButton
        self.toggle_btn = QPushButton("[ ☰ ]")
        self.toggle_btn.setFixedSize(36, 36)
        self.toggle_btn.setStyleSheet("QPushButton { border: none; font-size: 16pt; color: #00f2ff; background: transparent; } QPushButton:hover { color: #ffffff; }")
        self.toggle_btn.setToolTip("Toggle Full Screen")
        self.toggle_btn.clicked.connect(self._toggle_sidebar)
        
        self.top_bar_layout.addWidget(self.toggle_btn)
        self.top_bar_layout.addStretch()
        
        self.content_layout.addWidget(self.top_bar)

        # Content Stack
        self.stack = QStackedWidget()
        self._build_screens()
        self.content_layout.addWidget(self.stack)

        self.top_layout.addWidget(self.content_widget)

        # Add only the top container to main layout
        self.main_layout.addWidget(self.top_container)

    def _build_screens(self):
        self.screens = {
            'Attacks':            AttacksScreen(self.task_manager, self.output_pane),
            'Steganography':      SteganographyScreen(self.task_manager, self.output_pane),
            'Forensics':          ForensicsScreen(self.task_manager, self.output_pane),
            'NetworkScanner':     NetworkScannerScreen(self.task_manager, self.output_pane),
            'SQLInjector':        SQLInjectorScreen(self.task_manager, self.output_pane),
            'Crypto':             CryptoScreen(self.task_manager, self.output_pane),
            'OSINT':              OSINTScreen(self.task_manager, self.output_pane),
            'TrafficAnalyzer':    TrafficAnalyzerScreen(self.task_manager, self.output_pane),
            'ShodanIntelligence': ShodanIntelligenceScreen(self.task_manager, self.output_pane),
        }
        for name, widget in self.screens.items():
            self.stack.addWidget(widget)

    def _on_nav_select(self, category, sub_tool):
        widget = self.screens.get(category)
        if widget:
            self.stack.setCurrentWidget(widget)
            if hasattr(widget, 'show_tool'):
                widget.show_tool(sub_tool)

    def _toggle_sidebar(self):
        self.sidebar.setVisible(not self.sidebar.isVisible())

    def closeEvent(self, event):
        self.task_manager.stop_all()
        event.accept()
