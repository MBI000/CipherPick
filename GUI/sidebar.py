"""
CipherPick PyQt5 — Sidebar Navigation Tree
"""
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTreeWidget, QTreeWidgetItem, QLabel, QFrame
from PyQt5.QtCore import Qt, pyqtSignal

_NAV_TREE = [
    ("Attacks", "Attacks", [
        ("Password Cracking", "password_cracking"),
        ("SSH Bruteforce", "ssh_brute"),
        ("PDF Recovery", "pdf_recovery"),
        ("MITM Attacks", "mitm_attacks")
    ]),
    ("Steganography", "Steganography", [
        ("Text Steganography", "text_steg"),
        ("Image Steganography", "img_steg")
    ]),
    ("Forensics", "Forensics", [
        ("File Analysis", "file_analysis"),
        ("String Extraction", "string_extraction"),
        ("Directory Scanner", "dir_scanner")
    ]),
    ("Network Scanner", "NetworkScanner", [
        ("Host Discovery & Inventory", "host_discovery")
    ]),
    ("Traffic Analyzer", "TrafficAnalyzer", []),
    ("SQL Injector", "SQLInjector", []),
    ("Crypto Engine", "Crypto", [
        ("AES Engine", "aes"),
        ("RSA Engine", "rsa"),
        ("SHA Generator", "sha")
    ]),
    ("OSINT", "OSINT", [
        ("Username Hunter", "username_hunter"),
        ("Shodan OSINT", "shodan")
    ]),
    ("Shodan Intelligence", "ShodanIntelligence", []),
]

class Sidebar(QWidget):
    item_selected = pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)

        self._build_logo()
        
        lbl = QLabel("MODULES")
        lbl.setStyleSheet("color: #445566; font-size: 8pt; font-weight: bold; letter-spacing: 2px; margin: 15px 15px 5px 15px;")
        self.layout.addWidget(lbl)

        self.tree_widget = QTreeWidget()
        self.tree_widget.setObjectName("SidebarTree")
        self.tree_widget.setHeaderHidden(True)
        self.tree_widget.setIndentation(15)
        self.tree_widget.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.tree_widget.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.tree_widget.itemClicked.connect(self._on_item_clicked)
        self.tree_widget.setFocusPolicy(Qt.NoFocus)

        for cat_label, cat_name, sub_items in _NAV_TREE:
            cat_item = QTreeWidgetItem(self.tree_widget)
            cat_item.setText(0, cat_label)
            cat_item.setData(0, Qt.UserRole, (cat_name, None))
            
            for sub_label, sub_name in sub_items:
                sub_item = QTreeWidgetItem(cat_item)
                sub_item.setText(0, "▸ " + sub_label)
                sub_item.setData(0, Qt.UserRole, (cat_name, sub_name))

        self.layout.addWidget(self.tree_widget)

    def _build_logo(self):
        logo_container = QWidget()
        logo_layout = QVBoxLayout(logo_container)
        logo_layout.setContentsMargins(10, 10, 10, 10)
        logo_layout.setSpacing(2)

        title_lbl = QLabel("CIPHERPICK")
        title_lbl.setAlignment(Qt.AlignCenter)
        title_lbl.setStyleSheet("color: #00f2ff; font-size: 11pt; font-weight: bold; letter-spacing: 2px;")
        logo_layout.addWidget(title_lbl)

        status_lbl = QLabel("Active")
        status_lbl.setAlignment(Qt.AlignCenter)
        status_lbl.setStyleSheet("color: #00ff00; font-size: 7pt;")
        logo_layout.addWidget(status_lbl)

        self.layout.addWidget(logo_container)
        
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Plain)
        line.setStyleSheet("color: #1c2333;")
        self.layout.addWidget(line)

    def _on_item_clicked(self, item, column):
        data = item.data(0, Qt.UserRole)
        if data:
            cat_name, sub_name = data
            if sub_name or item.childCount() == 0:
                self.item_selected.emit(cat_name, sub_name or "")
            else:
                item.setExpanded(not item.isExpanded())
