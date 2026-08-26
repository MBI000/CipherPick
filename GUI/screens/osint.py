"""
CipherPick PyQt5 — OSINT & Info Gathering Screen
"""
import os
import sys
import json
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
                             QPushButton, QScrollArea, QFrame, QTextBrowser)
from PyQt5.QtCore import Qt, pyqtSlot
from PyQt5.QtGui import QTextCursor
from ..output_pane import ansi_to_html

from PyQt5.QtWidgets import QStackedWidget

class OSINTScreen(QWidget):
    def __init__(self, task_manager, output_pane):
        super().__init__()
        self._tm = task_manager
        self._output_pane = output_pane
        
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(20, 20, 20, 20)
        self.layout.setSpacing(10)

        self.stack = QStackedWidget()
        self.layout.addWidget(self.stack)

        self.tools = {}
        self._build_tools()
        
        self.layout.addWidget(QLabel("Scan Output:"))
        self.output_view = QTextBrowser()
        self.output_view.setOpenExternalLinks(True)
        self.output_view.setStyleSheet("background-color: #0a0a0c; border: 1px solid #1c2333; font-family: 'Courier New';")
        self.layout.addWidget(self.output_view, 1)

        self._tm.line_received.connect(self._on_line)
        
    def _build_tools(self):
        # Username Hunter Section
        uh_w = QWidget()
        uh_l = QVBoxLayout(uh_w)
        uh_l.setContentsMargins(0,0,0,0)
        title_uh = QLabel("USERNAME HUNTER")
        title_uh.setStyleSheet("color: #00f2ff; font-size: 16pt; font-weight: bold;")
        uh_l.addWidget(title_uh)
        
        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("Enter target username (e.g., janesmith)")
        uh_l.addWidget(QLabel("Target Username:"))
        uh_l.addWidget(self.user_input)
        hunt_btn = QPushButton("[ HUNT USERNAME ]")
        hunt_btn.clicked.connect(self._on_hunt)
        uh_l.addWidget(hunt_btn)
        uh_l.addStretch()
        
        self.tools['username_hunter'] = uh_w
        self.stack.addWidget(uh_w)

        # Shodan OSINT Section
        sh_w = QWidget()
        sh_l = QVBoxLayout(sh_w)
        sh_l.setContentsMargins(0,0,0,0)
        title_sh = QLabel("SHODAN OSINT LOOKUP")
        title_sh.setStyleSheet("color: #00f2ff; font-size: 16pt; font-weight: bold;")
        sh_l.addWidget(title_sh)
        
        self.sh_target = QLineEdit()
        self.sh_target.setPlaceholderText("Enter target domain or IP (e.g., 8.8.8.8 or example.com)")
        sh_l.addWidget(QLabel("Target IP / Hostname:"))
        sh_l.addWidget(self.sh_target)

        self.sh_key = QLineEdit("6apjUWGhpborF2uwaC0AToSg5dVb3OQx")
        self.sh_key.setEchoMode(QLineEdit.PasswordEchoOnEdit)
        sh_l.addWidget(QLabel("Shodan API Key:"))
        sh_l.addWidget(self.sh_key)

        sh_btn = QPushButton("[ LAUNCH SHODAN LOOKUP ]")
        sh_btn.clicked.connect(self._on_shodan_launch)
        sh_l.addWidget(sh_btn)
        sh_l.addStretch()
        
        self.tools['shodan'] = sh_w
        self.tools['spiderfoot'] = sh_w
        self.stack.addWidget(sh_w)

    def show_tool(self, tool_id):
        widget = self.tools.get(tool_id)
        if widget:
            self.stack.setCurrentWidget(widget)
        
    @pyqtSlot(str, str)
    def _on_line(self, task_id, line):
        if task_id in ['username_hunter', 'shodan', 'spiderfoot']:
            import re
            html = ansi_to_html(line)
            url_pattern = r'(https?://[^\s<]+)'
            html = re.sub(url_pattern, r'<a href="\1" style="color: #00aaff;">\1</a>', html)
            self.output_view.insertHtml(html)
            self.output_view.moveCursor(QTextCursor.End)

    def _add_section(self, text):
        lbl = QLabel(text.upper())
        lbl.setStyleSheet("color: #445566; font-size: 8pt; font-weight: bold; margin-top: 10px;")
        self.layout.addWidget(lbl)
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet("color: #1c2333;")
        self.layout.addWidget(line)

    def _on_hunt(self):
        username = self.user_input.text().strip()
        if not username: return
        
        self.output_view.clear()
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        kwargs = json.dumps({"username": username})
        cmd = [sys.executable, os.path.join(base_dir, "runner.py"), "UsernameHunter", kwargs]
        
        self.output_view.append(f"<span style='color: #00f2ff;'>[*] Launching Username Hunter for '{username}'...</span>")
        self._tm.start('username_hunter', cmd, cwd=base_dir)

    def _on_shodan_launch(self):
        target = self.sh_target.text().strip()
        api_key = self.sh_key.text().strip()
        if not target: return
        
        self.output_view.clear()
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        kwargs = json.dumps({"target": target, "api_key": api_key})
        cmd = [sys.executable, os.path.join(base_dir, "runner.py"), "ShodanScan", kwargs]
        
        self.output_view.append(f"<span style='color: #00f2ff;'>[*] Launching Shodan OSINT for '{target}'...</span><br>")
        self._tm.start('shodan', cmd, cwd=base_dir)
