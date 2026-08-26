"""
CipherPick PyQt5 — Attacks Screen
"""
import os
import sys
import json
import threading
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
                             QComboBox, QPushButton, QScrollArea, QFrame, QFileDialog)
from PyQt5.QtCore import Qt

from PyQt5.QtWidgets import QStackedWidget

class AttacksScreen(QWidget):
    def __init__(self, task_manager, output_pane):
        super().__init__()
        self._tm = task_manager
        self._output_pane = output_pane
        
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(20, 20, 20, 20)
        self.stack = QStackedWidget()
        self.layout.addWidget(self.stack)
        
        self.tools = {}
        self._build_tools()

    def _build_tools(self):
        # 1. Password Cracking
        crack_w = QWidget()
        crack_l = QVBoxLayout(crack_w)
        crack_l.setSpacing(15)
        self._add_title(crack_l, "PASSWORD CRACKING")
        self.crack_target = self._add_input_row(crack_l, "Target Hash/File:")
        self.crack_type = self._add_combo_row(crack_l, "Attack Type:", ["Numeric", "Mask", "Dictionary", "Hash Crack"])
        crack_btn = QPushButton("[ LAUNCH CRACKER ]")
        crack_btn.clicked.connect(self._on_crack)
        crack_l.addWidget(crack_btn)
        crack_l.addStretch()
        self.tools['password_cracking'] = crack_w
        self.stack.addWidget(crack_w)

        # SSH Bruteforce
        ssh_w = QWidget()
        ssh_l = QVBoxLayout(ssh_w)
        ssh_l.setSpacing(15)
        self._add_title(ssh_l, "SSH BRUTEFORCE")
        self.ssh_host = self._add_input_row(ssh_l, "Target Host/IP:")
        self.ssh_user = self._add_input_row(ssh_l, "Single Username (Optional):")
        self.ssh_userlist = self._add_input_row(ssh_l, "Userlist File (Optional):")
        self.ssh_passlist = self._add_input_row(ssh_l, "Password Wordlist:")
        ssh_btn = QPushButton("[ LAUNCH SSH BRUTEFORCE ]")
        ssh_btn.clicked.connect(self._on_ssh_brute)
        ssh_l.addWidget(ssh_btn)
        ssh_l.addStretch()
        self.tools['ssh_brute'] = ssh_w
        self.stack.addWidget(ssh_w)

        # 2. PDF Recovery
        pdf_w = QWidget()
        pdf_l = QVBoxLayout(pdf_w)
        pdf_l.setSpacing(15)
        self._add_title(pdf_l, "PDF RECOVERY")
        self.pdf_file = self._add_input_row(pdf_l, "PDF File:")
        self.pdf_wordlist = self._add_input_row(pdf_l, "Wordlist:")
        pdf_btn = QPushButton("[ RECOVER PDF ]")
        pdf_btn.clicked.connect(self._on_pdf_recovery)
        pdf_l.addWidget(pdf_btn)
        pdf_l.addStretch()
        self.tools['pdf_recovery'] = pdf_w
        self.stack.addWidget(pdf_w)

        # 3. MITM
        mitm_w = QWidget()
        mitm_l = QVBoxLayout(mitm_w)
        mitm_l.setSpacing(15)
        self._add_title(mitm_l, "MITM ATTACKS")
        self.mitm_target = self._add_input_row(mitm_l, "Target IP:")
        self.mitm_gw = self._add_input_row(mitm_l, "Gateway IP:")
        mitm_btn = QPushButton("[ LAUNCH EVILGINX3 ]")
        mitm_btn.setObjectName("Destructive")
        mitm_btn.clicked.connect(self._on_mitm)
        mitm_l.addWidget(mitm_btn)
        mitm_l.addStretch()
        self.tools['mitm_attacks'] = mitm_w
        self.stack.addWidget(mitm_w)

    def show_tool(self, tool_id):
        widget = self.tools.get(tool_id)
        if widget:
            self.stack.setCurrentWidget(widget)

    def _add_title(self, layout, text):
        title = QLabel(text)
        title.setStyleSheet("color: #00f2ff; font-size: 16pt; font-weight: bold; letter-spacing: 2px;")
        layout.addWidget(title)
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet("color: #1c2333;")
        layout.addWidget(line)

    def _add_section(self, text):
        lbl = QLabel(text.upper())
        lbl.setStyleSheet("color: #445566; font-size: 8pt; font-weight: bold; margin-top: 10px;")
        self.scroll_layout.addWidget(lbl)
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet("color: #1c2333;")
        self.scroll_layout.addWidget(line)

    def _add_input_row(self, layout, label_text):
        row = QWidget()
        row_l = QHBoxLayout(row)
        row_l.setContentsMargins(0, 0, 0, 0)
        row_l.addWidget(QLabel(label_text), 1)
        input_field = QLineEdit()
        row_l.addWidget(input_field, 3)
        browse_btn = QPushButton("...")
        browse_btn.setFixedWidth(30)
        browse_btn.clicked.connect(lambda: self._browse(input_field))
        row_l.addWidget(browse_btn)
        layout.addWidget(row)
        return input_field

    def _add_combo_row(self, layout, label_text, items):
        row = QWidget()
        row_l = QHBoxLayout(row)
        row_l.setContentsMargins(0, 0, 0, 0)
        row_l.addWidget(QLabel(label_text), 1)
        combo = QComboBox()
        combo.addItems(items)
        row_l.addWidget(combo, 3)
        layout.addWidget(row)
        return combo

    def _browse(self, field):
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path: field.setText(path)

    def _on_crack(self):
        tgt = self.crack_target.text().strip()
        if not tgt: return
        atk = self.crack_type.currentText()
        
        # Map attack names to runner class names
        class_map = {
            "Numeric": "NumericAttack",
            "Mask": "MaskAttack",
            "Dictionary": "TrieDictionaryAttack",
            "Hash Crack": "HashCracker"
        }
        class_name = class_map.get(atk)
        if not class_name: return

        # Simple heuristic for params
        kwargs = {}
        if class_name == "NumericAttack": kwargs = {"target": tgt, "length": 4}
        elif class_name == "MaskAttack": kwargs = {"target": tgt, "mask": "?d?d?d?d"}
        elif class_name == "TrieDictionaryAttack": kwargs = {"target": tgt, "wordlist": "passwords.txt"}
        elif class_name == "HashCracker": kwargs = {"target": tgt, "wordlist": "passwords.txt"}

        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        cmd = [sys.executable, os.path.join(base_dir, 'runner.py'), class_name, json.dumps(kwargs)]
        
        self._output_pane.append_ansi(f"<span style='color: #00f2ff;'>[*] Launching {atk} Attack...</span>\n")
        self._tm.start(f'crack_{class_name}', cmd, cwd=base_dir)

    def _on_ssh_brute(self):
        host = self.ssh_host.text().strip()
        passlist = self.ssh_passlist.text().strip()
        user = self.ssh_user.text().strip()
        userlist = self.ssh_userlist.text().strip()
        
        if not host or not passlist:
            self._output_pane.append_ansi("<span style='color: #ff003c;'>[!] Error: Host and Password list are required.</span>\n")
            return
            
        if not user and not userlist:
            self._output_pane.append_ansi("<span style='color: #ff003c;'>[!] Error: Either a single user or userlist is required.</span>\n")
            return

        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        kwargs = {
            "host": host,
            "passlist": passlist,
            "user": user if user else None,
            "userlist": userlist if userlist else None
        }
        cmd = [sys.executable, os.path.join(base_dir, 'runner.py'), 'SSHBruteforce', json.dumps(kwargs)]
        
        self._output_pane.append_ansi(f"<span style='color: #00f2ff;'>[*] Launching SSH Bruteforce against {host}...</span>\n")
        self._tm.start('ssh_brute', cmd, cwd=base_dir)

    def _on_pdf_recovery(self):
        pdf = self.pdf_file.text()
        wl = self.pdf_wordlist.text()
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        cmd = [sys.executable, os.path.join(base_dir, 'runner.py'), 'PDFRecovery', json.dumps({"pdf_path": pdf, "wordlist_path": wl})]
        self._tm.start('pdf_recovery', cmd, cwd=base_dir)

    def _on_mitm(self):
        target = self.mitm_target.text().strip()
        gateway = self.mitm_gw.text().strip()
        
        evilginx_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', "evilginx3-master", "evilginx3-master"))
        if not os.path.exists(evilginx_dir):
            self._output_pane.append_ansi("<span style='color: #ff003c;'>[!] Error: Evilginx3 directory not found.</span>\n")
            return

        try:
            # Launch in new window as per app.py
            cmd = f'start cmd /k "cd /d {evilginx_dir} && go run main.go -p ./phishlets"'
            import subprocess
            subprocess.Popen(cmd, shell=True)
            self._output_pane.append_ansi("<span style='color: #00ff00;'>[+] Evilginx 3 console spawned in new window.</span>\n")
        except Exception as e:
            self._output_pane.append_ansi(f"<span style='color: #ff003c;'>[!] Failed to start MITM: {e}</span>\n")
