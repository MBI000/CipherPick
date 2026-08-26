"""
CipherPick PyQt5 — Network Scanner Screen
"""
import os
import sys
import shutil
import json
import re
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
                             QComboBox, QPushButton, QSplitter, QTabWidget, 
                             QListWidget, QListWidgetItem, QTableWidget, QTableWidgetItem, 
                             QHeaderView, QTextEdit, QScrollArea, QCheckBox, QFileDialog)
from PyQt5.QtCore import Qt, pyqtSlot
from PyQt5.QtGui import QTextCursor, QColor
from datetime import datetime
from ..output_pane import ansi_to_html
from ..topology_widget import TopologyWidget

PROFILE_COMMANDS = {
    # Zenmap Defaults
    "Intense scan":                {"flags": "-T4 -A -v", "color": "#ff003c"},
    "Intense scan plus UDP":       {"flags": "-sS -sU -T4 -A -v", "color": "#ff5500"},
    "Intense scan, all TCP ports": {"flags": "-p 1-65535 -T4 -A -v", "color": "#ff0000"},
    "Intense scan, no ping":       {"flags": "-T4 -A -v -Pn", "color": "#ffaa00"},
    "Ping scan":                   {"flags": "-sn", "color": "#888888"},
    "Quick scan":                  {"flags": "-T4 -F", "color": "#00ff00"},
    "Quick scan plus":             {"flags": "-sV -T4 -O -F --version-light", "color": "#55ff55"},
    "Quick traceroute":            {"flags": "-sn --traceroute", "color": "#00aaff"},
    "Regular scan":                {"flags": "", "color": "#0077ff"},
    "Slow comprehensive scan":     {"flags": "-sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script default", "color": "#aa00ff"},
    
    # CLI Scan Techniques
    "TCP SYN scan (Stealth)":      {"flags": "-sS -v", "color": "#00ffcc"},
    "TCP Connect scan":            {"flags": "-sT -v", "color": "#00ccff"},
    "UDP scan":                    {"flags": "-sU -v", "color": "#ff9900"},
    "TCP Null scan":               {"flags": "-sN -v", "color": "#9900ff"},
    "TCP FIN scan":                {"flags": "-sF -v", "color": "#cc00ff"},
    "TCP Xmas scan":               {"flags": "-sX -v", "color": "#ff00cc"},
    "TCP ACK scan":                {"flags": "-sA -v", "color": "#ff3399"},
    "TCP Window scan":             {"flags": "-sW -v", "color": "#ff6699"},
    "TCP Maimon scan":             {"flags": "-sM -v", "color": "#ff9999"},
    
    # Target Discovery & Info
    "OS Detection":                {"flags": "-O -v", "color": "#ffff00"},
    "Version Detection":           {"flags": "-sV -v", "color": "#ccff00"},
    "Aggressive OS & Version":     {"flags": "-A -v", "color": "#ff3300"},
    "List scan (Resolve names)":   {"flags": "-sL -v", "color": "#cccccc"},
    
    # Firewall Evasion
    "Fragment packets":            {"flags": "-f -v", "color": "#666666"},
    "Decoy scan (10 random IPs)":  {"flags": "-D RND:10 -v", "color": "#333333"},
    # Custom Scanners
    "CipherPick Native (Socket Scan)": {"flags": "CUSTOM", "color": "#00f2ff"},
    "L0p4Map Subnet Discovery":        {"flags": "SUBNET", "color": "#ff00ff"},
    "L0p4Map Attack Surface (CVEs)":   {"flags": "ATTACK_SURFACE", "color": "#ff0000"},
}

MOCK_HOSTS = {}

class NetworkScannerScreen(QWidget):
    def __init__(self, task_manager, output_pane):
        super().__init__()
        self._tm = task_manager
        self._output_pane = output_pane
        self._hosts = dict(MOCK_HOSTS)
        self._selected_host = None
        self._scan_history = []

        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 5, 0, 0)
        self.layout.setSpacing(5)

        self._build_toolbar()
        self._build_body()
        
        # Initialize checkboxes for the default profile
        self._on_profile_changed(self.profile_combo.currentIndex())

        self._tm.line_received.connect(self._on_line_received)
        self._tm.task_done.connect(self._on_task_done)

    def _build_toolbar(self):
        toolbar = QWidget()
        tb_layout = QHBoxLayout(toolbar)
        tb_layout.setContentsMargins(0, 0, 0, 0)

        tb_layout.addWidget(QLabel("Target:"))
        self.target_input = QComboBox()
        self.target_input.setEditable(True)
        for h in self._hosts:
            self.target_input.addItem(h)
        self.target_input.setEditText("")
        self.target_input.currentTextChanged.connect(self._on_target_input_changed)
        tb_layout.addWidget(self.target_input, 1)

        tb_layout.addWidget(QLabel("Profile:"))
        self.profile_combo = QComboBox()
        for i, (p, data) in enumerate(PROFILE_COMMANDS.items()):
            self.profile_combo.addItem(p)
            self.profile_combo.setItemData(i, QColor(data['color']), Qt.ForegroundRole)
        self.profile_combo.currentIndexChanged.connect(self._on_profile_changed)
        tb_layout.addWidget(self.profile_combo)

        self.scan_btn = QPushButton("[ SCAN ]")
        self.scan_btn.clicked.connect(self._on_scan)
        tb_layout.addWidget(self.scan_btn)
        
        # Initialize button theme
        self._on_profile_changed(0)

        self.stop_btn = QPushButton("[ STOP ]")
        self.stop_btn.setObjectName("Destructive")
        self.stop_btn.clicked.connect(self._on_stop)
        tb_layout.addWidget(self.stop_btn)

        self.layout.addWidget(toolbar, 0)


    def _build_body(self):
        self.splitter = QSplitter(Qt.Horizontal)
        
        # Left Pane: Scan Options
        self.left_pane = self._build_scan_options()
        self.splitter.addWidget(self.left_pane)

        # Right Pane: Tabs
        self.right_tabs = QTabWidget()
        
        # Output Tab
        self.output_view = QTextEdit()
        self.output_view.setReadOnly(True)
        self.output_view.setStyleSheet("background-color: #0a0a0c; color: #c9d1d9; font-family: 'Consolas', 'Monaco', 'Courier New', monospace;")
        self.right_tabs.addTab(self.output_view, "Output")
        
        # Ports Tab 
        self.ports_table = QTableWidget(0, 5)
        self.ports_table.setHorizontalHeaderLabels(["Port", "Protocol", "State", "Service", "Version"])
        self.ports_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.ports_table.horizontalHeader().setStretchLastSection(True)
        self.right_tabs.addTab(self.ports_table, "Ports")
        
        # Topology Tab
        self.topo_view = TopologyWidget()
        self.right_tabs.addTab(self.topo_view, "Topology")
        
        # Details Tab
        self.details_view = QTextEdit()
        self.details_view.setReadOnly(True)
        self.right_tabs.addTab(self.details_view, "Details")
        
        # Scans Tab
        scans_tab = QWidget()
        scans_layout = QVBoxLayout(scans_tab)
        scans_layout.setContentsMargins(5, 5, 5, 5)
        
        scans_btn_layout = QHBoxLayout()
        self.save_btn = QPushButton("[ SAVE SCANS ]")
        self.save_btn.clicked.connect(self._on_save_scans)
        scans_btn_layout.addWidget(self.save_btn)

        self.load_btn = QPushButton("[ LOAD SCANS ]")
        self.load_btn.clicked.connect(self._on_load_scans)
        scans_btn_layout.addWidget(self.load_btn)
        
        scans_layout.addLayout(scans_btn_layout)
        
        self.scans_list = QListWidget()
        self.scans_list.itemClicked.connect(self._on_scan_item_clicked)
        self.scans_list.currentItemChanged.connect(self._on_scan_item_changed)
        self._refresh_scans_list()
        scans_layout.addWidget(self.scans_list)
        
        self.right_tabs.addTab(scans_tab, "Scans")
        
        # Vulnerabilities Tab
        self.vuln_table = QTableWidget(0, 5)
        self.vuln_table.setHorizontalHeaderLabels(["CVE ID", "CVSS", "Port", "Service", "Detail"])
        self.vuln_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.vuln_table.horizontalHeader().setStretchLastSection(True)
        self.vuln_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.right_tabs.addTab(self.vuln_table, "Vulnerabilities")

        self.splitter.addWidget(self.right_tabs)
        self.splitter.setStretchFactor(0, 1)
        self.splitter.setStretchFactor(1, 4)
        self.splitter.setSizes([200, 800])
        self.layout.addWidget(self.splitter, 1)
        
        self._refresh_all_tabs()

    def _build_scan_options(self):
        scroll = QScrollArea()
        scroll.setFixedWidth(280)
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; }")

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(6)

        self._scan_checks = {}
        sections = {
            "SCAN TYPE": [
                ("-F", "Fast scan"),
                ("-sS", "SYN scan"),
                ("-sT", "TCP connect"),
                ("-sU", "UDP scan"),
                ("-sN", "NULL scan"),
                ("-sX", "Xmas scan"),
                ("-p-", "All ports"),
                ("-A", "Aggressive"),
                ("-Pn", "No ping"),
            ],
            "DETECTION": [
                ("-sV", "Service version"),
                ("-O", "OS detection"),
                ("--osscan-guess", "OS guess"),
            ],
            "SCRIPTS": [
                ("-sC", "Default scripts"),
                ("--script banner", "Banner grab"),
                ("--script safe", "Safe scripts"),
                ("--script vuln", "Vuln scan"),
                ("--script vulners", "Vulners CVE"),
                ("--script malware", "Malware detect"),
                ("--script discovery", "Discovery"),
                ("--script http-enum", "HTTP enum"),
                ("--script http-headers", "HTTP headers"),
                ("--script http-methods", "HTTP methods"),
                ("--script ssl-cert", "SSL cert"),
                ("--script ssl-enum-ciphers", "SSL ciphers"),
                ("--script smb-enum-shares", "SMB shares"),
                ("--script smb-enum-users", "SMB users"),
                ("--script dns-brute", "DNS brute"),
                ("--script ftp-anon", "FTP anon"),
                ("--script ssh-auth-methods", "SSH auth"),
            ],
            "OUTPUT": [
                ("--open", "Show open only"),
                ("-v", "Verbose"),
                ("--reason", "Show reason"),
            ],
            "TIMING": [
                ("-T1", "Sneaky (slow)"),
                ("-T2", "Polite"),
                ("-T3", "Normal"),
                ("-T4", "Aggressive"),
                ("-T5", "Insane (fast)"),
            ],
        }

        for section_name, options in sections.items():
            sep = QWidget()
            sep.setFixedHeight(1)
            sep.setStyleSheet("background-color: #1c2333;")
            layout.addWidget(sep)
            layout.addSpacing(4)

            sec_label = QLabel(section_name)
            sec_label.setStyleSheet("color: #00f2ff; font-size: 11pt; font-weight: bold; letter-spacing: 2px;")
            layout.addWidget(sec_label)
            layout.addSpacing(2)

            for flag, description in options:
                cb = QCheckBox(f"{description}")
                cb.setFocusPolicy(Qt.NoFocus)
                cb.setToolTip(flag)
                cb.setStyleSheet('''
                    QCheckBox {
                        color: #c9d1d9;
                        font-size: 11pt;
                        spacing: 8px;
                    }
                    QCheckBox:hover { color: #ffffff; }
                    QCheckBox::indicator {
                        width: 16px; height: 16px;
                        border: 1px solid #1c2333;
                        background-color: #080c12;
                    }
                    QCheckBox::indicator:checked {
                        background-color: #00f2ff;
                        border: 1px solid #00f2ff;
                    }
                ''')
                self._scan_checks[flag] = cb
                layout.addWidget(cb)
            layout.addSpacing(4)

        sep = QWidget()
        sep.setFixedHeight(1)
        sep.setStyleSheet("background-color: #1c2333;")
        layout.addWidget(sep)
        layout.addSpacing(4)

        custom_label = QLabel("CUSTOM FLAGS")
        custom_label.setStyleSheet("color: #00f2ff; font-size: 11pt; font-weight: bold; letter-spacing: 2px;")
        layout.addWidget(custom_label)

        self.custom_flags = QLineEdit()
        self.custom_flags.setPlaceholderText("-p 80,443 --script http-title")
        self.custom_flags.setStyleSheet('''
            QLineEdit {
                background-color: #080c12;
                color: #c9d1d9;
                border: 1px solid #1c2333;
                padding: 6px;
                font-size: 10pt;
            }
            QLineEdit:focus { border: 1px solid #00f2ff; }
        ''')
        layout.addWidget(self.custom_flags)
        
        layout.addStretch()
        scroll.setWidget(container)
        return scroll

    def _on_target_input_changed(self, text):
        text = text.strip()
        if text in self._hosts:
            self._selected_host = text
            self._refresh_all_tabs()

    def _on_scan_item_clicked(self, item):
        if not item: return
        self._select_host_from_scan_text(item.text())

    def _on_scan_item_changed(self, current, previous):
        if not current: return
        self._select_host_from_scan_text(current.text())

    def _select_host_from_scan_text(self, text: str):
        if not text: return
        # Format is "192.168.1.10 - 10:15:20" or "192.168.1.10 (Subnet) - 10:15:20"
        ip_part = text.split(" ")[0].strip()
        if ip_part in self._hosts:
            self._selected_host = ip_part
            self.target_input.setCurrentText(ip_part)
            self._refresh_all_tabs()

    def _on_host_selected(self, item):
        self._selected_host = item.data(Qt.UserRole)
        self._refresh_all_tabs()

    def _populate_vulnerabilities_table(self, cves: list):
        self.vuln_table.setRowCount(0)
        if not cves:
            return
        for c in cves:
            row = self.vuln_table.rowCount()
            self.vuln_table.insertRow(row)
            
            try:
                cvss_val = float(c.get('cvss', 0.0))
            except (ValueError, TypeError):
                cvss_val = 0.0
                
            if cvss_val >= 9.0:
                sev = "Critical"
                color = QColor("#ff3333")
            elif cvss_val >= 7.0:
                sev = "High"
                color = QColor("#ff9933")
            elif cvss_val >= 4.0:
                sev = "Medium"
                color = QColor("#ffcc00")
            else:
                sev = "Low"
                color = QColor("#33cc33")
                
            cvss_str = f"[{cvss_val}-{sev}]"
            
            id_item = QTableWidgetItem(str(c.get('id', '')))
            cvss_item = QTableWidgetItem(cvss_str)
            port_item = QTableWidgetItem(str(c.get('port', '')))
            svc_item = QTableWidgetItem(str(c.get('service', '')))
            detail_item = QTableWidgetItem(str(c.get('detail', '')))
            
            for it in (id_item, cvss_item, port_item, svc_item, detail_item):
                it.setForeground(color)
                
            self.vuln_table.setItem(row, 0, id_item)
            self.vuln_table.setItem(row, 1, cvss_item)
            self.vuln_table.setItem(row, 2, port_item)
            self.vuln_table.setItem(row, 3, svc_item)
            self.vuln_table.setItem(row, 4, detail_item)

    def _refresh_all_tabs(self):
        host = self._hosts.get(self._selected_host, {})
        # Output
        raw = host.get('raw_output', '')
        self.output_view.setHtml(ansi_to_html(raw))
        # Ports
        self.ports_table.setRowCount(0)
        for p in host.get('ports', []):
            row = self.ports_table.rowCount()
            self.ports_table.insertRow(row)
            self.ports_table.setItem(row, 0, QTableWidgetItem(str(p.get('port', ''))))
            self.ports_table.setItem(row, 1, QTableWidgetItem(str(p.get('protocol', ''))))
            self.ports_table.setItem(row, 2, QTableWidgetItem(str(p.get('state', ''))))
            self.ports_table.setItem(row, 3, QTableWidgetItem(str(p.get('service', ''))))
            self.ports_table.setItem(row, 4, QTableWidgetItem(str(p.get('version', ''))))
        # Details
        details = "\n".join([f"{k:15}: {v}" for k, v in host.items() if k not in ['ports', 'raw_output', 'os_icon', 'vulnerabilities']])
        self.details_view.setPlainText(details)

        # Topology
        self.topo_view.update_topology(list(self._hosts.values()))

        # Vulnerabilities
        cves = host.get('vulnerabilities', [])
        self._populate_vulnerabilities_table(cves)

    def _refresh_scans_list(self):
        self.scans_list.clear()
        for s in self._scan_history:
            self.scans_list.addItem(s)

    def _on_profile_changed(self, index):
        profile = self.profile_combo.itemText(index)
        data = PROFILE_COMMANDS.get(profile)
        if data:
            color = data['color']
            self.scan_btn.setStyleSheet(f"""
                QPushButton {{
                    border: 1px solid {color};
                    color: {color};
                    background: rgba({int(color[1:3], 16)}, {int(color[3:5], 16)}, {int(color[5:7], 16)}, 0.1);
                }}
                QPushButton:hover {{
                    background: {color};
                    color: #000000;
                }}
            """)
            
            # Sync checkboxes
            flags = data.get("flags", "")
            
            if not hasattr(self, '_scan_checks'):
                return
            
            # Reset all checkboxes
            for cb in self._scan_checks.values():
                cb.setChecked(False)
                
            self.custom_flags.clear()
            
            if flags in ["CUSTOM", "SUBNET", "ATTACK_SURFACE"]:
                return
                
            flag_tokens = flags.split()
            custom_extras = []
            
            sorted_known_flags = sorted(self._scan_checks.keys(), key=len, reverse=True)
            
            i = 0
            while i < len(flag_tokens):
                token = flag_tokens[i]
                matched = False
                
                if i + 1 < len(flag_tokens):
                    two_part = token + " " + flag_tokens[i+1]
                    if two_part in self._scan_checks:
                        self._scan_checks[two_part].setChecked(True)
                        matched = True
                        i += 2
                        continue
                        
                if token in self._scan_checks:
                    self._scan_checks[token].setChecked(True)
                    matched = True
                    i += 1
                    continue
                    
                custom_extras.append(token)
                i += 1
                
            if custom_extras:
                self.custom_flags.setText(" ".join(custom_extras))

    def _on_scan(self):
        target = self.target_input.currentText().strip()
        if not target: return
        
        profile = self.profile_combo.currentText()
        p_data = PROFILE_COMMANDS.get(profile, {"flags": ""})
        base_flags = p_data.get("flags", "")
        
        if base_flags in ["SUBNET", "ATTACK_SURFACE"]:
            flags = base_flags
        else:
            checked_flags = []
            for flag, cb in self._scan_checks.items():
                if cb.isChecked():
                    checked_flags.append(flag)
            
            extra_flags = self.custom_flags.text().strip()
            flags = " ".join(checked_flags) + (" " + extra_flags if extra_flags else "")
            
            if flags.strip() == "":
                flags = "-sn"
            
        if "SUBNET" in flags:
            kwargs = json.dumps({"subnet": target})
            task_type = "SubnetScan"
            msg = f"<span style='color: #ff00ff;'>[+] Launching L0p4Map Subnet Discovery on {target}...</span>\n"
        elif "ATTACK_SURFACE" in flags:
            kwargs = json.dumps({"target": target})
            task_type = "AttackSurfaceScan"
            msg = f"<span style='color: #ff0000;'>[+] Launching L0p4Map Attack Surface Scan on {target}...</span>\n"
        else:
            kwargs = json.dumps({
                "target": target,
                "flags": flags
            })
            task_type = "NmapScan"
            msg = f"<span style='color: #00f2ff;'>[+] Launching Nmap Scan on {target}...</span>\n"
        
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        cmd = [sys.executable, os.path.join(base_dir, "runner.py"), task_type, kwargs]
        
        self._live_output = ""
        self.output_view.clear()
        self.right_tabs.setCurrentIndex(0)
        self.scan_btn.setEnabled(False)
        self._output_pane.append_ansi(msg)
        self._tm.start('net_scan', cmd, cwd=base_dir)

    def _on_stop(self):
        self._tm.stop('net_scan')
        self.scan_btn.setEnabled(True)

    @pyqtSlot(str, str)
    def _on_line_received(self, task_id, line):
        if task_id == 'net_scan':
            self.right_tabs.setCurrentIndex(0)
            
            self._live_output += line
            html = ansi_to_html(line)
            self.output_view.insertHtml(html)
            self.output_view.moveCursor(QTextCursor.End)

    @pyqtSlot(str, int)
    def _on_task_done(self, task_id, rc):
        if task_id == 'net_scan':
            self.scan_btn.setEnabled(True)
            self._output_pane.append_ansi(f"[*] Network scan finished with exit code {rc}.\n")
            
            try:
                subnet_res_path = '.cipherpick_logs/subnet_scan_results.json'
                net_res_path = '.cipherpick_logs/net_scan_results.json'
                vuln_res_path = '.cipherpick_logs/attack_surface_results.json'
                
                if os.path.exists(subnet_res_path):
                    with open(subnet_res_path, 'r') as f:
                        hosts = json.load(f)
                        
                    target = self.target_input.currentText().strip()
                    for h in hosts:
                        ip = h.get("ip")
                        existing_vulns = self._hosts.get(ip, {}).get("vulnerabilities", [])
                        host_data = {
                            "ip": ip,
                            "hostname": h.get("hostname"),
                            "os_icon": "🪟" if "windows" in h.get("os_hint", "").lower() else "🐧" if "linux" in h.get("os_hint", "").lower() else "🍎" if "macos" in h.get("os_hint", "").lower() else "🖥",
                            "os": h.get("os_hint"),
                            "role": h.get("role"),
                            "vendor": h.get("vendor"),
                            "mac": h.get("mac"),
                            "ports": [],
                            "vulnerabilities": existing_vulns,
                            "raw_output": getattr(self, '_live_output', '')
                        }
                        self._hosts[ip] = host_data
                    
                    scan_time = datetime.now().strftime('%H:%M:%S')
                    self._scan_history.insert(0, f"{target} (Subnet) - {scan_time}")
                    os.remove(subnet_res_path)

                elif os.path.exists(net_res_path):
                    with open(net_res_path, 'r') as f:
                        data = json.load(f)
                    
                    if not data.get('raw_output'):
                        data['raw_output'] = getattr(self, '_live_output', '')

                    target = data.get('target')
                    if target:
                        if target in self._hosts and 'vulnerabilities' in self._hosts[target]:
                            data['vulnerabilities'] = self._hosts[target]['vulnerabilities']
                        self._hosts[target] = data
                        self._selected_host = target
                        
                        scan_time = datetime.now().strftime('%H:%M:%S')
                        self._scan_history.insert(0, f"{target} - {scan_time}")
                    os.remove(net_res_path)

                if os.path.exists(vuln_res_path):
                    with open(vuln_res_path, 'r') as f:
                        data = json.load(f)
                    
                    target = data.get('target')
                    cves = data.get('cves', [])
                    if target:
                        if target not in self._hosts:
                            self._hosts[target] = {
                                "ip": target,
                                "hostname": target,
                                "ports": [],
                                "raw_output": getattr(self, '_live_output', '')
                            }
                        self._hosts[target]['vulnerabilities'] = cves
                        self._selected_host = target
                        
                    scan_time = datetime.now().strftime('%H:%M:%S')
                    self._scan_history.insert(0, f"{target} (Attack Surface) - {scan_time}")
                    os.remove(vuln_res_path)
                    
                    # Switch to Vulnerabilities tab automatically
                    for i in range(self.right_tabs.count()):
                        if self.right_tabs.tabText(i) == "Vulnerabilities":
                            self.right_tabs.setCurrentIndex(i)
                            break
                
                # Update combo box items if missing
                for host in self._hosts:
                    if self.target_input.findText(host) == -1:
                        self.target_input.addItem(host)
                
                self._refresh_scans_list()
                
                if not self._selected_host and self._hosts:
                    self._selected_host = list(self._hosts.keys())[0]
                self._refresh_all_tabs()
                        
            except Exception as e:
                print(f"Error updating UI: {e}")

    def _sync_current_vuln_table_to_host(self):
        if self._selected_host and self._selected_host in self._hosts:
            cves = []
            for row in range(self.vuln_table.rowCount()):
                id_item = self.vuln_table.item(row, 0)
                cvss_item = self.vuln_table.item(row, 1)
                port_item = self.vuln_table.item(row, 2)
                svc_item = self.vuln_table.item(row, 3)
                detail_item = self.vuln_table.item(row, 4)
                
                if not id_item: continue
                cve_id = id_item.text().strip()
                cvss_text = cvss_item.text().strip() if cvss_item else ""
                
                cvss_val = 0.0
                cvss_match = re.search(r"(\d+\.\d+|\d+)", cvss_text)
                if cvss_match:
                    try:
                        cvss_val = float(cvss_match.group(1))
                    except ValueError:
                        pass
                        
                port_val = port_item.text().strip() if port_item else ""
                svc_val = svc_item.text().strip() if svc_item else ""
                detail_val = detail_item.text().strip() if detail_item else ""
                
                cves.append({
                    "id": cve_id,
                    "cvss": cvss_val,
                    "port": port_val,
                    "service": svc_val,
                    "detail": detail_val
                })
            if cves:
                self._hosts[self._selected_host]['vulnerabilities'] = cves

    def _on_save_scans(self):
        self._sync_current_vuln_table_to_host()
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Scans", "", "JSON Files (*.json);;All Files (*)", options=options)
        if file_path:
            try:
                vulns_map = {}
                for ip, host_info in self._hosts.items():
                    if isinstance(host_info, dict) and 'vulnerabilities' in host_info:
                        vulns_map[ip] = host_info['vulnerabilities']
                
                data = {
                    "hosts": self._hosts,
                    "history": self._scan_history,
                    "vulnerabilities": vulns_map
                }
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=4)
                self._output_pane.append_ansi(f"[*] Scans successfully saved to {file_path}\n")
            except Exception as e:
                self._output_pane.append_ansi(f"<span style='color: #ff0000;'>[-] Failed to save scans: {e}</span>\n")

    def _on_load_scans(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Load Scans", "", "JSON Files (*.json);;All Files (*)", options=options)
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                if "hosts" in data:
                    loaded_hosts = data.get("hosts", {})
                    loaded_history = data.get("history", [])
                    loaded_vulns = data.get("vulnerabilities", {})
                    
                    for ip, cves in loaded_vulns.items():
                        if ip in loaded_hosts:
                            loaded_hosts[ip]['vulnerabilities'] = cves
                        else:
                            loaded_hosts[ip] = {"ip": ip, "hostname": ip, "ports": [], "vulnerabilities": cves}

                    self._hosts.update(loaded_hosts)
                    for h in loaded_history:
                        if h not in self._scan_history:
                            self._scan_history.append(h)
                    
                    self._refresh_scans_list()
                    
                    # Refresh target combo box
                    self.target_input.clear()
                    for host in self._hosts:
                        self.target_input.addItem(host)

                    if self._hosts:
                        active_target = self.target_input.currentText().strip()
                        if active_target in self._hosts:
                            self._selected_host = active_target
                        else:
                            self._selected_host = list(self._hosts.keys())[0]
                            self.target_input.setCurrentText(self._selected_host)

                    self._refresh_all_tabs()
                    self._output_pane.append_ansi(f"[*] Scans successfully loaded from {file_path}\n")
                else:
                    self._output_pane.append_ansi(f"<span style='color: #ff0000;'>[-] Invalid scan file format.</span>\n")
            except Exception as e:
                self._output_pane.append_ansi(f"<span style='color: #ff0000;'>[-] Failed to load scans: {e}</span>\n")

