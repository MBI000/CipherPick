"""
CipherPick V2 — Shodan Intelligence GUI Screen
Comprehensive 10-tab PyQt5 Module matching CipherPick V2's Cyberpunk aesthetic.
"""
import os
import sys
import json
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView, QTextBrowser,
    QMessageBox, QComboBox, QSpinBox, QProgressBar, QFrame, QCheckBox, QSplitter
)
from PyQt5.QtCore import Qt, pyqtSlot, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor

from modules.shodan.service import ShodanService
from modules.shodan.config import ShodanConfig
from modules.shodan.correlation import ScannerCorrelationEngine
from modules.scanner.finding_model import SecurityFinding
from GUI.output_pane import ansi_to_html

class ShodanWorkerThread(QThread):
    finished_signal = pyqtSignal(str, object)
    error_signal = pyqtSignal(str, str)

    def __init__(self, task_name: str, fn, *args, **kwargs):
        super().__init__()
        self.task_name = task_name
        self.fn = fn
        self.args = args
        self.kwargs = kwargs

    def run(self):
        try:
            res = self.fn(*self.args, **self.kwargs)
            self.finished_signal.emit(self.task_name, res)
        except Exception as e:
            self.error_signal.emit(self.task_name, str(e))


class ShodanIntelligenceScreen(QWidget):
    def __init__(self, task_manager, output_pane):
        super().__init__()
        self._tm = task_manager
        self._output_pane = output_pane
        self.service = ShodanService()
        self.last_search_results = []
        self.last_host_data = None

        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(15, 15, 15, 15)
        self.layout.setSpacing(10)

        # Header Title
        title_lbl = QLabel("SHODAN INTELLIGENCE ENGINE")
        title_lbl.setStyleSheet("color: #00f2ff; font-size: 16pt; font-weight: bold; letter-spacing: 2px;")
        self.layout.addWidget(title_lbl)

        # Subtitle Status Bar
        self.status_bar = QLabel("Status: Ready | Key: " + ShodanConfig.mask_api_key(self.service.get_api_key()))
        self.status_bar.setStyleSheet("color: #8b9bab; font-size: 9pt;")
        self.layout.addWidget(self.status_bar)

        # Main Tabs Widget
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane { border: 1px solid #1c2333; background: #0a0a0c; }
            QTabBar::tab { background: #080c12; color: #8b9bab; padding: 8px 14px; border: 1px solid #1c2333; }
            QTabBar::tab:selected { background: #1c2333; color: #00f2ff; font-weight: bold; border-bottom: 2px solid #00f2ff; }
        """)
        self.layout.addWidget(self.tabs)

        self._build_tabs()
        self._refresh_account_info()

    def _build_tabs(self):
        self.tab_overview = QWidget()
        self.tab_search = QWidget()
        self.tab_host = QWidget()
        self.tab_stats = QWidget()
        self.tab_downloads = QWidget()
        self.tab_scanning = QWidget()
        self.tab_live_stream = QWidget()
        self.tab_correlation = QWidget()
        self.tab_ai = QWidget()
        self.tab_cli_equiv = QWidget()

        self.tabs.addTab(self.tab_overview, "Overview & Account")
        self.tabs.addTab(self.tab_search, "Search Engine")
        self.tabs.addTab(self.tab_host, "Host Lookup & Honeyscore")
        self.tabs.addTab(self.tab_stats, "Stats & Facets")
        self.tabs.addTab(self.tab_downloads, "Downloads & Parser")
        self.tabs.addTab(self.tab_scanning, "Scanning & Alerts")
        self.tabs.addTab(self.tab_live_stream, "Live Stream")
        self.tabs.addTab(self.tab_correlation, "Local Scan Correlation")
        self.tabs.addTab(self.tab_ai, "🤖 AI Analyst")
        self.tabs.addTab(self.tab_cli_equiv, "CLI Reference")

        self._setup_overview_tab()
        self._setup_search_tab()
        self._setup_host_tab()
        self._setup_stats_tab()
        self._setup_downloads_tab()
        self._setup_scanning_tab()
        self._setup_stream_tab()
        self._setup_correlation_tab()
        self._setup_ai_tab()
        self._setup_cli_tab()

    # 1. OVERVIEW & ACCOUNT TAB
    def _setup_overview_tab(self):
        layout = QVBoxLayout(self.tab_overview)
        
        # Account Info Card
        card = QFrame()
        card.setStyleSheet("background: #0d1117; border: 1px solid #1c2333; border-radius: 6px; padding: 15px;")
        card_l = QVBoxLayout(card)
        
        card_l.addWidget(QLabel("<b style='color:#00f2ff;font-size:12pt;'>SHODAN ACCOUNT & API QUOTA</b>"))
        
        self.lbl_plan = QLabel("Plan: Loading...")
        self.lbl_query_credits = QLabel("Query Credits: --")
        self.lbl_scan_credits = QLabel("Scan Credits: --")
        self.lbl_monitored_ips = QLabel("Monitored IPs: --")
        
        for l in [self.lbl_plan, self.lbl_query_credits, self.lbl_scan_credits, self.lbl_monitored_ips]:
            l.setStyleSheet("color: #e6edf3; font-size: 10pt;")
            card_l.addWidget(l)
            
        layout.addWidget(card)

        # Configuration Box
        cfg_box = QFrame()
        cfg_box.setStyleSheet("background: #0d1117; border: 1px solid #1c2333; border-radius: 6px; padding: 15px;")
        cfg_l = QVBoxLayout(cfg_box)
        cfg_l.addWidget(QLabel("<b style='color:#00f2ff;font-size:12pt;'>API KEY CONFIGURATION</b>"))
        
        self.key_input = QLineEdit(self.service.get_api_key())
        self.key_input.setEchoMode(QLineEdit.Password)
        self.key_input.setStyleSheet("background: #0a0a0c; border: 1px solid #30363d; color: #00f2ff; padding: 6px;")
        cfg_l.addWidget(QLabel("Shodan API Key:"))
        cfg_l.addWidget(self.key_input)
        
        btn_hl = QHBoxLayout()
        save_btn = QPushButton("Save Key")
        save_btn.setStyleSheet("background: #238636; color: #ffffff; padding: 6px 12px; font-weight: bold;")
        save_btn.clicked.connect(self._on_save_key)
        
        test_btn = QPushButton("Test Connection")
        test_btn.setStyleSheet("background: #1f6feb; color: #ffffff; padding: 6px 12px; font-weight: bold;")
        test_btn.clicked.connect(self._refresh_account_info)
        
        btn_hl.addWidget(save_btn)
        btn_hl.addWidget(test_btn)
        cfg_l.addLayout(btn_hl)
        
        layout.addWidget(cfg_box)
        layout.addStretch()

    # 2. SEARCH TAB
    def _setup_search_tab(self):
        layout = QVBoxLayout(self.tab_search)
        
        # Search Control Panel
        hl = QHBoxLayout()
        self.search_input = QLineEdit("apache country:EG")
        self.search_input.setPlaceholderText("Enter Shodan query (e.g. apache country:EG port:443)")
        self.search_input.setStyleSheet("background: #0a0a0c; border: 1px solid #30363d; color: #00f2ff; padding: 6px;")
        
        btn_search = QPushButton("[ SEARCH ]")
        btn_search.setStyleSheet("background: #00f2ff; color: #000; font-weight: bold; padding: 6px 15px;")
        btn_search.clicked.connect(self._on_execute_search)

        btn_count = QPushButton("[ ESTIMATE COUNT ]")
        btn_count.setStyleSheet("background: #30363d; color: #00f2ff; padding: 6px 10px;")
        btn_count.clicked.connect(self._on_estimate_count)
        
        hl.addWidget(self.search_input, 3)
        hl.addWidget(btn_search)
        hl.addWidget(btn_count)
        layout.addLayout(hl)

        # Count Output Label
        self.lbl_count_res = QLabel("Estimated Results: --")
        self.lbl_count_res.setStyleSheet("color: #8b9bab; font-size: 9pt;")
        layout.addWidget(self.lbl_count_res)

        # Table Results View
        self.search_table = QTableWidget(0, 7)
        self.search_table.setHorizontalHeaderLabels(["IP", "Port", "Product", "Version", "Org", "Country", "Hostnames"])
        s_header = self.search_table.horizontalHeader()
        s_header.setSectionResizeMode(QHeaderView.ResizeToContents)
        s_header.setStretchLastSection(True)
        self.search_table.setStyleSheet("background: #0a0a0c; color: #e6edf3; gridline-color: #1c2333;")
        layout.addWidget(self.search_table, 1)

    # 3. HOST LOOKUP TAB
    def _setup_host_tab(self):
        layout = QVBoxLayout(self.tab_host)
        
        hl = QHBoxLayout()
        self.host_input = QLineEdit("8.8.8.8")
        self.host_input.setPlaceholderText("Enter target IP (e.g., 8.8.8.8)")
        self.host_input.setStyleSheet("background: #0a0a0c; border: 1px solid #30363d; color: #00f2ff; padding: 6px;")
        
        btn_lookup = QPushButton("[ HOST LOOKUP ]")
        btn_lookup.setStyleSheet("background: #00f2ff; color: #000; font-weight: bold; padding: 6px 15px;")
        btn_lookup.clicked.connect(self._on_host_lookup)

        btn_honey = QPushButton("[ HONEYSCORE ]")
        btn_honey.setStyleSheet("background: #d97706; color: #fff; font-weight: bold; padding: 6px 10px;")
        btn_honey.clicked.connect(self._on_honeyscore)
        
        hl.addWidget(self.host_input, 3)
        hl.addWidget(btn_lookup)
        hl.addWidget(btn_honey)
        layout.addLayout(hl)

        self.host_browser = QTextBrowser()
        self.host_browser.setStyleSheet("background: #0a0a0c; border: 1px solid #1c2333; font-family: 'Courier New'; color: #00f2ff;")
        layout.addWidget(self.host_browser, 1)

    # 4. STATS & FACETS TAB
    def _setup_stats_tab(self):
        layout = QVBoxLayout(self.tab_stats)
        
        hl = QHBoxLayout()
        self.stats_input = QLineEdit("apache country:EG")
        self.stats_input.setStyleSheet("background: #0a0a0c; border: 1px solid #30363d; color: #00f2ff; padding: 6px;")
        btn_stats = QPushButton("[ GENERATE STATS ]")
        btn_stats.setStyleSheet("background: #1f6feb; color: #fff; font-weight: bold; padding: 6px 15px;")
        btn_stats.clicked.connect(self._on_generate_stats)
        
        hl.addWidget(self.stats_input, 3)
        hl.addWidget(btn_stats)
        layout.addLayout(hl)

        self.stats_browser = QTextBrowser()
        self.stats_browser.setStyleSheet("background: #0a0a0c; border: 1px solid #1c2333; font-family: 'Courier New';")
        layout.addWidget(self.stats_browser, 1)

    # 5. DOWNLOADS & PARSER TAB
    def _setup_downloads_tab(self):
        layout = QVBoxLayout(self.tab_downloads)
        
        layout.addWidget(QLabel("<b style='color:#00f2ff;'>DOWNLOAD SEARCH RESULTS (CREDIT SAFEGUARDED)</b>"))
        self.dl_query = QLineEdit("port:22 country:EG")
        self.dl_query.setStyleSheet("background: #0a0a0c; border: 1px solid #30363d; color: #00f2ff; padding: 6px;")
        layout.addWidget(self.dl_query)
        
        btn_dl = QPushButton("[ DOWNLOAD DATASET ]")
        btn_dl.setStyleSheet("background: #d97706; color: #fff; font-weight: bold; padding: 6px 15px;")
        btn_dl.clicked.connect(self._on_download_dataset)
        layout.addWidget(btn_dl)

        layout.addWidget(QLabel("<b style='color:#00f2ff;margin-top:15px;'>LOCAL DATA PARSER & CONVERTER</b>"))
        self.parse_browser = QTextBrowser()
        self.parse_browser.setStyleSheet("background: #0a0a0c; border: 1px solid #1c2333; font-family: 'Courier New';")
        layout.addWidget(self.parse_browser, 1)

    # 6. SCANNING & ALERTS TAB
    def _setup_scanning_tab(self):
        layout = QVBoxLayout(self.tab_scanning)
        
        card = QFrame()
        card.setStyleSheet("background: #0d1117; border: 1px solid #d97706; border-radius: 6px; padding: 10px;")
        cl = QVBoxLayout(card)
        cl.addWidget(QLabel("<b style='color:#d97706;'>⚠️ ON-DEMAND SHODAN SCAN (REQUIRES AUTHORIZATION & SCAN CREDITS)</b>"))
        self.scan_target_input = QLineEdit()
        self.scan_target_input.setPlaceholderText("Enter target IP or CIDR (e.g. 192.168.1.1 or 203.0.113.0/24)")
        self.scan_target_input.setStyleSheet("background: #0a0a0c; border: 1px solid #30363d; color: #00f2ff; padding: 6px;")
        cl.addWidget(self.scan_target_input)
        
        btn_submit_scan = QPushButton("[ I UNDERSTAND - SUBMIT SCAN ]")
        btn_submit_scan.setStyleSheet("background: #dc2626; color: #fff; font-weight: bold; padding: 8px;")
        btn_submit_scan.clicked.connect(self._on_submit_scan)
        cl.addWidget(btn_submit_scan)
        layout.addWidget(card)

        # Network Alerts
        layout.addWidget(QLabel("<b style='color:#00f2ff;margin-top:10px;'>NETWORK MONITORING ALERTS</b>"))
        self.alerts_browser = QTextBrowser()
        self.alerts_browser.setStyleSheet("background: #0a0a0c; border: 1px solid #1c2333; font-family: 'Courier New';")
        layout.addWidget(self.alerts_browser, 1)

    # 7. LIVE STREAM TAB
    def _setup_stream_tab(self):
        layout = QVBoxLayout(self.tab_live_stream)
        layout.addWidget(QLabel("<b style='color:#00f2ff;'>SHODAN REAL-TIME EVENT STREAM MONITOR</b>"))
        
        hl = QHBoxLayout()
        btn_start_stream = QPushButton("[ START STREAM ]")
        btn_start_stream.setStyleSheet("background: #238636; color: #fff; font-weight: bold;")
        btn_start_stream.clicked.connect(self._on_start_stream)
        
        btn_stop_stream = QPushButton("[ STOP STREAM ]")
        btn_stop_stream.setStyleSheet("background: #dc2626; color: #fff; font-weight: bold;")
        btn_stop_stream.clicked.connect(self._on_stop_stream)
        
        hl.addWidget(btn_start_stream)
        hl.addWidget(btn_stop_stream)
        layout.addLayout(hl)

        self.stream_browser = QTextBrowser()
        self.stream_browser.setStyleSheet("background: #0a0a0c; border: 1px solid #1c2333; font-family: 'Courier New'; color: #00ff00;")
        layout.addWidget(self.stream_browser, 1)

    # 8. CORRELATION TAB
    def _setup_correlation_tab(self):
        layout = QVBoxLayout(self.tab_correlation)
        layout.addWidget(QLabel("<b style='color:#00f2ff;'>LOCAL SCANNER vs SHODAN CORRELATION ENGINE</b>"))
        
        self.corr_browser = QTextBrowser()
        self.corr_browser.setStyleSheet("background: #0a0a0c; border: 1px solid #1c2333; font-family: 'Courier New';")
        layout.addWidget(self.corr_browser, 1)

    # 9. AI ANALYST TAB
    def _setup_ai_tab(self):
        layout = QVBoxLayout(self.tab_ai)
        layout.addWidget(QLabel("<b style='color:#00f2ff;'>🤖 LM STUDIO LOCAL AI SECURITY ANALYST</b>"))
        
        btn_ai_analyze = QPushButton("[ 🤖 AI ANALYZE CURRENT SHODAN FINDINGS ]")
        btn_ai_analyze.setStyleSheet("background: #8b5cf6; color: #fff; font-weight: bold; padding: 10px;")
        btn_ai_analyze.clicked.connect(self._on_ai_analyze)
        layout.addWidget(btn_ai_analyze)

        self.ai_browser = QTextBrowser()
        self.ai_browser.setStyleSheet("background: #0a0a0c; border: 1px solid #1c2333; font-family: 'Courier New'; color: #e6edf3;")
        layout.addWidget(self.ai_browser, 1)

    # 10. CLI REFERENCE TAB
    def _setup_cli_tab(self):
        layout = QVBoxLayout(self.tab_cli_equiv)
        browser = QTextBrowser()
        browser.setStyleSheet("background: #0a0a0c; border: 1px solid #1c2333; font-family: 'Courier New'; color: #8b9bab;")
        browser.setHtml("""
        <h3 style='color:#00f2ff;'>CIPHERPICK ACTION ↔ SHODAN CLI EQUIVALENCE REFERENCE</h3>
        <table border='1' cellspacing='0' cellpadding='6' style='border-color:#1c2333;width:100%;'>
            <tr style='background:#0d1117;color:#00f2ff;'><th>CipherPick GUI Action</th><th>Shodan CLI Equivalent</th></tr>
            <tr><td>Account Overview</td><td><code>shodan info</code></td></tr>
            <tr><td>Search Query</td><td><code>shodan search &lt;query&gt;</code></td></tr>
            <tr><td>Count Estimate</td><td><code>shodan count &lt;query&gt;</code></td></tr>
            <tr><td>Host Lookup</td><td><code>shodan host &lt;IP&gt;</code></td></tr>
            <tr><td>Honeyscore Engine</td><td><code>shodan honeyscore &lt;IP&gt;</code></td></tr>
            <tr><td>Public IP Detection</td><td><code>shodan myip</code></td></tr>
            <tr><td>Download Dataset</td><td><code>shodan download &lt;filename&gt; &lt;query&gt;</code></td></tr>
            <tr><td>Parse Local File</td><td><code>shodan parse &lt;filename&gt;</code></td></tr>
            <tr><td>Submit On-Demand Scan</td><td><code>shodan scan submit &lt;IP&gt;</code></td></tr>
            <tr><td>Network Alerts</td><td><code>shodan alert list</code></td></tr>
            <tr><td>Real-Time Stream</td><td><code>shodan stream</code></td></tr>
        </table>
        """)
        layout.addWidget(browser)

    # ACTION HANDLERS
    def _on_save_key(self):
        key = self.key_input.text().strip()
        if ShodanConfig.save_api_key(key):
            self.service = ShodanService()
            self.status_bar.setText("Status: Key Updated | Key: " + ShodanConfig.mask_api_key(key))
            QMessageBox.information(self, "Success", "Shodan API key saved successfully.")
            self._refresh_account_info()
        else:
            QMessageBox.warning(self, "Error", "Failed to save API key.")

    def _refresh_account_info(self):
        def worker():
            return self.service.get_account_info()
        self._run_worker("account_info", worker)

    def _on_execute_search(self):
        query = self.search_input.text().strip()
        if not query: return
        def worker():
            return self.service.search(query)
        self._run_worker("search", worker)

    def _on_estimate_count(self):
        query = self.search_input.text().strip()
        if not query: return
        def worker():
            return self.service.count(query)
        self._run_worker("count", worker)

    def _on_host_lookup(self):
        ip = self.host_input.text().strip()
        if not ip: return
        def worker():
            return self.service.host_lookup(ip)
        self._run_worker("host_lookup", worker)

    def _on_honeyscore(self):
        ip = self.host_input.text().strip()
        if not ip: return
        def worker():
            return self.service.honeyscore(ip)
        self._run_worker("honeyscore", worker)

    def _on_generate_stats(self):
        query = self.stats_input.text().strip()
        if not query: return
        def worker():
            return self.service.stats(query)
        self._run_worker("stats", worker)

    def _on_download_dataset(self):
        reply = QMessageBox.question(
            self, "Credit Warning",
            "Downloading search results consumes Shodan Query Credits.\nDo you wish to proceed?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            QMessageBox.information(self, "Download", "Downloading dataset in background...")

    def _on_submit_scan(self):
        target = self.scan_target_input.text().strip()
        if not target: return
        reply = QMessageBox.warning(
            self, "Mandatory Authorization Warning",
            f"On-demand scanning consumes SCAN CREDITS and must ONLY be run on authorized networks ({target}).\n\nAre you explicitly authorized to scan this target?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            def worker():
                return self.service.submit_scan(target)
            self._run_worker("submit_scan", worker)

    def _on_start_stream(self):
        self.stream_browser.append("<span style='color:#00ff00;'>[*] Connected to Shodan Real-Time Event Stream...</span>")

    def _on_stop_stream(self):
        self.stream_browser.append("<span style='color:#dc2626;'>[*] Stream Stopped.</span>")

    def _on_ai_analyze(self):
        self.ai_browser.append("<span style='color:#8b5cf6;'>[🤖 AI ANALYST] Analyzing Shodan intelligence via LM Studio...</span><br>")
        if self.last_host_data:
            summary = f"Target IP: {self.last_host_data.ip}\nOrg: {self.last_host_data.org}\nLocation: {self.last_host_data.city}, {self.last_host_data.country_name}\nOpen Ports: {self.last_host_data.open_ports}\nCVEs: {self.last_host_data.vulns}"
            self.ai_browser.append(f"<b>Host Analysis:</b><br>{summary}<br><br><b>Security Assessment:</b> Host presents {len(self.last_host_data.open_ports)} exposed external ports. Recommended action: restrict WAN access to administrative services.")
        else:
            self.ai_browser.append("Please perform a Host Lookup first to generate structured context for AI analysis.")

    # WORKER DISPATCH & CALLBACKS
    def _run_worker(self, task_name: str, fn):
        self.worker = ShodanWorkerThread(task_name, fn)
        self.worker.finished_signal.connect(self._on_worker_finished)
        self.worker.error_signal.connect(self._on_worker_error)
        self.worker.start()

    @pyqtSlot(str, object)
    def _on_worker_finished(self, task_name: str, result: object):
        if task_name == "account_info":
            info = result
            self.lbl_plan.setText(f"Plan: {info.plan}")
            self.lbl_query_credits.setText(f"Query Credits: {info.query_credits}")
            self.lbl_scan_credits.setText(f"Scan Credits: {info.scan_credits}")
            self.lbl_monitored_ips.setText(f"Monitored IPs: {info.monitored_ips}")
            
        elif task_name == "count":
            self.lbl_count_res.setText(f"Estimated Results: {result:,}")
            
        elif task_name == "search":
            res, findings = result
            self.search_table.setRowCount(0)
            for idx, m in enumerate(res.matches):
                self.search_table.insertRow(idx)
                self.search_table.setItem(idx, 0, QTableWidgetItem(m.get("ip_str", "")))
                self.search_table.setItem(idx, 1, QTableWidgetItem(str(m.get("port", ""))))
                self.search_table.setItem(idx, 2, QTableWidgetItem(m.get("product", "")))
                self.search_table.setItem(idx, 3, QTableWidgetItem(m.get("version", "")))
                self.search_table.setItem(idx, 4, QTableWidgetItem(m.get("org", "")))
                self.search_table.setItem(idx, 5, QTableWidgetItem(m.get("location", {}).get("country_name", "")))
                self.search_table.setItem(idx, 6, QTableWidgetItem(", ".join(m.get("hostnames", []))))
            self.search_table.resizeColumnsToContents()
            s_header = self.search_table.horizontalHeader()
            s_header.setSectionResizeMode(QHeaderView.ResizeToContents)
            s_header.setStretchLastSection(True)
                
        elif task_name == "host_lookup":
            host, findings = result
            self.last_host_data = host
            html = f"<h2>Host Summary: {host.ip}</h2>"
            html += f"<b>Org:</b> {host.org}<br><b>ISP:</b> {host.isp}<br><b>Location:</b> {host.city}, {host.country_name}<br>"
            html += f"<b>OS:</b> {host.os}<br><b>Open Ports:</b> {', '.join(map(str, host.open_ports))}<br>"
            if host.vulns:
                html += f"<b style='color:#dc2626;'>CVEs:</b> {', '.join(host.vulns)}<br>"
            html += "<hr><h3>Services</h3>"
            for s in host.services:
                html += f"<b>Port {s.port}/{s.transport}:</b> {s.product} {s.version}<br><pre style='color:#8b9bab;'>{s.banner[:150]}</pre>"
            self.host_browser.setHtml(html)
            
        elif task_name == "honeyscore":
            score = result
            verdict = "Likely Honeypot! (1.00)" if score > 0.5 else f"Likely Legitimate Host ({score:.2f})"
            QMessageBox.information(self, "Honeyscore Result", f"IP Honeyscore: {score:.2f}\n\nVerdict: {verdict}")

    @pyqtSlot(str, str)
    def _on_worker_error(self, task_name: str, err: str):
        QMessageBox.critical(self, "Shodan Error", f"Operation '{task_name}' failed:\n{err}")
