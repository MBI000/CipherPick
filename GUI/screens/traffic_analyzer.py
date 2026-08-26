import time
import csv
import psutil
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, 
                             QComboBox, QLineEdit, QSplitter, QFileDialog)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QColor

try:
    from scapy.all import sniff, TCP, UDP, ICMP, IP as ScapyIP
except ImportError:
    pass

class TrafficWorker(QThread):
    packet_captured = pyqtSignal(dict)
    
    def __init__(self, iface: str):
        super().__init__()
        self.iface = iface
        self._running = True

    def stop(self):
        self._running = False

    def run(self):
        def process(pkt):
            if not self._running:
                return
            if ScapyIP not in pkt:
                return

            src = pkt[ScapyIP].src
            dst = pkt[ScapyIP].dst
            size = len(pkt)
            proto = "OTHER"
            port = "-"

            if TCP in pkt:
                proto = "TCP"
                port = str(pkt[TCP].dport)
            elif UDP in pkt:
                proto = "UDP"
                port = str(pkt[UDP].dport)
            elif ICMP in pkt:
                proto = "ICMP"

            self.packet_captured.emit({
                "src": src,
                "dst": dst,
                "proto": proto,
                "port": port,
                "size": size,
                "time": time.strftime('%H:%M:%S')
            })

        sniff(
            iface=self.iface,
            prn=process,
            store=False,
            filter="ip",
            stop_filter=lambda _: not self._running
        )


class TrafficAnalyzerScreen(QWidget):
    def __init__(self, task_manager, output_pane):
        super().__init__()
        self._tm = task_manager
        self._output_pane = output_pane
        
        self._packets = []
        
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(10, 10, 10, 10)
        self.layout.setSpacing(10)
        
        # Header / Controls
        header = QWidget()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 0)
        
        lbl = QLabel("INTERFACE:")
        lbl.setStyleSheet("color: #00f2ff; font-weight: bold;")
        header_layout.addWidget(lbl)
        
        self.iface_combo = QComboBox()
        self.iface_combo.setFixedWidth(250)
        self._populate_interfaces()
        header_layout.addWidget(self.iface_combo)
        
        self.btn_start = QPushButton("[ START ]")
        self.btn_start.clicked.connect(self._start_capture)
        self.btn_start.setStyleSheet("QPushButton { border: 1px solid #00f2ff; padding: 6px; }")
        header_layout.addWidget(self.btn_start)
        
        self.btn_stop = QPushButton("[ STOP ]")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._stop_capture)
        header_layout.addWidget(self.btn_stop)
        
        self.btn_clear = QPushButton("[ CLEAR ]")
        self.btn_clear.clicked.connect(self._clear)
        header_layout.addWidget(self.btn_clear)
        
        self.btn_export = QPushButton("[ EXPORT CSV ]")
        self.btn_export.clicked.connect(self._export_csv)
        header_layout.addWidget(self.btn_export)
        
        header_layout.addStretch()
        
        # Filter
        filter_lbl = QLabel("FILTER:")
        filter_lbl.setStyleSheet("color: #888888;")
        header_layout.addWidget(filter_lbl)
        
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("IP, port, proto...")
        self.filter_input.setFixedWidth(200)
        self.filter_input.textChanged.connect(self._apply_filter)
        header_layout.addWidget(self.filter_input)
        
        self.layout.addWidget(header)
        
        # Table
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["#", "TIME", "SRC", "DST", "PROTO", "PORT", "SIZE"])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        for col, w in [(0, 50), (1, 80), (4, 60), (5, 60), (6, 60)]:
            self.table.horizontalHeader().setSectionResizeMode(col, QHeaderView.Fixed)
            self.table.setColumnWidth(col, w)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet("QTableWidget { alternate-background-color: #111; }")
        
        self.layout.addWidget(self.table)
        
        # Status
        self.status_lbl = QLabel("// Ready")
        self.status_lbl.setStyleSheet("color: #aaaaaa;")
        self.layout.addWidget(self.status_lbl)
        
    def _populate_interfaces(self):
        try:
            addrs = psutil.net_if_addrs()
            for iface, _ in addrs.items():
                self.iface_combo.addItem(iface, iface)
        except Exception:
            pass

    def _start_capture(self):
        iface = self.iface_combo.currentData()
        if not iface: return
        
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.status_lbl.setText(f"// Capturing on {iface}...")
        
        self.worker = TrafficWorker(iface)
        self.worker.packet_captured.connect(self._on_packet)
        self.worker.start()

    def _stop_capture(self):
        if hasattr(self, 'worker'):
            self.worker.stop()
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.status_lbl.setText(f"// Capture stopped. {len(self._packets)} packets captured.")

    def _clear(self):
        self._packets.clear()
        self.table.setRowCount(0)
        self.status_lbl.setText("// Cleared")

    def _on_packet(self, pkt):
        self._packets.append(pkt)
        row = self.table.rowCount()
        self.table.insertRow(row)
        
        self.table.setItem(row, 0, QTableWidgetItem(str(row + 1)))
        self.table.setItem(row, 1, QTableWidgetItem(pkt['time']))
        self.table.setItem(row, 2, QTableWidgetItem(pkt['src']))
        self.table.setItem(row, 3, QTableWidgetItem(pkt['dst']))
        
        proto_item = QTableWidgetItem(pkt['proto'])
        if pkt['proto'] == "TCP":
            proto_item.setForeground(QColor("#00f2ff"))
        elif pkt['proto'] == "UDP":
            proto_item.setForeground(QColor("#00ccff"))
        elif pkt['proto'] == "ICMP":
            proto_item.setForeground(QColor("#ff4444"))
        self.table.setItem(row, 4, proto_item)
        
        self.table.setItem(row, 5, QTableWidgetItem(pkt['port']))
        self.table.setItem(row, 6, QTableWidgetItem(str(pkt['size'])))
        
        if row % 10 == 0:
            self.table.scrollToBottom()
            self.status_lbl.setText(f"// Capturing... {len(self._packets)} packets")

    def _apply_filter(self, text):
        text = text.lower()
        for row in range(self.table.rowCount()):
            visible = not text or any(
                text in (self.table.item(row, col).text().lower() if self.table.item(row, col) else "")
                for col in range(self.table.columnCount())
            )
            self.table.setRowHidden(row, not visible)

    def _export_csv(self):
        if not self._packets:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export Traffic", "traffic.csv", "CSV Files (*.csv)")
        if not path:
            return
        
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["#", "TIME", "SRC", "DST", "PROTO", "PORT", "SIZE"])
            for i, p in enumerate(self._packets):
                writer.writerow([i+1, p['time'], p['src'], p['dst'], p['proto'], p['port'], p['size']])
        
        self.status_lbl.setText(f"// Exported to {path}")
