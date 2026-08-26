"""
CipherPick PyQt5 — SQL Injector Screen
"""
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
                             QPushButton, QSpinBox, QProgressBar, QTextEdit)
from PyQt5.QtCore import Qt, pyqtSlot
from PyQt5.QtGui import QTextCursor
import os
import sys
from ..output_pane import ansi_to_html

class SQLInjectorScreen(QWidget):
    def __init__(self, task_manager, output_pane):
        super().__init__()
        self._tm = task_manager
        self._output_pane = output_pane
        
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(20, 20, 20, 20)
        self.layout.setSpacing(15)

        title = QLabel("SQL INJECTOR")
        title.setStyleSheet("color: #00f2ff; font-size: 16pt; font-weight: bold;")
        self.layout.addWidget(title)

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com/vuln.php?id=1")
        self.layout.addWidget(QLabel("Target URL:"))
        self.layout.addWidget(self.url_input)

        settings = QWidget()
        sl = QHBoxLayout(settings)
        sl.setContentsMargins(0, 0, 0, 0)
        
        sl.addWidget(QLabel("Level (1-5):"))
        self.level = QSpinBox()
        self.level.setRange(1, 5)
        sl.addWidget(self.level)
        
        sl.addWidget(QLabel("Risk (1-3):"))
        self.risk = QSpinBox()
        self.risk.setRange(1, 3)
        sl.addWidget(self.risk)
        
        self.layout.addWidget(settings)

        self.flags = QLineEdit("--batch --threads=5")
        self.layout.addWidget(QLabel("Extra Flags:"))
        self.layout.addWidget(self.flags)

        btn_row = QHBoxLayout()
        run_btn = QPushButton("[ RUN SQLMAP ]")
        run_btn.clicked.connect(self._on_run)
        btn_row.addWidget(run_btn)
        
        stop_btn = QPushButton("[ STOP ]")
        stop_btn.setObjectName("Destructive")
        stop_btn.clicked.connect(self._on_stop)
        btn_row.addWidget(stop_btn)
        self.layout.addLayout(btn_row)



        self.layout.addWidget(QLabel("Terminal Output:"))
        self.output_view = QTextEdit()
        self.output_view.setReadOnly(True)
        self.output_view.setStyleSheet("background-color: #0a0a0c; color: #c9d1d9; font-family: 'Consolas', 'Monaco', 'Courier New', monospace;")
        self.layout.addWidget(self.output_view, 1)

        self._tm.line_received.connect(self._on_line)
        self._tm.task_done.connect(self._on_done)

    @pyqtSlot(str, str)
    def _on_line(self, task_id, line):
        if task_id == 'sql_injector':
            html = ansi_to_html(line)
            self.output_view.insertHtml(html)
            self.output_view.moveCursor(QTextCursor.End)

    @pyqtSlot(str, int)
    def _on_done(self, task_id, rc):
        if task_id == 'sql_injector':
            pass

    def _on_run(self):
        url = self.url_input.text().strip()
        if not url: return
        
        level = self.level.value()
        risk = self.risk.value()
        extra = self.flags.text().strip()
        
        # Build command
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        sqlmap_path = os.path.join(base_dir, "modules", "sqlmap-master", "sqlmap.py")
        
        cmd = [sys.executable, sqlmap_path, "-u", url, f"--level={level}", f"--risk={risk}"]
        if extra:
            cmd.extend(extra.split())
        
        self.output_view.clear()
        self.output_view.append(f"<span style='color: #00f2ff;'>[*] Launching SQLMap on {url}...</span>")
        

        
        self._tm.start('sql_injector', cmd)

    def _on_stop(self):
        self._tm.stop('sql_injector')
