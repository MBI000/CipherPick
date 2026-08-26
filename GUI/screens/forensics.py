"""
CipherPick PyQt5 — Digital Forensics Screen
"""
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
                             QComboBox, QPushButton, QScrollArea, QSplitter, QTextEdit, QFileDialog)
from PyQt5.QtCore import Qt

class ForensicsScreen(QWidget):
    def __init__(self, task_manager, output_pane):
        super().__init__()
        self._tm = task_manager
        self._output_pane = output_pane
        
        self.layout = QVBoxLayout(self)
        
        title = QLabel("DIGITAL FORENSICS")
        title.setStyleSheet("color: #00f2ff; font-size: 16pt; font-weight: bold; margin: 10px;")
        self.layout.addWidget(title)

        self.op_combo = QComboBox()
        self.op_combo.addItems([
            "Full File Analysis",
            "Extract Strings",
            "Directory Scanner"
        ])
        self.layout.addWidget(QLabel("Analysis Type:"))
        self.layout.addWidget(self.op_combo)

        row = QWidget()
        l = QHBoxLayout(row)
        l.addWidget(QLabel("Target Path:"), 1)
        self.path_input = QLineEdit()
        l.addWidget(self.path_input, 3)
        btn = QPushButton("...")
        btn.clicked.connect(self._browse)
        l.addWidget(btn)
        self.layout.addWidget(row)

        analyze_btn = QPushButton("[ ANALYZE ]")
        analyze_btn.clicked.connect(self._on_analyze)
        self.layout.addWidget(analyze_btn)

        # Text comparison
        self.layout.addWidget(QLabel("Text Tampering Comparison:"))
        splitter = QSplitter(Qt.Horizontal)
        self.text1 = QTextEdit()
        self.text1.setPlaceholderText("Original Text")
        self.text2 = QTextEdit()
        self.text2.setPlaceholderText("Suspected Text")
        splitter.addWidget(self.text1)
        splitter.addWidget(self.text2)
        self.layout.addWidget(splitter)

        comp_btn = QPushButton("[ COMPARE ]")
        comp_btn.clicked.connect(self._on_compare)
        self.layout.addWidget(comp_btn)

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path: self.path_input.setText(path)

    def _on_analyze(self):
        op = self.op_combo.currentText()
        path = self.path_input.text()
        self._output_pane.append_ansi(f"[*] Analyzing {path} with {op}...\n")

    def _on_compare(self):
        t1 = self.text1.toPlainText()
        t2 = self.text2.toPlainText()
        if t1 == t2:
            self._output_pane.append_ansi("<span style='color: #00ff00;'>[+] Texts match.</span>\n")
        else:
            self._output_pane.append_ansi("<span style='color: #ff003c;'>[!] Tampering detected.</span>\n")

    def show_tool(self, tool_id):
        if tool_id == "file_analysis":
            self.op_combo.setCurrentText("Full File Analysis")
        elif tool_id == "string_extraction":
            self.op_combo.setCurrentText("Extract Strings")
        elif tool_id == "dir_scanner":
            self.op_combo.setCurrentText("Directory Scanner")
