"""
CipherPick PyQt5 — Steganography Screen
"""
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
                             QComboBox, QPushButton, QScrollArea, QFrame, QTextEdit, QFileDialog)
from PyQt5.QtCore import Qt

class SteganographyScreen(QWidget):
    def __init__(self, task_manager, output_pane):
        super().__init__()
        self._tm = task_manager
        self._output_pane = output_pane
        
        self.layout = QVBoxLayout(self)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll_content = QWidget()
        self.scroll_layout = QVBoxLayout(self.scroll_content)
        self.scroll_layout.setContentsMargins(20, 20, 20, 20)
        
        self._build_content()
        self.scroll.setWidget(self.scroll_content)
        self.layout.addWidget(self.scroll)

    def _build_content(self):
        title = QLabel("STEGANOGRAPHY")
        title.setStyleSheet("color: #00f2ff; font-size: 16pt; font-weight: bold;")
        self.scroll_layout.addWidget(title)

        self.op_combo = QComboBox()
        self.op_combo.addItems([
            "Encode Text in Text",
            "Decode Text from Text",
            "Encode Text in Image",
            "Decode Text from Image",
            "Encode Image in Image",
            "Decode Image from Image"
        ])
        self.scroll_layout.addWidget(QLabel("Operation:"))
        self.scroll_layout.addWidget(self.op_combo)

        self.cover_file = self._add_input_row("Cover/Stego File:")
        self.secret_file = self._add_input_row("Secret File (if image):")
        
        self.scroll_layout.addWidget(QLabel("Secret Text (if text):"))
        self.secret_text = QTextEdit()
        self.secret_text.setMaximumHeight(100)
        self.scroll_layout.addWidget(self.secret_text)

        exec_btn = QPushButton("[ EXECUTE ]")
        exec_btn.clicked.connect(self._on_execute)
        self.scroll_layout.addWidget(exec_btn)
        
        self.scroll_layout.addStretch()

    def _add_input_row(self, label):
        row = QWidget()
        l = QHBoxLayout(row)
        l.setContentsMargins(0, 0, 0, 0)
        l.addWidget(QLabel(label), 1)
        edit = QLineEdit()
        l.addWidget(edit, 3)
        btn = QPushButton("...")
        btn.setFixedWidth(30)
        btn.clicked.connect(lambda: self._browse(edit))
        l.addWidget(btn)
        self.scroll_layout.addWidget(row)
        return edit

    def _browse(self, edit):
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path: edit.setText(path)

    def _on_execute(self):
        op = self.op_combo.currentText()
        self._output_pane.append_ansi(f"[*] Running {op}...\n")

    def show_tool(self, tool_id):
        if tool_id == "text_steg":
            self.op_combo.setCurrentText("Encode Text in Text")
        elif tool_id == "img_steg":
            self.op_combo.setCurrentText("Encode Text in Image")
