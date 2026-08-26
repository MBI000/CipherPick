from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
                             QComboBox, QPushButton, QTextEdit)
from PyQt5.QtCore import Qt
import os
import sys
import base64

# Import the backend engine
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
try:
    import engine
except ImportError:
    engine = None

class CryptoScreen(QWidget):
    def __init__(self, task_manager, output_pane):
        super().__init__()
        self._tm = task_manager
        self._output_pane = output_pane
        
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(20, 20, 20, 20)
        self.layout.setSpacing(15)

        title = QLabel("CRYPTO ENGINE")
        title.setStyleSheet("color: #00f2ff; font-size: 16pt; font-weight: bold;")
        self.layout.addWidget(title)

        self.algo_combo = QComboBox()
        self.algo_combo.addItems(["SHA-256", "AES-128", "RSA-2048"])
        self.layout.addWidget(QLabel("Algorithm:"))
        self.layout.addWidget(self.algo_combo)

        self.payload = QTextEdit()
        self.payload.setPlaceholderText("Enter text to process...")
        self.layout.addWidget(QLabel("Input Data:"))
        self.layout.addWidget(self.payload)

        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Encryption Key (if needed)")
        self.layout.addWidget(QLabel("Key:"))
        self.layout.addWidget(self.key_input)

        btn_row = QHBoxLayout()
        enc_btn = QPushButton("[ ENCRYPT / HASH ]")
        enc_btn.clicked.connect(self._on_encrypt)
        btn_row.addWidget(enc_btn)
        
        dec_btn = QPushButton("[ DECRYPT ]")
        dec_btn.clicked.connect(self._on_decrypt)
        btn_row.addWidget(dec_btn)
        self.layout.addLayout(btn_row)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setStyleSheet("background-color: #0a0a0c; border: 1px solid #1c2333;")
        self.layout.addWidget(QLabel("Output:"))
        self.layout.addWidget(self.output)

    def _on_encrypt(self):
        if not engine:
            self.output.setText("Error: Engine module not found.")
            return
        
        algo = self.algo_combo.currentText()
        data = self.payload.toPlainText().encode('utf-8')
        if not data: return
        
        try:
            if algo == "SHA-256":
                res = engine.generate_sha256(data)
                self.output.setText(res)
            elif algo == "AES-128":
                key = self.key_input.text().encode('utf-8')
                if not key:
                    self.output.setText("Error: AES key required.")
                    return
                res = engine.aes_encrypt(data, key)
                self.output.setText(base64.b64encode(res).decode('utf-8'))
            elif algo == "RSA-2048":
                # Mock/Simple for now, matching app.py logic would need key loading
                self.output.setText("RSA Encryption requires key loading (see app.py pattern)")
        except Exception as e:
            self.output.setText(f"Error: {e}")

    def _on_decrypt(self):
        if not engine: return
        
        algo = self.algo_combo.currentText()
        data_str = self.payload.toPlainText()
        if not data_str: return
        
        try:
            if algo == "AES-128":
                key = self.key_input.text().encode('utf-8')
                raw = base64.b64decode(data_str)
                res = engine.aes_decrypt(raw, key)
                self.output.setText(res.decode('utf-8', errors='replace'))
            else:
                self.output.setText(f"{algo} does not support standard decryption here.")
        except Exception as e:
            self.output.setText(f"Error: {e}")

    def show_tool(self, tool_id):
        if tool_id == "aes":
            self.algo_combo.setCurrentText("AES-128")
        elif tool_id == "rsa":
            self.algo_combo.setCurrentText("RSA-2048")
        elif tool_id == "sha":
            self.algo_combo.setCurrentText("SHA-256")
