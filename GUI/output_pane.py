"""
CipherPick PyQt5 — Shared ANSI-Colorized Terminal Output Utilities
"""
import re
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextEdit
from PyQt5.QtGui import QTextCursor, QColor
from PyQt5.QtCore import Qt

_ANSI_HTML_MAP = {
    '30': 'color: #555555;',
    '31': 'color: #ff003c;',
    '32': 'color: #00ff00;',
    '33': 'color: #fce205;',
    '34': 'color: #025cf7;',
    '35': 'color: #d122e3;',
    '36': 'color: #00f2ff;',
    '37': 'color: #ffffff;',
    '90': 'color: #555555;',
    '91': 'color: #ff003c;',
    '92': 'color: #00ff00;',
    '93': 'color: #fce205;',
    '94': 'color: #025cf7;',
    '95': 'color: #d122e3;',
    '96': 'color: #00f2ff;',
    '97': 'color: #ffffff;',
    
    # Backgrounds
    '40': 'background-color: #000000;',
    '41': 'background-color: #ff003c; color: #ffffff;',
    '42': 'background-color: #00ff00; color: #000000;',
    '43': 'background-color: #fce205; color: #000000;',
    '44': 'background-color: #025cf7; color: #ffffff;',
    '45': 'background-color: #d122e3; color: #ffffff;',
    '46': 'background-color: #00f2ff; color: #000000;',
    '47': 'background-color: #ffffff; color: #000000;',

    '1':  'font-weight: bold; text-shadow: 0 0 5px currentColor;',
    '2':  'opacity: 0.7;',
}

_ANSI_PATTERN = re.compile(r'\033\[([0-9;]*)m')

def ansi_to_html(text):
    """Converts terminal ANSI escape sequences to HTML spans for QTextEdit."""
    parts = _ANSI_PATTERN.split(text)
    html_out = ""
    span_depth = 0
    
    for i, part in enumerate(parts):
        if i % 2 == 0:
            # Text part - replace spaces with &nbsp; and \n with <br>
            escaped = part.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            escaped = escaped.replace(' ', '&nbsp;').replace('\n', '<br>')
            html_out += escaped
        else:
            # Code part
            codes = part.split(';')
            if '0' in codes or part == '' or part == '0':
                html_out += "</span>" * span_depth
                span_depth = 0
            else:
                style = ""
                for code in codes:
                    if code in _ANSI_HTML_MAP:
                        style += _ANSI_HTML_MAP[code]
                if style:
                    html_out += f'<span style="{style}">'
                    span_depth += 1
    
    html_out += "</span>" * span_depth
    # Wrap in a span with a robust monospaced font
    return f'<span style="font-family: \'Consolas\', \'Monaco\', \'Courier New\', monospace;">{html_out}</span>'

class OutputPane(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)

        # Header
        header = QWidget()
        header.setObjectName("OutputHeader")
        header.setStyleSheet("background-color: #080c12; border-top: 1px solid #1c2333; border-bottom: 1px solid #1c2333;")
        h_layout = QHBoxLayout(header)
        h_layout.setContentsMargins(12, 4, 12, 4)

        lbl = QLabel("● LOGS & OUTPUT")
        lbl.setStyleSheet("color: #445566; font-size: 8pt; font-weight: bold; letter-spacing: 2px;")
        h_layout.addWidget(lbl)
        h_layout.addStretch()

        clear_btn = QPushButton("[ CLEAR ]")
        clear_btn.setObjectName("Destructive")
        clear_btn.setFixedWidth(70)
        clear_btn.clicked.connect(self.clear)
        h_layout.addWidget(clear_btn)

        self.layout.addWidget(header)

        # Terminal Text Area
        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setUndoRedoEnabled(False)
        self.text_edit.setStyleSheet("background-color: #0a0a0c; color: #c9d1d9; border: none;")
        self.layout.addWidget(self.text_edit)

        self.append_ansi("\033[92m[*] CipherPick PyQt5 C2 initialized.\033[0m\n")

    def clear(self):
        self.text_edit.clear()

    def append_ansi(self, text):
        html = ansi_to_html(text)
        self.text_edit.insertHtml(html)
        self.text_edit.moveCursor(QTextCursor.End)

    def append_line(self, text, color=None):
        if color:
            style = f"color: {color};"
            html = f'<span style="{style}">{text}</span><br>'
        else:
            html = f'<span>{text}</span><br>'
        self.text_edit.insertHtml(html)
        self.text_edit.moveCursor(QTextCursor.End)
