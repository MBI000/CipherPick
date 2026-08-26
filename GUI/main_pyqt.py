"""
CipherPick PyQt5 — Application Entry Point
"""
import sys
import os
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import QFile, QTextStream

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from .app_window import AppWindow

def main():
    app = QApplication(sys.argv)
    
    # Load Stylesheet
    style_file = QFile(os.path.join(os.path.dirname(__file__), "style.qss"))
    if style_file.open(QFile.ReadOnly | QFile.Text):
        stream = QTextStream(style_file)
        app.setStyleSheet(stream.readAll())
    
    window = AppWindow()
    window.showMaximized()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
