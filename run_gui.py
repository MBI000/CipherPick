"""
CipherPick — run_gui.py
Launcher for the PyQt5 desktop interface.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from GUI.main_pyqt import main

if __name__ == '__main__':
    main()
