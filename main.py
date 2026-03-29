"""
main.py — Entry point for CryptoApp
Usage  : python main.py
Requires: pip install cryptography customtkinter matplotlib
"""

import sys
import os

# Ensure the project root is in the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gui.main_window import MainApp


def main():
    app = MainApp()
    app.mainloop()


if __name__ == "__main__":
    main()
