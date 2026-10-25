"""
USB Sentinel AI - Main Application Entrypoint
Full-Stack Desktop USB Forensics and AI Threat Intelligence Application.
"""

import sys
import os
import subprocess
import shutil

# Check if PyQt6 can be imported. If Anaconda's conflicting Qt DLLs cause an ImportError,
# seamlessly re-launch using the clean Python 3.12 or 'py' launcher.
try:
    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtCore import Qt
    from gui import MainWindow
except ImportError as err:
    script_path = os.path.abspath(__file__)
    clean_python = r"C:\Users\Anup\AppData\Local\Programs\Python\Python312\python.exe"
    if os.path.exists(clean_python) and os.path.normpath(sys.executable).lower() != os.path.normpath(clean_python).lower():
        sys.exit(subprocess.call([clean_python, script_path] + sys.argv[1:]))
    py_bin = shutil.which("py")
    if py_bin:
        sys.exit(subprocess.call([py_bin, script_path] + sys.argv[1:]))
    raise err


def exception_hook(exctype, value, traceback):
    """Global exception hook to prevent silent crashes and log errors."""
    print(f"[FATAL UNCAUGHT EXCEPTION]: {exctype.__name__}: {value}")
    sys.__excepthook__(exctype, value, traceback)


def main():
    # Set exception hook
    sys.excepthook = exception_hook

    # Ensure running in project root
    project_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_dir)

    # Initialize PyQt6 application
    app = QApplication(sys.argv)
    app.setApplicationName("USB Sentinel AI")
    app.setOrganizationName("Sentinel Security Systems")
    app.setApplicationVersion("1.0.0")

    # High-DPI font sharpness
    font = app.font()
    if font.pointSize() > 0:
        font.setPointSize(10)
    app.setFont(font)

    # Launch Main Dashboard Window
    window = MainWindow()
    window.show()

    # Enter Qt Event Loop
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
