from PyQt6.QtWidgets import QApplication
import sys

from src.Gui.MainWindow import MainWindow


def main() -> None:
    sys.excepthook = lambda *args: sys.__excepthook__(*args)
    app = QApplication(sys.argv)
    window = MainWindow()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
