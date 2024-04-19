from PyQt6.QtWidgets import QApplication
import logging, sys

from src.Gui.MainWindow import MainWindow


def main() -> None:
    logging.basicConfig(level=logging.DEBUG)
    sys.excepthook = lambda *args: sys.__excepthook__(*args)
    app = QApplication(sys.argv)
    window = MainWindow()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
