from PyQt6.QtWidgets import QApplication
import logging, os, sys

from src.Gui.MainWindow import MainWindow


def main() -> None:
    if not os.path.exists("_crypt"):
        os.mkdir("_crypt")

    logging.basicConfig(level=logging.DEBUG)
    sys.excepthook = lambda *args: sys.__excepthook__(*args)
    app = QApplication(sys.argv)
    window = MainWindow()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
