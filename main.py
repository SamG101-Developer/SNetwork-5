from PyQt6.QtWidgets import QApplication, QErrorMessage
import logging, os, sys

from src.Gui.MainWindow import MainWindow


def custom_excepthook(type, value, traceback) -> None:
    QErrorMessage.qtHandler().showMessage(f"{type.__name__}: {value}")
    logging.exception(f"{type.__name__}: {value}")
    sys.__excepthook__(type, value, traceback)


def main() -> None:
    if not os.path.exists("_crypt"):
        os.mkdir("_crypt")

    logging.basicConfig(level=logging.DEBUG)
    sys.excepthook = custom_excepthook
    app = QApplication(sys.argv)
    window = MainWindow()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
