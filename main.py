from PyQt6.QtWidgets import QApplication
import logging, os, sys
import nest_asyncio

from SNetwork.Gui2.MainWindow import Window


nest_asyncio.apply()


def custom_excepthook(type, value, traceback) -> None:
    logging.exception(f"{type.__name__}: {value}")
    sys.__excepthook__(type, value, traceback)


def main() -> None:
    if not os.path.exists("_crypt"):
        os.mkdir("_crypt")

    logging.basicConfig(level=logging.DEBUG)
    sys.excepthook = custom_excepthook
    app = QApplication(sys.argv)
    window = Window()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
