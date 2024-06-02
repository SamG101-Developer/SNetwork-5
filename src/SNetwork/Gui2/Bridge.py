from typing import Optional

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QDialog, QLabel, QVBoxLayout
from PyQt6.QtCore import Qt

from SNetwork.Gui2.MainWindow import Window
from SNetwork.CommunicationStack.CommunicationStack import CommunicationStack


class Bridge:
    _f: Window
    _b: CommunicationStack

    _help_popup: Optional[QDialog]

    def __init__(self, f: Window, b: CommunicationStack) -> None:
        self._f = f
        self._b = b
        self._help_popup = None

        self._create_help_popup()

    def _create_help_popup(self) -> None:
        self._help_popup = QDialog(self._f)
        self._help_popup.setWindowTitle("Help")
        self._help_popup.setFixedSize(640, 480)

        text = """
        <h1>SNetwork</h1>
        <p>The SNetwork is a secure network that allows for absolute anonymity whilst browsing the internet. It is a
        distributed peer-to-peer network that is not controlled by any single entity. The network uses layered
        authenticated encryption to ensure that all data is secure and private.</p>
        
        <h2>Creating a Route</h2>
        <p>Click the "Create Route" button to create a route through the network. This will allow you to browse the
        internet securely and privately. Once you have created a route, you can stop it at any time by clicking the
        "Stop Route" button.</p>
        
        <h2>Using S-Apps</h2>
        <p>There are several S-Apps available that allow you to communicate, store data, and browse the internet. You
        can access these apps by clicking the corresponding buttons on the main screen.</p>
        """

        # Set the rich text to the dialog
        label = QLabel(text)
        label.setOpenExternalLinks(True)
        label.setWordWrap(True)
        label.setFont(QFont("Jetbrains Mono", 9))

        self._help_popup.setLayout(QVBoxLayout())
        self._help_popup.layout().addWidget(label)

    def create_route(self) -> None:
        self._f._create_route_button.setEnabled(False)
        self._f._stop_route_button.setEnabled(True)
        self._f._s_message_button.setEnabled(True)
        self._f._s_net_button.setEnabled(True)
        self._f._s_drive_button.setEnabled(True)
        self._f._s_mail_button.setEnabled(True)

    def stop_route(self) -> None:
        self._f._create_route_button.setEnabled(True)
        self._f._stop_route_button.setEnabled(False)
        self._f._s_message_button.setEnabled(False)
        self._f._s_net_button.setEnabled(False)
        self._f._s_drive_button.setEnabled(False)
        self._f._s_mail_button.setEnabled(False)

    def help(self) -> None:
        self._help_popup.show()
        self._help_popup.raise_()
        self._help_popup.activateWindow()
