import glob, os

from PyQt6.QtGui import QCloseEvent
from PyQt6.QtWidgets import QWidget, QGridLayout, QFileDialog, QInputDialog

from SNetwork.Gui.AppItem import AppItem
from SNetwork.Gui.Banner import BannerWidget
from SNetwork.CommStack.Stack import Stack
from SNetwork.DirectoryService.DirectoryService import DirectoryService
from SNetwork.Utils.Types import Optional


class MainWindow(QWidget):
    _stack: Optional[Stack]
    _directory_service: Optional[DirectoryService]

    def __init__(self, parent=None) -> None:
        super().__init__(parent)

        # Initialize the stack and directory service
        self._stack = None
        self._directory_service = None

        # Create the grid layout.
        layout = QGridLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)

        # Add a banner to the top of the layout
        layout.addWidget(BannerWidget(), 0, 0, 1, 5)

        # Add the buttons
        self._join_button = AppItem(
            parent=self, text="Join Network", icon="./icons/join_network.svg", clicked=self.join)
        self._route_button = AppItem(
            parent=self, text="Create Route", icon="./icons/create_route.svg", clicked=self.route, disabled=True)
        self._store_button = AppItem(
            parent=self, text="Store Data", icon="./icons/store_data.svg", clicked=self.store, disabled=True)
        self._retrieve_button = AppItem(
            parent=self, text="Retrieve Data", icon="./icons/retrieve_data.svg", clicked=self.retrieve, disabled=True)
        self._reset_button = AppItem(
            parent=self, text="Reset", icon="./icons/reset.svg", clicked=self.reset, disabled=False)
        self._host_hidden_service_button = AppItem(
            parent=self, text="Host hidden service", icon="./icons/hidden_service.svg", disabled=True)
        self._directory_button = AppItem(
            parent=self, text="Directory Node", icon="./icons/directory_node.svg", clicked=self.directory, large=True)
        self._exit_application_button = AppItem(
            parent=self, text="Exit Application", icon="./icons/exit_app.svg", clicked=self.exit_app, disabled=False)

        # Add the buttons to the layout
        layout.addWidget(self._join_button, 1, 0)
        layout.addWidget(self._route_button, 1, 1)
        layout.addWidget(self._store_button, 1, 2)
        layout.addWidget(self._retrieve_button, 1, 3)
        layout.addWidget(self._reset_button, 1, 4)
        layout.addWidget(self._host_hidden_service_button, 2, 0)
        layout.addWidget(self._directory_button, 2, 1, 1, 3)
        layout.addWidget(self._exit_application_button, 2, 4)

        # Set the layout of the main window
        self.setLayout(layout)
        self.setStyleSheet("MainWindow {background-color: #404040;}")
        self.showMaximized()

    def reset(self):
        # Remove all files in _crypt
        # Remove all files in _store
        crypt_files = glob.glob("./_crypt/*")
        store_files = glob.glob("./_store/*")
        for file in crypt_files + store_files:
            os.remove(file)

    def join(self) -> None:
        # Button states
        self._join_button._activated = True
        self._join_button.setDisabled(True)
        self._route_button.setDisabled(False)
        self._store_button.setDisabled(False)
        self._retrieve_button.setDisabled(False)

        self._stack = Stack()

    def route(self) -> None:
        # Button states
        self._route_button._activated = True
        self._route_button.setDisabled(True)
        self._host_hidden_service_button.setDisabled(False)

        self._stack.handle_create_route()

    def store(self) -> None:
        open_file_dialog = QFileDialog(self)
        file_directory, _ = open_file_dialog.getOpenFileName(self, "Open File", "", "All Files (*)")
        if file_directory:
            file_contents = open(file_directory, "rb").read()
            self._stack.store_file(file_directory, file_contents)

    def retrieve(self) -> None:
        file_name, _ = QInputDialog.getText(self, "Retrieve File", "Enter the name of the file to retrieve:")
        file_name and self._stack.retrieve_file(file_name)

    def directory(self) -> None:
        # Button states
        self._directory_button._activated = True
        self._directory_button.setDisabled(True)
        self._join_button.setDisabled(True)

        self._directory_service = DirectoryService()

    def exit_app(self) -> None:
        if self._stack and self._stack.level0:
            self._stack.level0.leave()
        super().close()

    def closeEvent(self, event: QCloseEvent) -> None:
        self.exit_app()
        super().closeEvent(event)
