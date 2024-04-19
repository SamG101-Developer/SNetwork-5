from PyQt6.QtWidgets import QWidget, QGridLayout, QFileDialog, QInputDialog

from src.Gui.AppItem import AppItem
from src.Gui.Banner import BannerWidget
from src.CommStack.Stack import Stack
from src.DirectoryService.DirectoryService import DirectoryService
from src.Utils.Types import Optional


class MainWindow(QWidget):
    _stack: Optional[Stack]
    _directory_service: Optional[DirectoryService]

    def __init__(self, parent=None) -> None:
        super().__init__(parent)

        # Create the grid layout.
        layout = QGridLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)

        # Add a banner to the top of the layout
        layout.addWidget(BannerWidget(), 0, 0, 1, 4)

        # Add the buttons
        self._join_button = AppItem(
            parent=self, text="Join Network", icon="./icons/join_network.svg", clicked=self.join)
        self._route_button = AppItem(
            parent=self, text="Create Route", icon="./icons/create_route.svg", clicked=self.route, disabled=True)
        self._store_button = AppItem(
            parent=self, text="Store Data", icon="./icons/store_data.svg", clicked=self.store, disabled=True)
        self._retrieve_button = AppItem(
            parent=self, text="Retrieve Data", icon="./icons/retrieve_data.svg", clicked=self.retrieve, disabled=True)
        self._host_hidden_service_button = AppItem(
            parent=self, text="Host hidden service", icon="./icons/hidden_service.svg", disabled=True)
        self._directory_button = AppItem(
            parent=self, text="Directory Node", icon="./icons/directory_node.svg", clicked=self.directory, large=True)
        self._dummy_button_r = AppItem(
            parent=self, text="", disabled=True)

        # Add the buttons to the layout
        layout.addWidget(self._join_button, 1, 0)
        layout.addWidget(self._route_button, 1, 1)
        layout.addWidget(self._store_button, 1, 2)
        layout.addWidget(self._retrieve_button, 1, 3)
        layout.addWidget(self._host_hidden_service_button, 2, 0)
        layout.addWidget(self._directory_button, 2, 1, 1, 2)
        layout.addWidget(self._dummy_button_r, 2, 3)

        # Set the layout of the main window
        self.setLayout(layout)
        self.setStyleSheet("MainWindow {background-color: #404040;}")
        self.showMaximized()

    def join(self) -> None:
        # Button states
        self._join_button._activated = True
        self._join_button.setDisabled(True)
        self._route_button.setDisabled(False)

        self._stack = Stack()

    def route(self) -> None:
        # Button states
        self._route_button._activated = True
        self._route_button.setDisabled(True)
        self._store_button.setDisabled(False)
        self._host_hidden_service_button.setDisabled(False)
        self._retrieve_button.setDisabled(False)

        self._stack.handle_user_command("route")

    def store(self) -> None:
        open_file_dialog = QFileDialog(self)
        file_directory, _ = open_file_dialog.getOpenFileName(self, "Open File", "", "All Files (*)")
        file_directory and self._stack.store_file(file_directory)

    def retrieve(self) -> None:
        file_name, _ = QInputDialog.getText(self, "Retrieve File", "Enter the name of the file to retrieve:")
        file_name and self._stack.retrieve_file(file_name)

    def directory(self) -> None:
        # Button states
        self._directory_button._activated = True
        self._directory_button.setDisabled(True)
        self._join_button.setDisabled(True)

        self._directory_service = DirectoryService()
