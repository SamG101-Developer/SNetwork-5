import json
import subprocess
import time
from threading import Thread, Lock

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QWidget, QGridLayout, QScrollArea, QVBoxLayout, QLabel, QApplication

from SNetwork.Config import DIRECTORY_SERVICE_PRIVATE_FILE
from SNetwork.Managers.DirectoryServiceManager import DirectoryServiceManager
from SNetwork.Managers.ProfileManager import ProfileManager
from SNetwork.Utils.Files import SafeFileOpen
from SNetwork.Utils.Types import Optional

NODE_COUNT = 14
DIR_NODE_COUNT = 4
W = 6
H = 3
assert W * H == NODE_COUNT + DIR_NODE_COUNT


class LogMessageDisplay(QWidget):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setLayout(QVBoxLayout())
        self.setFont(QFont("JetBrains Mono", 5))
        self.layout().setAlignment(Qt.AlignmentFlag.AlignTop)

    def add_new_log_message(self, message: str) -> None:
        label = QLabel(message)
        label.setWordWrap(False)
        self.layout().addWidget(label)


class LogMessageScroller(QScrollArea):
    _node_id: int
    _log_message_display: LogMessageDisplay
    _log_message_recv = pyqtSignal(str)
    _program_thread: Thread
    _io_lock: Lock

    def __init__(self, node_id: int, is_dir: bool, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._node_id = node_id
        self._is_dir = is_dir
        self._log_message_display = LogMessageDisplay()
        self._io_lock = Lock()

        # Configure the scroll area.
        self.setWidgetResizable(True)
        self.setWidget(self._log_message_display)
        self.widget().setLayout(QGridLayout())

        # Connect the signal to the display.
        self._log_message_recv.connect(self._log_message_display.add_new_log_message)

        if not is_dir:
            self._program_thread = Thread(target=self.run_node_process)
            self._program_thread.start()
        else:
            self._program_thread = Thread(target=self.run_dir_process)
            self._program_thread.start()

    def run_node_process(self) -> None:
        username, password = (f"username_{self._node_id}", "pass")
        ProfileManager.create_profile(username, password)
        command = f".venv/Scripts/python main.py join --name {username} --pass {password}"

        # Create the process and link the logging to pipes.
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Read the output from the process.
        Thread(target=self.read_output, args=(process.stdout,), daemon=True).start()
        Thread(target=self.read_output, args=(process.stderr,), daemon=True).start()

        # Wait for the process to finish.
        process.wait()

    def run_dir_process(self) -> None:
        name = f"snetwork.directory-service.{self._node_id}"
        with SafeFileOpen(DIRECTORY_SERVICE_PRIVATE_FILE % name, "r") as file:
            secret_key = json.load(file)["secret_key"]
        command = f".venv/Scripts/python main.py directory --name snetwork.directory-service.{self._node_id}"

        # Create the process and link the logging to pipes.
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Read the output from the process.
        Thread(target=self.read_output, args=(process.stdout,), daemon=True).start()
        Thread(target=self.read_output, args=(process.stderr,), daemon=True).start()

        # Wait for the process to finish.
        process.wait()

    def read_output(self, pipe) -> None:
        while True:
            line = pipe.readline().decode("utf-8").strip()
            if not line:
                break
            with self._io_lock:
                self._log_message_recv.emit(line)


class TestGui(QWidget):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle("Test GUI")
        self.setLayout(QGridLayout())

        # Cell for each node (to output log messages)
        counter = 0
        for i in range(H):
            for j in range(W):
                n = i * W + j
                if n < DIR_NODE_COUNT:
                    log_message_display = LogMessageScroller(n, True, self)
                else:
                    log_message_display = LogMessageScroller(n - DIR_NODE_COUNT, False, self)
                self.layout().addWidget(log_message_display, i, j)
                counter += 1

        self.showMaximized()


def create_directory_services() -> None:
    for i in range(4):
        DirectoryServiceManager.new_directory_service(f"snetwork.directory-service.{i}")


if __name__ == "__main__":
    import sys

    sys.excepthook = lambda e, v, t: sys.__excepthook__(e, v, t)
    # create_directory_services()
    app = QApplication(sys.argv)
    window = TestGui()
    sys.exit(app.exec())
