import glob
import json
import os
import subprocess
from threading import Thread, Lock

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QMouseEvent
from PyQt6.QtWidgets import QWidget, QGridLayout, QScrollArea, QVBoxLayout, QLabel, QDialog, QApplication

from SNetwork.Config import DIRECTORY_SERVICE_PRIVATE_FILE, DIRECTORY_SERVICE_PUBLIC_FILE
from SNetwork.Managers.DirectoryServiceManager import DirectoryServiceManager
from SNetwork.Managers.KeyManager import KeyManager
from SNetwork.Managers.ProfileManager import ProfileManager
from SNetwork.Utils.Files import SafeFileOpen
from SNetwork.Utils.Types import Optional

NODE_COUNT = 14
DIR_NODE_COUNT = 4
W = 6
H = 3
assert W * H == NODE_COUNT + DIR_NODE_COUNT


class LogMessageDisplay(QWidget):
    _messages: list[str]

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._messages = []

        self.setLayout(QVBoxLayout())
        self.setFont(QFont("JetBrains Mono", 5))
        self.layout().setAlignment(Qt.AlignmentFlag.AlignTop)

    def add_new_log_message(self, message: str) -> None:
        self._messages.append(message)
        label = QLabel(message)
        label.setWordWrap(False)
        self.layout().addWidget(label)

    def nth_message(self, n: int) -> str:
        return self._messages[n]


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

        # Connect the signal to the display.
        self._log_message_recv.connect(self._log_message_display.add_new_log_message)

        if not is_dir:
            self._program_thread = Thread(target=self.run_node_process)
            self._program_thread.start()
        else:
            self._program_thread = Thread(target=self.run_dir_process)
            self._program_thread.start()

    def mousePressEvent(self, event: QMouseEvent) -> None:
        # Bring text up in an expanded dialog (bigger font, more readable)

        dialog = QDialog(self)
        dialog.setLayout(QVBoxLayout())
        dialog.layout().setAlignment(Qt.AlignmentFlag.AlignTop)
        dialog.setWindowTitle(f"Node {self._node_id} Log Messages")
        dialog.setFixedSize(800, 600)
        dialog.setWindowOpacity(0.9)

        scroller = QScrollArea(dialog)
        scroller.setWidgetResizable(True)
        scroller.setWidget(LogMessageDisplay())
        scroller.widget().setFont(QFont("JetBrains Mono", 10))

        for i in range(self._log_message_display.layout().count()):
            log_message = self._log_message_display.nth_message(i)
            scroller.widget().add_new_log_message(log_message)

        dialog.layout().addWidget(scroller)
        dialog.show()

    def run_node_process(self) -> None:
        username, password = (f"username_{self._node_id}", "pass")
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
    for file in glob.glob(DIRECTORY_SERVICE_PRIVATE_FILE % "*"):
        if os.path.exists(file):
            os.chmod(file, 0o700)
            os.remove(file)
    with SafeFileOpen(DIRECTORY_SERVICE_PUBLIC_FILE, "w") as file:
        json.dump({}, file)

    for i in range(4):
        username = f"snetwork.directory-service.{i}"
        if info := DirectoryServiceManager.validate_directory_profile(username):
            KeyManager.del_info(info[0])
        DirectoryServiceManager.create_directory_profile(username)


def create_nodes(n: int, offset: int = 0) -> None:
    for i in range(offset, n + offset):
        username, password = (f"username_{i}", "pass")
        ProfileManager.create_profile(username, password)
        command = f".venv/Scripts/python main.py profile create --name {username} --pass {password}"
        subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


if __name__ == "__main__":
    import sys

    sys.excepthook = lambda e, v, t: sys.__excepthook__(e, v, t)
    # create_directory_services()
    # create_nodes(NODE_COUNT)
    app = QApplication(sys.argv)
    window = TestGui()
    sys.exit(app.exec())
