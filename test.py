import subprocess
import time
from threading import Thread

import asn1crypto.algos
import select
from PyQt6.QtCore import QThread, Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QWidget, QGridLayout, QScrollArea, QVBoxLayout, QLabel, QApplication

from SNetwork.Managers.DirectoryServiceManager import DirectoryServiceManager
from SNetwork.Managers.ProfileManager import ProfileManager
from SNetwork.Utils.Types import Optional

NODE_COUNT = 10
W = 5
H = 2
assert W * H == NODE_COUNT


class LogMessageDisplay(QWidget):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setLayout(QVBoxLayout())
        self.setFont(QFont("JetBrains Mono", 5))
        self.layout().setAlignment(Qt.AlignmentFlag.AlignTop)

    def add_new_log_message(self, message: str) -> None:
        label = QLabel(message)
        self.layout().addWidget(label)


class LogMessageScroller(QScrollArea):
    _node_id: int
    _log_message_display: LogMessageDisplay
    _log_message_recv = pyqtSignal(str)
    _program_thread: Thread

    def __init__(self, node_id: int, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._node_id = node_id
        self._log_message_display = LogMessageDisplay()

        # Configure the scroll area.
        self.setWidgetResizable(True)
        self.setWidget(self._log_message_display)
        self.widget().setLayout(QGridLayout())

        # Connect the signal to the display.
        self._log_message_recv.connect(self._log_message_display.add_new_log_message)
        self._program_thread = Thread(target=self.run_node_process)
        self._program_thread.start()

    def run_node_process(self) -> None:
        print(f"Starting process for node {self._node_id}")
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
        print(f"Process for node {self._node_id} has finished.")

    def read_output(self, pipe) -> None:
        while True:
            line = pipe.readline().decode("utf-8").strip()
            if not line:
                break
            self._log_message_recv.emit(line)



class TestGui(QWidget):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle("Test GUI")
        self.setLayout(QGridLayout())

        # Cell for each node (to output log messages)
        for i in range(H):
            for j in range(W):
                log_message_display = LogMessageScroller(i * W + j)
                self.layout().addWidget(log_message_display, i, j)

        self.showMaximized()


def create_directory_services() -> None:
    for i in range(4):
        DirectoryServiceManager.new_directory_service(f"snetwork.directory-service.{i}")


if __name__ == "__main__":
    import sys
    sys.excepthook = lambda e, v, t: sys.__excepthook__(e, v, t)
    create_directory_services()
    app = QApplication(sys.argv)
    window = TestGui()
    sys.exit(app.exec())
