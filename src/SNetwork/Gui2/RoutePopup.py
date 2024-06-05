from PyQt6.QtCore import pyqtSlot, Qt, QRectF, QVariantAnimation
from PyQt6.QtWidgets import QDialog
from PyQt6.QtGui import QPaintEvent, QPainter, QColor, QFont

from SNetwork.Utils.Types import Str
from SNetwork.Config import HOP_COUNT


class RoutePopup(QDialog):
    def __init__(self, parent=None, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.setWindowTitle("Route Progress")
        self.setFixedSize(640, 480)

        from SNetwork.CommunicationStack.Layer2 import Layer2
        self._progress_cur = 0.0
        self._progress_max = len(Layer2.ROUTING_STATUS_MESSAGES) * HOP_COUNT
        self._message = ""

        self._progress_animation = QVariantAnimation(self, duration=100)
        self._progress_animation.valueChanged.connect(self._update_progress)

    @pyqtSlot(str)
    def status_update(self, message: Str) -> None:
        self._message = message

        self._progress_animation.stop()
        self._progress_animation.setStartValue(self._progress_cur)
        self._progress_animation.setEndValue(self._progress_cur + 1)
        self._progress_animation.start()

    # @pyqtSlot(float)
    def _update_progress(self, progress: float) -> None:
        self._progress_cur = progress
        self.repaint()

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Background of the progress bar.
        painter.setBrush(QColor(192, 192, 192))
        painter.setPen(Qt.PenStyle.NoPen)

        # Circles distributed along the progress bar for each node + the client node.
        diameter = 20
        line_thickness = 10
        # for i in range(HOP_COUNT + 1):
        #     x = self.width() * 0.1 + i * (self.width() * 0.8 / HOP_COUNT) - diameter / 2
        #     y = self.height() * 0.5 - diameter / 2
        #     painter.drawEllipse(QRectF(x, y, diameter, diameter))
        painter.drawRect(QRectF(self.width() * 0.1, self.height() * 0.5 - line_thickness / 2, self.width() * 0.8, line_thickness))

        # Re-draw a percentage of the path to show progress.
        frac = min(self._progress_cur / self._progress_max, 1)
        painter.setBrush(QColor(128, 0, 255))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRect(QRectF(self.width() * 0.1, self.height() * 0.5 - line_thickness / 2, self.width() * 0.8 * frac, line_thickness))

        # Draw part of any circles that are covered by the progress bar.
        for i in range(HOP_COUNT + 1):
            x = self.width() * 0.1 + i * (self.width() * 0.8 / HOP_COUNT) - diameter / 2
            y = self.height() * 0.5 - diameter / 2
            if x < self.width() * 0.1 + self.width() * 0.8 * frac:
                painter.drawEllipse(QRectF(x, y, diameter, diameter))
                identifier = "Client" if i == 0 else f"Node {i}"
                painter.setPen(QColor(224, 224, 224))
                painter.setFont(QFont("Jetbrains Mono", 7))
                painter.drawText(QRectF(x - 50, y + diameter / 2, diameter + 100, self.height() * 0.1), Qt.AlignmentFlag.AlignCenter, identifier)
                painter.setPen(Qt.PenStyle.NoPen)

        # Add text
        painter.setPen(QColor(224, 224, 224))
        painter.setFont(QFont("Jetbrains Mono", 9))
        painter.drawText(QRectF(0, self.height() * 0.5, self.width(), self.height() * 0.2), Qt.AlignmentFlag.AlignCenter, self._message)


if __name__ == "__main__":
    import sys
    import secrets

    from PyQt6.QtCore import QObject, pyqtSignal, QTimer
    from PyQt6.QtWidgets import QApplication

    class Tester(QObject):
        _status_update = pyqtSignal(str)

        def __init__(self, route_popup: RoutePopup):
            super().__init__()
            self._route_popup = route_popup
            self._status_update.connect(self._route_popup.status_update)

            self._timer = QTimer(self)
            self._timer.timeout.connect(self.update)
            self._timer.start(500)

        @pyqtSlot()
        def update(self):
            self._status_update.emit(secrets.token_hex(16))

    sys.excepthook = lambda *args: sys.__excepthook__(*args)
    app = QApplication(sys.argv)
    route_popup = RoutePopup()
    tester = Tester(route_popup)
    route_popup.show()
    app.exec()
