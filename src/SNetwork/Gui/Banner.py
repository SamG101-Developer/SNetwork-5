from PyQt6.QtWidgets import QWidget
from PyQt6.QtGui import QPaintEvent, QPainter, QColor, QFont, QPen
from PyQt6.QtCore import Qt


class BannerWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

    def paintEvent(self, event: QPaintEvent):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(32, 32, 32))
        painter.drawRoundedRect(0, 0, self.width(), self.height(), 16, 16)

        font = QFont()
        font.setPointSize(16)
        font.setBold(True)
        painter.setFont(font)

        painter.setPen(QPen(QColor("#404040")))
        painter.drawText(0, 0, self.width(), self.height(), Qt.AlignmentFlag.AlignCenter, "SNetwork Anonymous Network")
