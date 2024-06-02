import os

from PyQt6.QtWidgets import QWidget, QPushButton, QGraphicsDropShadowEffect, QGridLayout, QSizePolicy, QSpacerItem
from PyQt6.QtCore import QVariantAnimation, QEvent, QSize, Qt, QRectF
from PyQt6.QtGui import QColor, QEnterEvent, QPainter, QPaintEvent, QBrush, QResizeEvent, QPen, QFont, QPainterPath, \
    QTransform

from SNetwork.Utils.Types import Optional


class Widget(QPushButton):
    def __init__(self, parent: Optional[QWidget] = None, *args, **kwargs) -> None:
        super().__init__(parent, *args, **kwargs)
        self.setGraphicsEffect(QGraphicsDropShadowEffect(self, xOffset=0, yOffset=0, blurRadius=32, color=QColor(64, 64, 64, 24)))
        self._hover_animation = QVariantAnimation()
        self._setup_hover_animation()

    def _setup_hover_animation(self) -> None:
        self._hover_animation.setStartValue(QColor(255, 255, 255))
        self._hover_animation.setEndValue(QColor(240, 240, 240))
        self._hover_animation.setDuration(200)
        self._hover_animation.valueChanged.connect(self.repaint)

    def enterEvent(self, event: QEnterEvent) -> None:
        self._hover_animation.stop()
        self._hover_animation.setDirection(QVariantAnimation.Direction.Forward)
        self._hover_animation.start()
        super().enterEvent(event)

    def leaveEvent(self, event: QEvent) -> None:
        self._hover_animation.stop()
        self._hover_animation.setDirection(QVariantAnimation.Direction.Backward)
        self._hover_animation.start()
        super().leaveEvent(event)

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setBrush(QBrush(self._hover_animation.currentValue()))
        painter.setPen(Qt.PenStyle.NoPen)

        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.drawRoundedRect(self.rect(), 48, 48)

        font = QFont("Jetbrains Mono", 12, QFont.Weight.Bold)
        painter.setFont(font)
        painter.setPen(QPen(QColor(96, 96, 96)))
        painter.drawText(QRectF(0, self.height() * 0.8, self.width(), self.height() * 0.2), Qt.AlignmentFlag.AlignCenter, self.text())


class Button(Widget):
    def __init__(self, parent: Optional[QWidget] = None, *args, **kwargs) -> None:
        self._coming_soon = kwargs.pop("coming_soon") if "coming_soon" in kwargs else False
        super().__init__(parent, *args, **kwargs)
        self.setFixedSize(256, 256)
        # self._setup_size_policy()

    # def _setup_size_policy(self) -> None:
    #     policy = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
    #     policy.setHeightForWidth(True)
    #     self.setSizePolicy(policy)
    #
    # def heightForWidth(self, width: int) -> int:
    #     return width

    def paintEvent(self, event: QPaintEvent) -> None:
        if self.isEnabled():
            super().paintEvent(event)
        else:
            painter = QPainter(self)
            painter.setBrush(QBrush(QColor(240, 240, 240)))
            painter.setPen(QPen(QColor(255, 255, 255), 4))
            painter.drawRoundedRect(self.rect(), 48, 48)

            font = QFont("Jetbrains Mono", 12, QFont.Weight.Bold)
            painter.setFont(font)
            painter.setPen(QPen(QColor(96, 96, 96)))
            painter.drawText(QRectF(0, self.height() * 0.8, self.width(), self.height() * 0.2), Qt.AlignmentFlag.AlignCenter, self.text())
            painter.end()

        # Add red diagonal banner over top-right corner with text "Coming Soon"
        if self._coming_soon:
            painter = QPainter(self)
            path = QPainterPath()
            path.moveTo(self.width() * 0.5, 0)
            path.lineTo(self.width() * 0.8, 0)
            path.lineTo(self.width(), self.height() * 0.2)
            path.lineTo(self.width(), self.height() * 0.5)
            path.lineTo(self.width() * 0.5, 0)

            painter.setBrush(QBrush(QColor("#886600CC")))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawPath(path)
            painter.end()

            painter = QPainter(self)
            font = QFont("Jetbrains Mono", 11, QFont.Weight.Bold)
            painter.setFont(font)
            painter.setTransform(QTransform().translate(self.width() * 0.5, self.height() * -0.5).rotate(45))
            painter.setPen(QPen(QColor(240, 240, 240)))
            painter.drawText(QRectF(self.width() * 0.5, 0, self.width() * 0.5, self.height() * 0.5), Qt.AlignmentFlag.AlignCenter, "Coming Soon")
            painter.end()


class Window(QWidget):
    def __init__(self, parent: Optional[QWidget] = None, *args, **kwargs) -> None:
        super().__init__(parent, *args, **kwargs)
        from SNetwork.Gui2.Bridge import Bridge

        self._bridge = Bridge(self, None)
        self._make_buttons()
        self._setup_layout()
        self.showFullScreen()

    def _make_buttons(self) -> None:
        self._create_route_button = Button(self, text="Create Route", clicked=self._bridge.create_route)
        self._stop_route_button = Button(self, text="Stop Route", enabled=False, clicked=self._bridge.stop_route)
        self._help_button = Button(self, text="Help", clicked=self._bridge.help)
        self._configure_button = Button(self, text="Configure", enabled=False, coming_soon=True)
        self._browse_hs_button = Button(self, text="Browse HS", enabled=False, coming_soon=True)
        self._s_mail_button = Button(self, text="S-Mail", enabled=False, coming_soon=True)
        self._s_message_button = Button(self, text="S-Message", enabled=False, coming_soon=True)
        self._s_drive_button = Button(self, text="S-Drive", enabled=False, coming_soon=True)
        self._s_net_button = Button(self, text="S-Net", enabled=False, coming_soon=True)

    def _setup_layout(self) -> None:
        layout = QGridLayout()
        layout.setSpacing(64)
        layout.setContentsMargins(64, 64, 64, 64)

        layout.addWidget(self._create_route_button, 0, 0)
        layout.addWidget(self._stop_route_button, 0, 1)
        layout.addWidget(self._help_button, 0, 2)
        layout.addWidget(self._configure_button, 0, 3)
        layout.addWidget(self._browse_hs_button, 0, 4)
        layout.addWidget(self._s_mail_button, 1, 0)
        layout.addWidget(self._s_message_button, 1, 1)
        layout.addWidget(self._s_drive_button, 1, 2)
        layout.addWidget(self._s_net_button, 1, 3)

        # Spacer at bottom and right
        layout.addItem(QSpacerItem(0, 0, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding), 2, 0, 1, 4)
        layout.addItem(QSpacerItem(0, 0, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding), 0, 9, 2, 1)
        self.setLayout(layout)

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(QColor(255, 255, 255)))
        painter.drawRect(self.rect())


if __name__ == "__main__":
    from PyQt6.QtWidgets import QApplication
    import sys

    # Set to light mode with equivalent of c++ qputenv("QT_QPA_PLATFORM", "windows:darkmode=0")
    os.environ["QT_QPA_PLATFORM"] = "windows:darkmode=0"

    sys.excepthook = lambda *args: sys.__excepthook__(*args)
    app = QApplication(sys.argv)
    window = Window()
    window.show()
    app.exec()
