from PyQt6.QtWidgets import QPushButton, QSizePolicy
from PyQt6.QtGui import QPaintEvent, QPainter, QColor, QFont, QPen, QPixmap
from PyQt6.QtCore import QSize, Qt, QVariantAnimation, QEasingCurve, QEvent


class AppItem(QPushButton):
    _activated: bool

    def __init__(self, parent=None, **kwargs):
        super().__init__(parent)
        self._activated = False
        self._text = kwargs.get("text", "")
        self._icon = kwargs.get("icon", "")
        self.clicked.connect(kwargs.get("clicked", lambda: None))
        self.setDisabled(kwargs.get("disabled", False))

        policy = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
        policy.setHeightForWidth(False) if kwargs.get("large", False) else policy.setHeightForWidth(True)
        self.setSizePolicy(policy)

        self._hover_animation = QVariantAnimation(self)
        self._hover_animation.setStartValue(QColor(32, 32, 32))
        self._hover_animation.setEndValue(QColor(48, 48, 48))
        self._hover_animation.valueChanged.connect(self.repaint)
        self._hover_animation.setDuration(150)
        self._hover_animation.setEasingCurve(QEasingCurve.Type.InOutSine)

        self._disabled_color = QColor(48, 48, 48)

    def sizeHint(self):
        return QSize(self.width(), self.width())

    def heightForWidth(self, width: int):
        return width

    def paintEvent(self, event: QPaintEvent):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen if self.isEnabled() and not self._activated else QPen(QColor(0, 255, 0)) if self._activated else QPen(QColor(255, 0, 0), 2))
        painter.setBrush(self._hover_animation.currentValue() if self.isEnabled() else self._disabled_color)

        painter.drawRoundedRect(0, 0, self.width(), self.height(), 16, 16)
        pixmap = QPixmap(self._icon)
        if not pixmap.isNull():
            pixmap = pixmap.scaled(
                self.width() // 2, self.height() // 2, Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation)
        painter.drawPixmap((self.width() - pixmap.width()) // 2, self.height() // 8, pixmap)

        font = QFont()
        font.setPointSize(16)
        font.setBold(True)
        painter.setFont(font)

        painter.setPen(QPen(QColor("#404040")))
        painter.drawText(0, self.height() // 2, self.width(), 3 * self.height() // 4, Qt.AlignmentFlag.AlignCenter,
                         self._text)

    def event(self, event: QEvent):
        if event.type() == QEvent.Type.HoverEnter and self.isEnabled():
            self._hover_animation.stop()
            self._hover_animation.setDirection(QVariantAnimation.Direction.Forward)
            self._hover_animation.start()
        elif event.type() == QEvent.Type.HoverLeave and self.isEnabled():
            self._hover_animation.stop()
            self._hover_animation.setDirection(QVariantAnimation.Direction.Backward)
            self._hover_animation.start()
        return super().event(event)