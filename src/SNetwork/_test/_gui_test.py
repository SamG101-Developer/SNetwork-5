import math
import random
import sys
from typing import List, Optional, Tuple, Generator

import shapefile
import shapely.geometry
from OpenGL import GL, GLU
from PyQt6.QtCore import QPoint, QTimer, Qt, QThread, pyqtSignal
from PyQt6.QtGui import QMouseEvent, QFont, QPaintEvent, QPainter, QPen
from PyQt6.QtWidgets import QApplication, QWidget, QGridLayout, QVBoxLayout, QHBoxLayout, QLabel, QSpacerItem, \
    QSizePolicy
from PyQt6.QtOpenGLWidgets import QOpenGLWidget

WATER_COLOR = (.1, .1, .1)
LAND_COLOR = (.15, .15, .15)
BORDER_COLOR = (52 / 255, 120 / 255, 144 / 255)
SELECTED_BORDER_COLOR = (0, 1, 0)
EARTH_RADIUS = 7
ALT = 0


class QEarth(QOpenGLWidget):
    _x: int
    _y: int
    _z: int
    _cx: int
    _cy: int
    _cz: int
    _rx: float
    _ry: float
    _rz: float
    _timer: QTimer

    _polygons: None
    _last_pos: Optional[QPoint]
    _marked: List[int]
    _mouse_locked: bool

    def __init__(self, parent: Optional[QWidget] = None, *args, **kwargs) -> None:
        super().__init__(parent, *args, **kwargs)

        self._x = 0
        self._y = 0
        self._z = 50

        self._cx = self._cy = self._cz = 0
        self._rx = self._ry = self._rz = 0.0

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._rotate)

        self._polygons = None
        self._last_pos = None
        self._marked = []
        self._mouse_locked = True

        self._timer.start(1)

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if not self._mouse_locked:
            self._last_pos = event.pos()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if not self._mouse_locked:
            if event.buttons() == Qt.MouseButton.LeftButton and self._last_pos:
                self._rx += 4 * (event.pos().y() - self._last_pos.y())
                self._ry += 4 * (event.pos().x() - self._last_pos.x())
            self._last_pos = event.pos()
        super().mouseMoveEvent(event)

    def initializeGL(self) -> None:
        GL.glMatrixMode(GL.GL_PROJECTION)
        GL.glFrustum(-1.0, 1.0, -1.0, 1.0, 5.0, 1000.0)

        # Anti-aliasing config
        GL.glEnable(GL.GL_MULTISAMPLE)
        GL.glEnable(GL.GL_LINE_SMOOTH)
        GL.glEnable(GL.GL_POLYGON_SMOOTH)
        GL.glEnable(GL.GL_BLEND)
        GL.glHint(GL.GL_LINE_SMOOTH_HINT, GL.GL_NICEST)
        GL.glHint(GL.GL_POLYGON_SMOOTH_HINT, GL.GL_NICEST)
        GL.glBlendFunc(GL.GL_SRC_ALPHA, GL.GL_ONE_MINUS_SRC_ALPHA)

        self._create_polygons()

    def paintGL(self) -> None:
        GL.glClear(GL.GL_COLOR_BUFFER_BIT | GL.GL_DEPTH_BUFFER_BIT)

        GL.glColor(*WATER_COLOR)
        GL.glEnable(GL.GL_DEPTH_TEST)

        GL.glBegin(GL.GL_POLYGON)
        for vertex in range(0, 100):
            angle, radius = float(vertex) * 2.0 * math.pi / 100, EARTH_RADIUS
            GL.glVertex3f(math.cos(angle) * radius, math.sin(angle) * radius, 0.0)
        GL.glEnd()

        if self._polygons:
            GL.glPushMatrix()
            GL.glRotated(self._rx, 1, 0, 0)
            GL.glRotated(self._ry, 0, 1, 0)
            GL.glRotated(self._rz, 0, 0, 1)
            GL.glCallList(self._polygons)
            GL.glPopMatrix()
        GL.glMatrixMode(GL.GL_MODELVIEW)
        GL.glLoadIdentity()
        GLU.gluLookAt(self._x, self._y, self._z, self._cx, self._cy, self._cz, 0, 1, 0)
        self.update()

    def _rotate(self) -> None:
        # Mock earths true rotation on the tilted y-axis
        self._rx = 270
        self._rz += 1
        self._ry = 23.5
        self.update()

    def _create_polygons(self) -> None:
        if not self.context():
            return

        del self._polygons
        self._polygons = GL.glGenLists(1)
        GL.glNewList(self._polygons, GL.GL_COMPILE)

        # Move marked polygons to the end of the list to draw them last.
        polygons = [*extract_polygons()]

        for i, polygon in enumerate(polygons):
            GL.glLineWidth(1)
            GL.glBegin(GL.GL_LINE_LOOP)
            GL.glColor(*(BORDER_COLOR if i not in self._marked else SELECTED_BORDER_COLOR))
            for lon, lat in polygon.exterior.coords:
                point = llh_to_ecef(lat, lon, ALT)
                GL.glVertex3f(*point)
            GL.glEnd()

            color = LAND_COLOR if i not in self._marked else SELECTED_BORDER_COLOR
            GL.glColor(*color)
            GL.glBegin(GL.GL_TRIANGLES)
            for vertex in polygon_tesselator(polygon):
                GL.glVertex(*vertex)
            GL.glEnd()

        # Draw 3d arcs between the marked countries. Arcs are curved above the earth's surface.
        if len(self._marked) > 1:
            GL.glLineWidth(1)
            GL.glBegin(GL.GL_LINE_STRIP)
            GL.glColor(*SELECTED_BORDER_COLOR)
            polygons = [*extract_polygons()]
            for country, next_country in zip(self._marked, self._marked[1:]):
                country = polygons[country]
                next_country = polygons[next_country]

                country_point = (country.centroid.y, country.centroid.x, ALT)
                next_country_point = (next_country.centroid.y, next_country.centroid.x, ALT)

                # Arc over the earths surface from the "country_point" to the "next_country_point".
                GL.glVertex3f(*llh_to_ecef(*country_point))
                iterations = 100
                for i in range(1, iterations + 1):
                    angle = i * math.pi / iterations
                    lat = country_point[0] + (next_country_point[0] - country_point[0]) / iterations * i
                    lon = country_point[1] + (next_country_point[1] - country_point[1]) / iterations * i
                    alt = country_point[2] + (next_country_point[2] - country_point[2]) / iterations * i

                    # elevate the alt to make a 3d arc with vertical distance.
                    alt += 2 * math.sin(angle)

                    GL.glVertex3f(*llh_to_ecef(lat, lon, alt))

            GL.glEnd()

        GL.glEndList()

    def mark_countries(self, countries: List[int]) -> None:
        # Mark multiple countries with a red border.
        self._marked.extend(countries)
        self._create_polygons()

    @staticmethod
    def random_country() -> int:
        # A random country must be a Polygon. Either select a Polygon, or the largest sub-polygon of a multi-polygon.
        polygons = [*extract_polygons()]
        i, polygon = random.choice(list(enumerate(polygons)))

        if polygon.geom_type == "MultiPolygon":
            polygon = max(polygon.geoms, key=lambda p: p.area)

        return i


def polygon_tesselator(polygon: shapely.geometry.Polygon) -> List[Tuple[float, float, float]]:
    vertices = []
    tess = GLU.gluNewTess()

    GLU.gluTessCallback(tess, GLU.GLU_TESS_EDGE_FLAG_DATA, lambda *_: None)
    GLU.gluTessCallback(tess, GLU.GLU_TESS_VERTEX, lambda v: vertices.append(v))
    GLU.gluTessCallback(tess, GLU.GLU_TESS_COMBINE, lambda v, *_: v)
    GLU.gluTessCallback(tess, GLU.GLU_TESS_END, lambda: None)

    GLU.gluTessBeginPolygon(tess, 0)
    GLU.gluTessBeginContour(tess)
    for lon, lat in polygon.exterior.coords:
        point = llh_to_ecef(lat, lon, ALT)
        GLU.gluTessVertex(tess, point, point)

    GLU.gluTessEndContour(tess)
    GLU.gluTessEndPolygon(tess)
    GLU.gluDeleteTess(tess)
    return vertices


def extract_polygons() -> Generator[shapely.geometry.Polygon, None, None]:
    sf = shapefile.Reader("World.shp")
    polygons = sf.shapes()

    for i, polygon in enumerate(polygons):
        polygon = shapely.geometry.shape(polygon)

        match polygon.geom_type:
            case "Polygon":
                yield polygon
            case "MultiPolygon":
                yield from polygon.geoms


def llh_to_ecef(lat: float, lon: float, alt: float) -> Tuple[float, float, float]:
    a = EARTH_RADIUS
    f = 1 / 298.257223563
    b = a * (1 - f)
    e2 = 1 - (pow(b, 2) / pow(a, 2))

    lat_rad = math.radians(lat)
    lon_rad = math.radians(lon)
    N = a / math.sqrt(1 - e2 * pow(math.sin(lat_rad), 2))

    X = (N + alt) * math.cos(lat_rad) * math.cos(lon_rad)
    Y = (N + alt) * math.cos(lat_rad) * math.sin(lon_rad)
    Z = (N * (1 - e2) + alt) * math.sin(lat_rad)

    return X, Y, Z


class Window(QWidget):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setLayout(QGridLayout())

        ROWS, COLS = 4, 9

        # Add 8x6 earth widgets to the layout.
        for i in range(ROWS):
            for j in range(COLS):
                self.add_earth(i, j)

        # Add stretch on right side to center the earth widgets.
        self.layout().addItem(QSpacerItem(0, 0, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum), 0, COLS)

        self.showMaximized()

    def paintEvent(self, event: QPaintEvent) -> None:
        # Draw a background color.
        painter = QPainter(self)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(Qt.GlobalColor.black)
        painter.drawRect(self.rect())

    def add_earth(self, i, j):
        self.layout().addWidget(EarthContainer(), i, j)


class EarthContainer(QWidget):
    _mark_countries_signal = pyqtSignal(list)

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setLayout(QVBoxLayout())
        self.layout().setSpacing(0)

        self.earth = QEarth()
        countries = [self.earth.random_country() for _ in range(4)]
        polygons = [*extract_polygons()]
        locations = [(polygons[country].centroid.y, polygons[country].centroid.x, ALT) for country in countries]
        self._mark_countries_signal.connect(self.earth.mark_countries)
        self._mark_countries_signal.emit(countries)

        self.layout().addWidget(self.earth)
        self.layout().addWidget(EarthLabelCard(locations))

        SIZE = 180
        self.earth.setFixedSize(SIZE - 10, SIZE - 10)
        self.setFixedWidth(SIZE)

    def paintEvent(self, event: QPaintEvent) -> None:
        # Rounded rectangle
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QPen(Qt.GlobalColor.darkGray, 2))
        painter.setBrush(Qt.GlobalColor.black)
        painter.drawRoundedRect(self.rect(), 10, 10)


class EarthLabelCard(QWidget):
    def __init__(self, locations: List[Tuple[float, float, float]], parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setLayout(QVBoxLayout())
        self.layout().setContentsMargins(0, 0, 0, 0)
        self.layout().setSpacing(4)
        self.setFont(QFont("JetBrains Mono", 6))

        lat = self._format_coord(locations[0][0])
        lon = self._format_coord(locations[0][1])
        self.layout().addWidget(self._create_inner_label("Client:", f"({lat}, {lon})"))

        for i, location in enumerate(locations[1:], start=1):
            lat = self._format_coord(location[0])
            lon = self._format_coord(location[1])
            self.layout().addWidget(self._create_inner_label(f"Hop-{i}:", f"({lat}, {lon})"))
        self.layout().addItem(QSpacerItem(0, 0, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

    def _format_coord(self, coord: float) -> str:
        coord = f"{coord:.3f}"
        coord.zfill(8)
        return coord

    def _create_inner_label(self, lhs_label: str, rhs_label: str) -> QWidget:
        container = QWidget()
        container.setLayout(QHBoxLayout())
        container.layout().addWidget(QLabel(lhs_label), alignment=Qt.AlignmentFlag.AlignLeft)
        container.layout().addWidget(QLabel(rhs_label), alignment=Qt.AlignmentFlag.AlignRight)
        container.layout().setContentsMargins(0, 0, 0, 0)
        container.layout().setSpacing(0)
        return container


if __name__ == "__main__":
    sys.excepthook = lambda *args: sys.__excepthook__(*args)
    app = QApplication(sys.argv)
    window = Window()
    sys.exit(app.exec())
