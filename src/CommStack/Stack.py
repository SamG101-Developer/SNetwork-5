from src.CommStack.Level0 import Level0
from src.CommStack.Level1 import Level1
from src.CommStack.Level2 import Level2
from src.CommStack.LevelD import LevelD
from threading import Thread


class Stack:
    _level0: Level0
    _level1: Level1
    _level2: Level2
    _levelD: LevelD

    def __init__(self):
        self._level0 = self._level1 = self._level2 = self._levelD = None
        Thread(target=self._init_level_0).start()
        Thread(target=self._init_level_1).start()
        Thread(target=self._init_level_2).start()
        Thread(target=self._init_level_D).start()

    def _init_level_0(self):
        self._level0 = Level0()

    def _init_level_1(self):
        while not self._level0: pass
        self._level1 = Level1(self._level0)

    def _init_level_2(self):
        while not self._level1: pass
        self._level2 = Level2(self._level1)

    def _init_level_D(self):
        while not self._level0: pass
        self._levelD = LevelD(self._level0)

    def handle_create_route(self):
        self._level2.create_route()

    def store_file(self, file_directory) -> None:
        self._level2._level1._level0.put(file_directory)

    def retrieve_file(self, file_name) -> None:
        self._level2._level1._level0.get(file_name)

    @property
    def levelD(self):
        return self._levelD

    @property
    def level2(self):
        return self._level2

    @property
    def level1(self):
        return self._level2._level1

    @property
    def level0(self):
        return self._level2._level1._level0
