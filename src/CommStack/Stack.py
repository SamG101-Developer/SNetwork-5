from threading import Thread

from src.CommStack.Level0 import Level0
from src.CommStack.Level1 import Level1
from src.CommStack.Level2 import Level2
from src.CommStack.LevelD import LevelD
from src.Utils.Types import Optional


class Stack:
    level0: Optional[Level0]
    level1: Optional[Level1]
    level2: Optional[Level2]
    levelD: Optional[LevelD]

    def __init__(self):
        self.level0 = self.level1 = self.level2 = self.levelD = None
        Thread(target=self._init_level_0).start()
        Thread(target=self._init_level_1).start()
        Thread(target=self._init_level_2).start()
        Thread(target=self._init_level_D).start()

    def _init_level_0(self):
        self.level0 = Level0()

    def _init_level_1(self):
        while not self.level0: pass
        self.level1 = Level1(self.level0)

    def _init_level_2(self):
        while not self.level1: pass
        self.level2 = Level2(self.level1)

    def _init_level_D(self):
        while not self.level0: pass
        self.levelD = LevelD(self.level0)

    def handle_create_route(self):
        while not self.level2: pass
        self.level2.create_route()

    def store_file(self, file_directory) -> None:
        while not self.level0: pass
        self.level0.put(file_directory)

    def retrieve_file(self, file_name) -> None:
        while not self.level0: pass
        self.level0.get(file_name)
