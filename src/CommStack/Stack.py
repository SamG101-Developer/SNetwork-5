from src.CommStack.Level2 import Level2
from src.CommStack.LevelD import LevelD


class Stack:
    levelD: LevelD
    level2: Level2

    def __init__(self):
        self.levelD = LevelD(self.level2._level1._level0)
        self.level2 = Level2()

    def handle_create_route(self):
        self.level2.create_route()

    def store_file(self, file_directory) -> None:
        self.level2._level1._level0.put(file_directory)

    def retrieve_file(self, file_name) -> None:
        self.level2._level1._level0.get(file_name)
