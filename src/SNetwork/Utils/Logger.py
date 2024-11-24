from enum import Enum
from logging import Logger
import logging, sys


class LoggerHandlers(Enum):
    LAYER_1 = 0
    LAYER_2 = 1
    LAYER_3 = 2
    LAYER_4 = 3
    LAYER_D = 4
    LAYER_A = 5
    SYSTEM = 6
    CRYPTOGRAPHY = 7


def isolated_logger(logger_name: LoggerHandlers) -> Logger:
    # Create a new logger with the specified name.
    logger_name = logger_name.name.title().split(".")[-1]
    logger = Logger(logger_name)
    logger.setLevel(logging.DEBUG)

    # Only add a handler if one does not already exist.
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(f"[{logger_name}] - %(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    # Return the logger.
    return logger
