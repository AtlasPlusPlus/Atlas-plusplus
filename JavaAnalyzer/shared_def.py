from enum import Enum, auto, Flag
from termcolor import colored
import sys


class Attribute(Flag):
    IGNORE = 0  # no attribute, we don't care about
    TRACE = auto()  # no attribute, we'll trace it
    PATH = auto()  # string for file path
    SIZE = auto()
    FD = auto()  # file descritpor (int)

    def __str__(self) -> str:
        string = self.name
        assert string, f"unknown attribute: {self.value}"
        if sys.stdout.isatty():
            for name in sorted(Attribute._member_names_, key=len, reverse=True):
                if name in string and name != "TRACE":
                    string = string.replace(name, colored(name, "green", attrs=["bold"]))
        return string


class LogLevel(Enum):
    DEBUG = auto()
    INFO = auto()
    WARN = auto()
    ERROR = auto()


class InvalidStateError(Exception):
    pass


class WontImplementError(NotImplementedError):
    pass
