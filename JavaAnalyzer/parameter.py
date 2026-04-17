from dataclasses import dataclass

from . import operand
from . import util
from .shared_def import *


@dataclass
class Parameter:
    _reg: int
    _descriptor: str
    attribute: Attribute
    sources: set[operand.Operand]
    traced: bool

    def prune(self) -> None:
        """
        if there're const source, remove all non-const source in `self.sources`. If there're more than 1 STRING_LEN source, remove other STRING_LEN sources.
        """
        const_sources: set[operand.Operand] = {
            source for source in self.sources if source.is_const()
        }
        if const_sources:
            self.sources = const_sources
        elif any(source.type == operand.OpType.UNKNOWN for source in self.sources):
            util.log(LogLevel.DEBUG, f"there're unknown sources of {self}, use const values only.")
            self.sources = const_sources
        strlen_sources = {
            source for source in self.sources if source.type == operand.OpType.STRING_LEN
        }
        if len(strlen_sources) > 1:
            self.sources = self.sources - strlen_sources
            self.sources.add(strlen_sources.pop())

    def __str__(self) -> str:
        return (
            f"{self.descriptor} v{self.reg}, Attribute: {self.attribute}, Sources: {self.sources}"
        )

    def __eq__(self, argument: object) -> bool:
        if type(argument) == Parameter:
            return self is argument
        return False

    def __hash__(self) -> int:
        return id(self)

    @property
    def reg(self):
        return self._reg

    @property
    def descriptor(self):
        return self._descriptor
