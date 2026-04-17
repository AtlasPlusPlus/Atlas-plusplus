"""
define types and classes that other files can use
"""

from enum import Enum, auto, Flag
from typing import Literal


class InvalidStateError(Exception):
    pass


class Trace(Enum):
    IMM = auto()
    STR = auto()
    REG = auto()
    RET = auto()
    STACK = auto()
    MEM = auto()


TraceResult = (
    tuple[Literal[Trace.IMM], int]  # (IMM, value of imm)
    | tuple[Literal[Trace.STR], str]  # (STR, value of string)
    | tuple[Literal[Trace.REG], int]  # (REG, REG number)
    | tuple[Literal[Trace.RET], int]  # (RET, addr of callsite)
    | tuple[Literal[Trace.STACK], int]  # (STACK, stack-based offset), for env_offset only
    | tuple[Literal[Trace.STACK], None]  # (STACK, failed), for env_offset only
    | tuple[Literal[Trace.MEM], int]
)


class Attribute(Flag):
    NONE = 0  # no attribute actually, a normal argument
    PATH = 2  # string for file path
