__desc__ = "common utils that other files may use"

from termcolor import colored
import sys
import re
import struct
from androguard.core.analysis.analysis import ClassAnalysis, MethodAnalysis, FieldAnalysis
from .shared_def import *
from . import shared


def log(level: LogLevel, msg: str) -> None:
    def strip_color(string: str) -> str:
        ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
        return ansi_escape.sub("", string)

    if level.value < shared.log_level.value:
        return
    match level:
        case LogLevel.DEBUG:
            msg = "[DEBUG] " + msg
            color = None
        case LogLevel.INFO:
            msg = "[INFO] " + strip_color(msg)
            color = "green"
        case LogLevel.WARN:
            msg = "[WARN] " + strip_color(msg)
            color = "yellow"
        case LogLevel.ERROR:
            msg = "[ERROR] " + strip_color(msg)
            color = "red"
    if not sys.stdout.isatty():
        color = None
    print(colored(msg, color))


def get_field_analysis_by_name(class_name: str, field_name: str) -> FieldAnalysis:
    cls = shared.analysis.get_class_analysis(class_name)
    for fld in cls.get_fields():
        if fld.name == field_name:
            return fld
    raise InvalidStateError(f"can't find field {field_name} in {cls.name}")


def get_literal_value(value: int, desc: str) -> int | float:
    """
    if the value is a float, parse it and return the float value
    """
    match desc:
        case "F":
            return struct.unpack("<f", struct.pack("<I", value))[0]
        case "D":
            return struct.unpack("<d", struct.pack("<I", value))[0]
        case _:
            return value


def normalize_classname(classname: str) -> str:
    """
    do not treat String and ByteBuffer as a class
    """
    match classname:
        case "Ljava/lang/String;":
            return "String"
        case "Ljava/nio/ByteBuffer;":
            return "DirectBuffer"
        case _:
            return classname
