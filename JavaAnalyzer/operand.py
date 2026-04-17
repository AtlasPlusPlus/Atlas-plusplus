from enum import Enum, auto
from dataclasses import dataclass
from androguard.core.analysis.analysis import ClassAnalysis, MethodAnalysis, FieldAnalysis
from androguard.core.dex import ClassDefItem
import sys
from . import shared
from . import jenum
from . import util
from .shared_def import *


class OpType(Enum):
    """
    see `dex_type.Operand` and `dex_type.Kind` of androguard
    """

    REGISTER = 0
    LITERAL = auto()
    RAW = auto()
    OFFSET = auto()

    METH = 0x100
    STRING = auto()
    FIELD = auto()
    TYPE = auto()
    VARIES = auto()
    INLINE_METHOD = auto()
    VTABLE_OFFSET = auto()
    FIELD_OFFSET = auto()
    RAW_STRING = auto()
    PROTO = auto()
    METH_PROTO = auto()
    CALL_SITE = auto()

    # new enums
    RETURN_VALUE = auto()
    ARGUMENT = auto()
    NEW_ARRAY = auto()
    ARRAY_LEN = auto()
    STRING_LEN = auto()
    NEW_BUFFER = auto()
    NEW_STRING = auto()
    UNKNOWN = auto()  # top-level argument, and there's no caller to analyze
    NULL_REF = auto()


@dataclass(unsafe_hash=True)
class Operand:
    _type: OpType

    # reg num for REGISTER
    # -1 for RETURN_VALUE
    # caller_arg_index for ARGUMENT
    # size for ARRAY
    # array-ref-number for ARRAY_LEN
    # offset of length() callsite for STRING_LEN
    # reference number for reference
    # str for RAW
    # 0 for NULL_REF
    _value: int | str
    _points_to: str | None  # points to a string/method/field or descritpor (such as "[B").

    def __init__(self, operand: tuple[OpType, int | str] | tuple[int, int, str]):
        if len(operand) == 2:
            # REGISTER, LITERAL, OFFSET
            op_type, value = operand
            op_type = op_type.value
            points_to = None
        else:
            op_type, value, points_to = operand
        self._type = OpType(op_type)
        self._value = value
        self._points_to = points_to

    def is_const(self) -> bool:
        if self.type in {OpType.LITERAL, OpType.STRING, OpType.RAW, OpType.NULL_REF}:
            return True
        assert type(self._value) == int
        if self.type in {OpType.NEW_ARRAY, OpType.NEW_BUFFER} and self._value > 0:
            return True
        if self.type == OpType.FIELD:
            class_name, _, _ = self.get_field_info()
            return jenum.is_enum(class_name)
        return False

    def is_external(self) -> bool:
        def cls_is_external(clsname: str) -> bool:
            if clsname.startswith("Ljava/"):
                return False
            cls = shared.analysis.get_class_analysis(clsname)
            if not cls:
                return True
            return cls.is_external()

        if self.type == OpType.METH:
            method_analysis = self.get_method_analysis()
            if not method_analysis:
                return True
            if method_analysis.is_external():
                return True
            arg_descs, _, _ = method_analysis.get_descriptor().removeprefix("(").partition(")")
            for arg_desc in arg_descs.split():
                if not (arg_desc.startswith("L") and arg_desc.endswith(";")):
                    continue
                if arg_desc.startswith("Ljava/"):
                    continue
                arg_cls = shared.analysis.get_class_analysis(arg_desc)
                if arg_cls.is_external():
                    return True
            return False
        elif self.type == OpType.TYPE:
            assert self.points_to
            return cls_is_external(self.points_to)
        elif self.type == OpType.FIELD:
            clsname, _, _ = self.get_field_info()
            return cls_is_external(clsname)
        raise InvalidStateError

    def is_interface(self) -> bool:
        def cls_is_interface(clsname: str) -> bool:
            if clsname.startswith("Ljava/"):
                return False
            clazz = shared.analysis.get_class_analysis(clsname).get_class()
            assert isinstance(clazz, ClassDefItem)
            if "interface" in clazz.get_access_flags_string():
                return True
            return False

        if self.type == OpType.METH:
            assert self._points_to
            classname, _, _ = self._points_to.partition("->")
            return cls_is_interface(classname)
        elif self.type == OpType.TYPE:
            assert self.points_to
            return cls_is_interface(self.points_to)
        raise InvalidStateError

    def get_field_info(self) -> tuple[str, str, str]:
        """
        parse `self._points_to` string, e.g.
        "Lcom/samsung/android/panorama/InterfaceNative;->mGlobalPtr J"

        :return (classname, field_name, field_desc):
        """
        assert self._points_to
        classname, _, member = self._points_to.partition("->")
        field_name, _, field_desc = member.partition(" ")
        return classname, field_name, field_desc

    def get_method_analysis(self) -> MethodAnalysis | None:
        """
        parse `self._points_to` to MethodAnalysis.
        e.g. "Landroid/graphics/Bitmap;->createBitmap(Landroid/graphics/Bitmap; I I I I Landroid/graphics/Matrix; Z)Landroid/graphics/Bitmap;"
        """
        assert self.type == OpType.METH and self._points_to
        classname, _, member = self._points_to.partition("->")
        method_name, _, method_desc = member.partition("(")
        method_desc = "(" + method_desc
        method_analysis = shared.analysis.get_method_analysis_by_name(
            classname, method_name, method_desc
        )
        return method_analysis

    def __str__(self) -> str:
        string = f"type: {self._type.name}, value: {self._value}"
        if sys.stdout.isatty():
            for name in sorted(OpType._member_names_, key=len, reverse=True):
                if name == self._type.name and name in {
                    "LITERAL",
                    "STRING",
                    "NEW_ARRAY",
                    "ARRAY_LEN",
                    "STRING_LEN",
                    "NEW_BUFFER",
                    "NEW_STRING",
                    "NULL_REF",
                }:
                    string = string.replace(name, colored(name, "green", attrs=["bold"]))
                    break
        if self._points_to:
            string += f", points_to: {self._points_to}"
        return string

    def __repr__(self) -> str:
        return self.__str__()

    def __eq__(self, operand: object) -> bool:
        if type(operand) == Operand:
            eq = self.type == operand.type
            if self.type == OpType.METH and self.points_to:
                eq = eq and self.points_to == operand.points_to
            else:
                eq = eq and self.value == operand.value
            return eq
        return False

    @property
    def type(self):
        return self._type

    @property
    def value(self):
        return self._value

    @property
    def points_to(self):
        return self._points_to


NULL_REF = Operand((OpType.NULL_REF, 0))
UNKNOWN = Operand((OpType.UNKNOWN, -1))
