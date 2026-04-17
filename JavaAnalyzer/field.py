from __future__ import annotations

from androguard.core.analysis.analysis import ClassAnalysis, MethodAnalysis, FieldAnalysis
from androguard.core.dex import EncodedValue
from androguard.core import dex
from dataclasses import dataclass
from collections import defaultdict
from enum import Enum, auto
from . import operand
from . import util
from . import method
from . import jenum
from . import shared
from .shared_def import *


def _parse_encoded_value(encoded_value: EncodedValue) -> operand.Operand:
    value_type = encoded_value.get_value_type()
    if dex.VALUE_BYTE <= value_type <= dex.VALUE_LONG:
        value = encoded_value.get_value()
        assert type(value) == int
        return operand.Operand((operand.OpType.LITERAL, value))
    elif dex.VALUE_FLOAT <= value_type <= dex.VALUE_DOUBLE:
        value = encoded_value.get_value()
        raise NotImplementedError("fix androguard float/double parsing")
    elif value_type == dex.VALUE_BOOLEAN:
        value = encoded_value.get_value()
        assert type(value) == bool
        return operand.Operand((operand.OpType.LITERAL, 1 if value else 0))
    elif value_type == dex.VALUE_NULL:
        return operand.NULL_REF
    else:
        raise NotImplementedError(f"encoded value type: {hex(value_type)}")


@dataclass
class Field:
    _analysis: FieldAnalysis
    _sources: set[operand.Operand]  # STRING | NEW_ARRAY | METH | non-zero LITERAL
    _writers: list[method.Method]  # native writers, they set this field
    _producers: list[method.Method]  # their return values are used to fill this field
    attribute: Attribute

    def __init__(self, analysis: FieldAnalysis) -> None:
        self._analysis = analysis
        self._sources = set()
        self._writers = []
        self._producers = []
        self.attribute = Attribute.IGNORE
        if analysis.get_field().get_descriptor() == "Z":
            self.sources.add(operand.Operand((operand.OpType.LITERAL, 0)))
            self.sources.add(operand.Operand((operand.OpType.LITERAL, 1)))
            return
        if any(keyword in analysis.name.casefold() for keyword in shared.SIZE_KEYWORDS):
            self.attribute |= Attribute.SIZE
        if (
            any(keyword in analysis.name.casefold() for keyword in shared.PATH_KEYWORDS)
            and analysis.get_field().get_descriptor() == "Ljava/lang/String;"
        ):
            self.attribute |= Attribute.PATH
        self._trace_xref_write()

    def _trace_xref_write(self) -> None:
        """
        trace sources of field, and write `self._values`, `self._writers` and `self._producers`
        """
        util.log(LogLevel.DEBUG, f"tracing field {self}")
        sources: set[operand.Operand] = set()
        init_val = self.analysis.get_field().get_init_value()
        if init_val:
            val = _parse_encoded_value(init_val)
            if not (val.type == operand.OpType.LITERAL and not val.value):
                self._sources.add(val)

        # trace sources
        for wt_cls, wt_mthd, write_site in self.analysis.get_xref_write(True):
            writer = method.get_method(wt_mthd)
            if "native" in wt_mthd.access:
                self._writers.append(writer)
                continue
            sink = writer.insts[write_site].operands[-1]
            sources |= writer.trace_sources(write_site, sink)
        if any(source.type == operand.OpType.UNKNOWN for source in sources):
            util.log(LogLevel.DEBUG, f"there're unknown sources of {self}, use const values only.")
            sources = set(src for src in sources if src.is_const())
        for source in sources:
            if source.type == operand.OpType.FIELD:  # enum field?
                field_source = source.points_to
                assert field_source
                cls_name, fld_name, _ = source.get_field_info()
                if jenum.is_enum(cls_name):
                    continue
                field_source = util.get_field_analysis_by_name(cls_name, fld_name)
                if field_source == self.analysis:
                    continue
                field_source = get_field(field_source)
                self._sources |= field_source.sources
            elif source.type in {operand.OpType.LITERAL, operand.OpType.STRING}:
                if source.value:
                    self._sources.add(source)
            elif source.type == operand.OpType.TYPE:
                if not (source.is_external() or source.is_interface()):
                    self._sources.add(source)
            elif source.type == operand.OpType.REGISTER:
                continue
            else:
                self._sources.add(source)

        # record producers
        for source in self.sources:
            if source.type != operand.OpType.METH:
                continue
            method_analysis = source.get_method_analysis()
            if not method_analysis:
                continue
            if any(keyword in method_analysis.name.casefold() for keyword in shared.SIZE_KEYWORDS):
                self.attribute |= Attribute.SIZE
            if (
                any(keyword in method_analysis.name.casefold() for keyword in shared.PATH_KEYWORDS)
                and self.analysis.get_field().get_descriptor() == "Ljava/lang/String;"
            ):
                self.attribute |= Attribute.PATH
            if method_analysis.is_external():
                desc = util.normalize_classname(self.analysis.get_field().get_descriptor())
                if desc.startswith("L") and desc.endswith(";"):
                    raise WontImplementError(
                        f"external method {method_analysis.full_name} is not supported yet!"
                    )
            if source.is_external():
                util.log(
                    LogLevel.DEBUG,
                    f"ignore external method source {method_analysis.full_name}",
                )
                continue
            if source.is_interface():
                util.log(LogLevel.DEBUG, f"ignore interface {source}")
                continue
            producer = method.get_method(method_analysis)
            self._producers.append(producer)
        util.log(LogLevel.DEBUG, f"traced field {self}, sources: {self.sources}, ")
        util.log(LogLevel.DEBUG, f"- writers: {self.writers}")
        util.log(LogLevel.DEBUG, f"- producers: {self.producers}")

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        return f"{self.analysis.field.get_class_name()} {self.analysis.name}"

    def __eq__(self, field: object) -> bool:
        if type(field) == Field:
            return self.__str__() == field.__str__()
        return False

    def __hash__(self) -> int:
        return self.__str__().__hash__()

    @property
    def analysis(self):
        return self._analysis

    @property
    def sources(self):
        return self._sources

    @property
    def writers(self):
        return self._writers

    @property
    def producers(self):
        return self._producers


# {classname: {fieldname1: field1, ...}, ...}
_fields: defaultdict[str, dict[str, Field]] = defaultdict(dict)


def get_field(field_analysis: FieldAnalysis) -> Field:
    """
    get the field. create it if it doesn't exist.
    """
    class_name = field_analysis.field.get_class_name()
    if field_analysis.name not in _fields[class_name]:
        _fields[class_name][field_analysis.name] = Field(field_analysis)
    return _fields[class_name][field_analysis.name]
