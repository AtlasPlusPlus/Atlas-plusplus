__desc__ = "parse enum class"

from collections import defaultdict
from . import shared
from . import method
from . import util

# cache for `_parse_enum`: {classname1: {fieldname1: value1, ...}, ...}
_enum_values: defaultdict[str, dict[str, int]] = defaultdict(dict)


def is_enum(classname: str) -> bool:
    classname = util.normalize_classname(classname)
    if not (classname.startswith("L") and classname.endswith(";")):
        return False
    cls = shared.analysis.get_class_analysis(classname)
    return cls.extends == "Ljava/lang/Enum;"


def _parse_enum(classname: str) -> None:
    """
    parse <clinit> of the enum class and write `_enum_values`
    """
    assert is_enum(classname)
    clinit = shared.analysis.get_method_analysis_by_name(classname, "<clinit>", "()V")
    assert clinit
    clinit = method.get_method(clinit)
    name: str | None = None
    value: int | None = None
    for _, inst in clinit.insts.items():
        if inst.analysis.get_name().startswith("const-string"):
            value = None
            name = inst.operands[-1].points_to
        elif inst.analysis.get_name().startswith("const"):
            if not name:
                continue
            value = inst.operands[-1].value
            _enum_values[classname][name] = value
            name = None


def get_enum_vals(class_name: str) -> list[int]:
    """
    get int values of enum class.
    """
    if not _enum_values[class_name]:
        _parse_enum(class_name)
    return list(_enum_values[class_name].values())


def get_enum_val(class_name: str, field_name: str) -> int:
    """
    get int value of enum field.
    """
    if not _enum_values[class_name]:
        _parse_enum(class_name)
    return _enum_values[class_name][field_name]
