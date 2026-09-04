__desc__ = "parse *.json to get native api basic info"

from dataclasses import dataclass
from androguard.core.analysis.analysis import ClassAnalysis, MethodAnalysis, FieldAnalysis
from collections import defaultdict
from typing import Iterator, NewType
import os
import numpy
import json
import copy
from .. import config
from ..NativeAnalyzer import api
from .shared_def import *
from . import util
from . import method
from . import operand
from . import shared


# for dynamicly linked native API, ID is java_name&sig
# for staticly linked native API, ID is java_name (if no override) or java_name&param_sig
ApiId = NewType("ApiId", str)
# {libname: {api_id1: api1, ...}, ...}
_apis: defaultdict[str, dict[ApiId, api.API]] = defaultdict(dict)


def _is_active(method: MethodAnalysis) -> bool:
    """
    an api is active iff it's public or one of its callers is active
    """
    if any(keyword in method.access for keyword in ("public", "static constructor")):
        return True
    for _, caller, _ in method.get_xref_from():
        if _is_active(caller):
            return True
    return False


def _get_ApiId(libname: str, method: MethodAnalysis) -> ApiId | None:
    sig = method.get_descriptor().replace(" ", "")
    if method.name + sig in _apis[libname]:
        return ApiId(method.name + sig)
    sig = sig.split(")")[0] + ")"
    if method.name + sig in _apis[libname]:
        return ApiId(method.name + sig)
    if method.name in _apis[libname]:
        return ApiId(method.name)


def get_class_lib(cls: ClassAnalysis) -> str | None:
    """
    get native library of the class if any.
    """

    def get_possible_libnames_from_loadLibrary(cls: ClassAnalysis) -> set[str]:
        possible_libnames: set[str] = set()
        possible_libs: set[operand.Operand] = set()
        for method_analysis in cls.get_methods():
            if "native" in method_analysis.access:
                continue
            if "static" not in method_analysis.access:
                continue
            clinit = method.get_method(method_analysis)
            for offset, inst in clinit.insts.items():
                if (
                    inst.analysis.get_name() == "invoke-virtual"
                    and inst.operands[-1].points_to
                    and inst.operands[-1].points_to
                    == "Ljava/lang/Runtime;->loadLibrary(Ljava/lang/String;)V"
                ) or (
                    inst.analysis.get_name() == "invoke-static"
                    and inst.operands[-1].points_to
                    and inst.operands[-1].points_to
                    == "Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V"
                ):
                    possible_libs |= clinit.trace_sources(offset, inst.operands[-2])
        for possible_lib in possible_libs:
            if possible_lib.type == operand.OpType.STRING:
                assert possible_lib.points_to
                possible_libnames.add(f"lib{possible_lib.points_to}.so")
            else:
                raise NotImplementedError(f"possible_lib: {possible_lib}")
        return possible_libnames

    native_methods = [mthd for mthd in cls.get_methods() if "native" in mthd.access]
    if not native_methods:
        return
    # get param sring of system.loadLibrary(), and check api integrity
    possible_libnames = get_possible_libnames_from_loadLibrary(cls)
    if not possible_libnames:
        util.log(LogLevel.DEBUG, f"can't find library from loadLibrary() of {cls.name}")
        for libname in _apis:
            if all(_get_ApiId(libname, mthd) for mthd in native_methods):
                return libname
    for possible_libname in possible_libnames:
        if _apis[possible_libname] and any(
            _get_ApiId(possible_libname, mthd) for mthd in native_methods
        ):
            return possible_libname
    if len(possible_libnames) == 1:
        return possible_libnames.pop()


def find_api(libname: str, method: MethodAnalysis) -> api.API | None:
    api_id = _get_ApiId(libname, method)
    if api_id:
        return _apis[libname][api_id]


def get_valuable_apis(cls: ClassAnalysis, native_lib: str) -> Iterator[MethodAnalysis]:
    """
    yield high value apis for fuzzing if any
    """

    def is_empty(native_api: api.API) -> bool:
        # an api that only calls __android_log_print has 6 insts
        # an api that calls __android_log_print and returns 0 has 11 insts
        return (
            native_api.inst_count <= 11
            and native_api.call_depth <= 1
            and native_api.cyc_complexity <= 1
        )

    for method in cls.get_methods():
        if "native" not in method.access:
            continue
        if not _is_active(method):
            util.log(LogLevel.INFO, f"ignore api: {method.name}{method.descriptor}, inactive")
            continue
        native_api = find_api(native_lib, method)
        if not native_api:
            continue
        if native_api.value < config.API_VALUE_THRESHOLD or is_empty(native_api):
            util.log(
                LogLevel.INFO,
                f"ignore api: {method.name}{method.descriptor} (value: {native_api.value}, inst_count: {native_api.inst_count})",
            )
            continue
        yield method


def add_rwa_info() -> None:
    """
    add read/write/attr of all native APIs
    """

    def get_rw_field(
        cls: ClassAnalysis, method: MethodAnalysis, field_info: list[tuple[int, str, str]]
    ) -> Iterator[tuple[ClassAnalysis, FieldAnalysis]]:
        """
        parse (api_param_index, class name, field name) to (cls, field)
        """
        for param_idx, class_name, field_name in field_info:
            param_idx -= 2  # remove
            assert param_idx >= -1, "wrong api_param_index from NativeAnalyzer!"
            if param_idx == -1:  # this
                target_class = cls
            else:  # other param
                if class_name:
                    class_name = "L" + class_name + ";"
                else:
                    arg_desc, _, _ = method.descriptor.removeprefix("(").partition(")")
                    class_name = arg_desc.split()[param_idx]
                target_class = shared.analysis.get_class_analysis(class_name)
                if target_class is None:
                    continue
            if target_class.is_external():
                util.log(
                    LogLevel.WARN,
                    f"ignore read/write field {field_name} of external class {target_class.name} from native api {method.name}",
                )
                continue
            target_field = next(fld for fld in target_class.get_fields() if fld.name == field_name)
            yield target_class, target_field

    for cls in shared.analysis.get_internal_classes():
        if any(cls.name[1:].startswith(pkgname) for pkgname in shared.PACKAGE_PREFIX_WHITELIST):
            continue
        native_lib = get_class_lib(cls)
        if not native_lib:
            continue
        for method_analysis in cls.get_methods():
            if "native" not in method_analysis.access:
                continue
            api_id = _get_ApiId(native_lib, method_analysis)
            if not api_id:
                continue

            # parse attribute analysis results
            native_api = _apis[native_lib][api_id]
            arg_num = len(method_analysis.descriptor.split())
            arg_attr = [
                (Attribute(a) | Attribute.TRACE) if a else Attribute.TRACE
                for a in native_api.attr[:arg_num]
            ]

            # parse r/w analysis results and add them to androguard's methods & fields
            for rd_cls, rd_field in get_rw_field(cls, method_analysis, native_api.read):
                method_analysis.add_xref_read(rd_cls, rd_field, -1)
                rd_cls.add_field_xref_read(method_analysis, cls, rd_field.field, 0)
            for wt_cls, wt_field in get_rw_field(cls, method_analysis, native_api.write):
                method_analysis.add_xref_write(wt_cls, wt_field, -1)
                wt_cls.add_field_xref_write(method_analysis, cls, wt_field.field, 0)
            method.get_method(method_analysis, arg_attr)


def parse_api_json(apkname: str) -> None:
    """
    parse all ".json" to init `_apis`
    """
    api_path = os.path.join(config.API_PATH, apkname)
    assert os.path.isdir(api_path)

    # parse all ".json"
    @dataclass
    class APISubView:
        inst_count: float
        cyc_complexity: float
        loop_count: float
        call_depth: float
        risksite_count: float

    norm_min = APISubView(float("inf"), float("inf"), float("inf"), float("inf"), float("inf"))
    norm_max = APISubView(0, 0, 0, 0, 0)
    api_num = 0
    for filename in os.listdir(api_path):
        if not filename.endswith(".json"):
            continue
        libname = filename.removesuffix(".json")
        with open(os.path.join(api_path, filename), "r", encoding="utf-8") as f:
            apis: list[dict] = json.load(f)
            api_num += len(apis)
            for native_api_dict in apis:
                native_api_dict["address"] = int(native_api_dict["address"], base=16)
                for key in vars(norm_max):
                    max_v = getattr(norm_max, key)
                    if native_api_dict[key] > max_v:
                        setattr(norm_max, key, native_api_dict[key])
                    min_v = getattr(norm_min, key)
                    if native_api_dict[key] < min_v:
                        setattr(norm_min, key, native_api_dict[key])
                native_api = api.API.__new__(api.API)
                for key, v in native_api_dict.items():
                    setattr(native_api, key, v)
                api_id = ApiId(native_api_dict["java_name"] + native_api_dict["signature"])
                _apis[libname][api_id] = native_api
    if not api_num:
        util.log(LogLevel.ERROR, "there's no native API in this APK!")
        return
    elif api_num == 1:
        util.log(LogLevel.INFO, "there's only 1 API in this APK, set it value to 1")
        for libname, lib_apis in _apis.items():
            for api_id, native_api in lib_apis.items():
                _apis[libname][api_id].value = 1
    else:
        # Entropy Weight Method
        weight = APISubView(float("nan"), float("nan"), float("nan"), float("nan"), float("nan"))

        # 1. normalization
        apis_copy = copy.deepcopy(_apis)
        norm_sum = APISubView(0, 0, 0, 0, 0)
        for _, lib_apis in apis_copy.items():
            for _, native_api in lib_apis.items():
                for key in vars(weight):
                    max_v = getattr(norm_max, key)
                    min_v = getattr(norm_min, key)
                    if max_v - min_v:
                        v = getattr(native_api, key)
                        v = (v - min_v) / (max_v - min_v)
                        setattr(native_api, key, v)
                        sum_v = getattr(norm_sum, key)
                        setattr(norm_sum, key, sum_v + v)
                    else:
                        setattr(weight, key, 0)
        # 2. Proportion
        for _, lib_apis in apis_copy.items():
            for _, native_api in lib_apis.items():
                for key in vars(weight):
                    if getattr(weight, key) == 0:
                        continue
                    v = getattr(native_api, key)
                    sum_v = getattr(norm_sum, key)
                    setattr(native_api, key, v / sum_v)
        # 3. Entropy
        k = 1 / numpy.log(api_num)
        sum_d = 0
        for key in vars(weight):
            if getattr(weight, key) == 0:
                continue
            sum_p = 0
            for _, lib_apis in apis_copy.items():
                for _, native_api in lib_apis.items():
                    v = getattr(native_api, key)
                    if v:
                        sum_p += v * numpy.log(v)
            e = -k * sum_p
            d = 1 - e
            sum_d += d
            setattr(weight, key, d)
        # 4. Weight
        for key in vars(weight):
            if getattr(weight, key) == 0:
                continue
            w = getattr(weight, key)
            setattr(weight, key, w / sum_d)
        # 5. Calculate value
        for libname, lib_apis in apis_copy.items():
            for api_id, native_api in lib_apis.items():
                value = 0
                for k, w in vars(weight).items():
                    value += w * getattr(native_api, k)
                _apis[libname][api_id].value = value

    # update ".json"
    apis_copy = copy.deepcopy(_apis)
    for filename in os.listdir(api_path):
        if not filename.endswith(".json"):
            continue
        libname = filename.removesuffix(".json")
        for _, native_api in apis_copy[libname].items():
            native_api.address = hex(native_api.address)
        with open(os.path.join(api_path, filename), "w", encoding="utf-8") as f:
            json.dump(
                [vars(native_api) for _, native_api in apis_copy[libname].items()], f, indent=2
            )


_UNIMPLEMENTED_JNI = set(
    (
        "GetSuperclass",
        "IsAssignableFrom",
        "NewObject",
        "NewObjectV",
        "NewObjectA",
        "GetObjectRefType",
        "RegisterNatives",
        "UnregisterNatives",
        "MonitorEnter",
        "MonitorExit",
        "FromReflectedMethod",
        "FromReflectedField",
        "ToReflectedMethod",
        "ToReflectedField",
    )
)


def is_mockable(libname: str, native_method: MethodAnalysis) -> bool:
    api_id = _get_ApiId(libname, native_method)
    if not api_id:
        util.log(LogLevel.WARN, f"can't find {native_method.name} in {libname}")
        return False
    jni_calls = _apis[libname][api_id].jni_calls
    for jni_call in jni_calls:
        if jni_call in _UNIMPLEMENTED_JNI or jni_call.startswith("Call"):
            return False
    return True
