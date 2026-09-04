from __future__ import annotations

__desc__ = "generate harness according to an API sequence"

from dataclasses import dataclass
from androguard.core.analysis.analysis import ClassAnalysis, MethodAnalysis, FieldAnalysis
from androguard.core.dex import dex_types
from enum import Enum, auto
from pathlib import Path
import os
import io
import shutil
import subprocess
import struct
from . import method
from . import operand
from . import shared
from . import util
from . import api
from . import jenum
from . import parameter
from . import field
from .shared_def import *
from .. import config

_FUZZ_INPUT_FD = "stdin"

SEMANTIC_HINTS = ("path", "size", "array-len")
ALL_SEMANTIC_HINTS = frozenset(SEMANTIC_HINTS)


class VarType(Enum):
    UNDEFINED = 0
    CLASS = auto()
    OBJECT = auto()
    FIELD_ID = auto()
    METHOD_ID = auto()

    VALUE = auto()
    LENGTH = auto()
    BUFFER = auto()
    MUX = auto()  # used for switch

    # binary symbols, used for direct call
    SYMBOL = auto()  # extern "C" xxx
    ADDRESS = auto()

    FILE = auto()


_normal_var_count: int  # record the number of vars created, used for subscript for var names
_normal_file_count: int


@dataclass(frozen=True)
class Var:
    _type: VarType
    _name: str

    @classmethod
    def from_symbol(cls, libname: str, method_analysis: MethodAnalysis) -> Var:
        native_api = api.find_api(libname, method_analysis)
        assert native_api
        return Var(VarType.SYMBOL, native_api.binary_name)

    @classmethod
    def from_descriptor(cls, desc: str) -> Var:

        def generate_name(desc: str) -> str:
            desc = util.normalize_classname(desc)
            if desc.startswith("["):
                return generate_name(desc[1:]) + "_arr"
            if desc in dex_types.TYPE_DESCRIPTOR:
                return dex_types.TYPE_DESCRIPTOR[desc]
            if desc.startswith("L") and desc.endswith(";"):
                return cls.from_descriptor(desc).name
            return desc

        desc = util.normalize_classname(desc)
        if desc.startswith("L") and desc.endswith(";"):
            return Var(VarType.CLASS, desc.removeprefix("L").removesuffix(";").replace("/", "_"))
        global _normal_var_count
        name = generate_name(desc) + f"_{_normal_var_count}"
        _normal_var_count += 1
        return Var(VarType.VALUE, name)

    @classmethod
    def create_file_pointer(cls) -> Var:
        global _normal_file_count
        var = Var(VarType.FILE, f"fp_{_normal_file_count}")
        _normal_file_count += 1
        return var

    def get_obj(self) -> Var:
        assert self._type == VarType.CLASS, f"{self} {self._type}"
        return Var(VarType.OBJECT, self._name + "_obj")

    def get_fieldID(self, field_name: str) -> Var:
        assert self._type == VarType.CLASS
        return Var(VarType.FIELD_ID, self._name + f"_{field_name}")

    def get_field_val(self) -> Var:
        assert self._type == VarType.FIELD_ID
        return Var(VarType.VALUE, self._name + "_val")

    def get_methodID(self, method_analysis: MethodAnalysis) -> Var:
        def generate_name(desc: str) -> str:
            if desc.startswith("["):
                return generate_name(desc[1:]) + "_arr"
            if desc in dex_types.TYPE_DESCRIPTOR:
                return desc
            if desc.startswith("L") and desc.endswith(";"):
                return desc.removesuffix(";").rsplit("/", maxsplit=1)[-1]
            raise NotImplementedError(f"unknown descriptor: {arg_desc}")

        assert self._type == VarType.CLASS
        method_name = method_analysis.name
        arg_descs, _, _ = method_analysis.get_descriptor().removeprefix("(").partition(")")
        for arg_desc in arg_descs.split():
            method_name += "_" + generate_name(arg_desc)
        return Var(VarType.METHOD_ID, self._name + f"_{method_name}")

    def get_return_val(self) -> Var:
        assert self._type == VarType.METHOD_ID
        return Var(VarType.VALUE, self._name + "_val")

    def get_addr(self) -> Var:
        assert self._type == VarType.SYMBOL
        return Var(VarType.ADDRESS, self._name + "_addr")

    def get_mux(self) -> Var:
        # var or enum class
        assert self._type in {VarType.VALUE, VarType.OBJECT}
        return Var(VarType.MUX, self._name + "_mux")

    def get_length(self) -> Var:
        assert self._type in {VarType.VALUE, VarType.FILE}
        return Var(VarType.LENGTH, self._name + "_len")

    def get_buf(self) -> Var:
        assert self._type in {VarType.VALUE, VarType.FILE}
        return Var(VarType.BUFFER, self._name + "_buf")

    def __str__(self) -> str:
        return self._name

    def __repr__(self) -> str:
        return self._name

    @property
    def name(self):
        return self._name


# Var for var
# int, float for immediate
# str for string literal
# None for null
Argument = Var | int | str | float | None

_instrument_libs: list[str] = []


def get_instrument_libraries(target_lib: str) -> None:
    """
    write `_instrument_libs`
    """
    # get indirect linked libraries
    proc = subprocess.Popen(
        ["readelf", "-d", f"{config.LIB64_PATH}/{target_lib}"], stdout=subprocess.PIPE
    )
    assert proc.stdout
    global _instrument_libs
    _instrument_libs = [target_lib]
    for line in io.TextIOWrapper(proc.stdout):
        if "(NEEDED)" in line:
            lib = line.rsplit("Shared library: [")[-1].removesuffix("]\n")
            if lib not in shared.IGNORE_NEEDED_LIBRARIES:
                util.log(LogLevel.INFO, f"instrument indirect library {lib}")
                _instrument_libs.append(lib)


class Harness:
    _sequence: list[method.Method | field.Field]
    _native_lib: str
    _enabled_semantics: frozenset[str]

    _created_vars: set[Var]  # {varname1, varname2, ...}
    _alloced_vars: set[Var]  # {varname1, varname2, ...}

    _art_codes: list[list[str]]  # harness of art environment

    _mock_enable: bool
    _mock_codes: list[list[str]]  # harness of JNIMock environment
    _declare_codes: list[str]  # used for direct call of `_mock_codes`
    _dynamic_registered: bool  # indicates whether JNI_OnLoad exists, used for JNIMock harness

    def __init__(
        self,
        native_lib: str,
        sequence: list[method.Method | field.Field],
        enabled_semantics: frozenset[str] = ALL_SEMANTIC_HINTS,
    ) -> None:
        global _normal_file_count, _normal_var_count
        _normal_var_count = 0
        _normal_file_count = 0

        self._sequence = sequence
        self._native_lib = native_lib
        self._enabled_semantics = enabled_semantics
        self._created_vars = set()
        self._alloced_vars = set()

        self._art_codes = []

        self._mock_enable = True
        self._mock_codes = []
        self._declare_codes = []
        self._dynamic_registered = False

        # check whether the api sequence can run on JNIMock environment
        for node in sequence:
            if type(node) != method.Method:
                continue
            if "native" not in node.analysis.access:
                util.log(
                    LogLevel.INFO,
                    f"Can't generate mock harness: Java method detected - {node.analysis.name}",
                )
                self._mock_enable = False
                break
            # check whether the native method has strong JNI dependency
            if not api.is_mockable(native_lib, node.analysis):
                util.log(
                    LogLevel.INFO,
                    f"Can't generate mock harness: Strong JNI call detected in {node.analysis.name}",
                )
                self._mock_enable = False
                break

        if self._mock_enable:
            self._declare_codes = self._generate_api_declares()
            if self._dynamic_registered:
                self._mock_codes.append(self._generate_base_addr())

        self._generate_harness_codes()

    def _generate_api_declares(self) -> list[str]:
        """
        write `self._dynamic_registered`
        """

        def get_ctype_from_jdesc(desc: str) -> str:
            if desc in dex_types.TYPE_DESCRIPTOR:
                ctype = dex_types.TYPE_DESCRIPTOR[desc]
                if desc != "V":
                    ctype = "j" + ctype
            else:  # array and object are all considered as `jobject`
                ctype = "jobject"
            return ctype

        declare_codes: list[str] = []
        for node in self._sequence:
            if type(node) != method.Method:
                continue
            symbol = Var.from_symbol(self._native_lib, node.analysis)
            if not symbol.name.startswith("Java_"):
                self._dynamic_registered = True
            arg_types, _, ret_type = node.analysis.get_descriptor().removeprefix("(").partition(")")
            ret_type = get_ctype_from_jdesc(ret_type)
            code = f'extern "C" {ret_type} {symbol.name}(JNIEnv *, jobject'
            arg_types = arg_types.split()
            for arg_type in arg_types:
                code += f", {get_ctype_from_jdesc(arg_type)}"
            code += ");"
            declare_codes.append(code)
        return declare_codes

    def _generate_base_addr(self) -> list[str]:
        """
        generate codes that get base addr of JNI_OnLoad. write `self._mock_codes`
        """
        assert self._dynamic_registered, "JNI_OnLoad not exist!"
        codes: list[str] = []
        codes.append(r"Dl_info dl_info{};")
        codes.append("if (!dladdr(reinterpret_cast<void *>(JNI_OnLoad), &dl_info))")
        codes.append("\treturn;")
        codes.append("auto base_addr{reinterpret_cast<uintptr_t>(dl_info.dli_fbase)};")
        return codes

    def _FindClass(self, classname: str) -> list[str]:
        """
        :param classname: Lcom/example;
        """
        cls = shared.analysis.get_class_analysis(classname)
        if cls.is_external() and not cls.is_android_api():
            raise WontImplementError(f"external class {classname} is not supported yet!")
        cls_var = Var.from_descriptor(classname)
        assert cls_var not in self._created_vars
        self._created_vars.add(cls_var)
        class_string = classname.removeprefix("L").removesuffix(";")
        return [
            f"auto {cls_var}" + '{env->FindClass("' + class_string + '")};',
            "check_JNI_exception();",
        ]

    def _AllocObject(self, cls_var: Var) -> list[str]:
        """
        construct the code of `AllocObject`

        note: it's `AllocObject`, not `NewObject`. So the object may be not initialized correctly.
        """
        assert cls_var in self._created_vars
        obj_var = cls_var.get_obj()
        assert obj_var not in self._created_vars
        self._created_vars.add(obj_var)
        return [
            f"auto {obj_var}" + "{env->AllocObject(" + cls_var.name + ")};",
            "check_JNI_exception();",
        ]

    def _create_var_with_init_vals(
        self, var: Var, var_desc: str, init_vals: set[operand.Operand]
    ) -> list[str]:
        def create_var_with_init_val(
            var: Var, var_desc: str, init_val: operand.Operand
        ) -> list[str]:
            codes: list[str] = []
            if init_val == operand.NULL_REF:
                return codes
            if var_desc in dex_types.TYPE_DESCRIPTOR:
                if init_val.type == operand.OpType.LITERAL:
                    assert type(init_val.value) == int
                    if var_desc in {"D", "F"}:
                        codes.append(f"{var} = {util.get_literal_value(init_val.value, var_desc)};")
                    else:
                        codes.append(f"{var} = {hex(init_val.value)};")
                elif init_val.type == operand.OpType.FIELD:  # enum field
                    class_name, field_name, _ = init_val.get_field_info()
                    enum_val = jenum.get_enum_val(class_name, field_name)
                    codes.append(f"{var} = {hex(enum_val)};")
                elif init_val.type == operand.OpType.TYPE:  # enum
                    classname = init_val.points_to
                    assert classname
                    raise NotImplementedError
                else:
                    raise InvalidStateError(f"{init_val} is not a literal")
            elif var_desc.startswith("["):
                length_var = var.get_length()
                self._created_vars.add(length_var)
                if init_val.type == operand.OpType.RAW:
                    if var_desc != "[B":
                        raise NotImplementedError("RAW non-byte array is not implemented yet!")
                    assert type(init_val.value) == str
                    codes.append(f"{length_var} = {hex(len(init_val.value))};")
                    buf_var = var.get_buf()
                    raw_bytes = init_val.value.removeprefix("b'").removesuffix("'").encode("latin1")
                    codes.append(
                        f"jbyte {buf_var}[]"
                        + "{0x"
                        + raw_bytes.hex(",").replace(",", ", 0x")
                        + "};"
                    )
                    self._created_vars.add(buf_var)
                    assert var_desc[1:] in dex_types.TYPE_DESCRIPTOR
                    codes.append(
                        f"auto {var}"
                        + "{"
                        + f"env->New{dex_types.TYPE_DESCRIPTOR[var_desc[1:]].capitalize()}Array({length_var})"
                        + "};"
                    )
                    codes.append(
                        f"env->Set{dex_types.TYPE_DESCRIPTOR[var_desc[1:]].capitalize()}ArrayRegion({var}, 0, {length_var}, {buf_var});"
                    )
                    codes.append("check_JNI_exception();")
                    return codes
                assert type(init_val.value) == int
                codes.append(f"{length_var} = {hex(init_val.value)};")
                codes += self._create_var_with_fuzz_input(var, var_desc)
            elif var_desc == "Ljava/lang/String;":
                if init_val.type == operand.OpType.LITERAL:
                    assert init_val.value == 0
                    codes.append(f'{var} = env->NewStringUTF("");')
                elif init_val.type == operand.OpType.STRING:
                    assert init_val.points_to is not None
                    codes.append(f'{var} = env->NewStringUTF("{init_val.points_to}");')
                else:
                    raise InvalidStateError(f"init val {init_val} of string is not valid!")
            elif var_desc == "Ljava/nio/ByteBuffer;":
                raise NotImplementedError(f"create {var_desc} var not implemented yet!")
            elif var_desc.startswith("L") and var_desc.endswith(";"):  # object
                if init_val.type == operand.OpType.LITERAL:
                    assert init_val.value == 0
                    codes.append(f"jobject {var} = nullptr;")
                    return codes
                if not jenum.is_enum(var_desc):
                    raise NotImplementedError(
                        f"create {var_desc} with init_val {init_val} not implemented yet!"
                    )
                assert init_val.type == operand.OpType.FIELD
                class_name, field_name, _ = init_val.get_field_info()
                fld = util.get_field_analysis_by_name(class_name, field_name)
                codes += self._GetField(fld)
                field_val_var = (
                    Var.from_descriptor(class_name).get_fieldID(field_name).get_field_val()
                )
                codes.append(f"{var} = {field_val_var};")
            else:
                raise InvalidStateError(f"unknown type: {var_desc}")
            return codes

        def create_default_initialized_var(var: Var, var_desc: str) -> str:
            """
            note: it doesn't add the var to `self._created_vars`
            """
            if var_desc in dex_types.TYPE_DESCRIPTOR:
                return f"j{dex_types.TYPE_DESCRIPTOR[var_desc]} {var}" + r"{};"
            elif var_desc.startswith("["):
                return f"jsize {var.get_length()}" + r"{};"
            elif var_desc == "Ljava/lang/String;":
                return f"jstring {var}" + r"{};"
            elif var_desc == "Ljava/nio/ByteBuffer;":
                raise NotImplementedError(f"create {var_desc} var not implemented yet!")
            elif var_desc.startswith("L") and var_desc.endswith(";"):
                return f"jobject {var}" + r"{};"
            raise InvalidStateError(f"unknown type: {var_desc}")

        codes: list[str] = []
        if len(init_vals) == 1:
            init_val = init_vals.pop()
            init_vals.add(init_val)
            codes.append(create_default_initialized_var(var, var_desc))
            codes += create_var_with_init_val(var, var_desc, init_val)
            self._created_vars.add(var)
            return codes

        # use switch(fuzz_input) to select the init_val
        mux_var = var.get_mux()
        codes += self._create_var_with_fuzz_input(mux_var, "B")
        if config.HARNESS_DEBUG:
            codes.append(f"{mux_var} = 0;")
        codes.append(create_default_initialized_var(var, var_desc))
        codes.append(f"switch ({mux_var}) " + "{")
        for i, init_val in enumerate(init_vals):
            if var_desc.startswith("["):
                raise NotImplementedError(
                    "fix create_var_with_init_val and create_default_initialized_var!"
                )
            codes.append(f"case {i}:" + " {")
            saved_created_vars = self._created_vars.copy()
            codes += ["\t" + code for code in create_var_with_init_val(var, var_desc, init_val)]
            codes.append("\tbreak;")
            self._created_vars = saved_created_vars
            codes.append("}")
        codes.append("default: {")
        for alloced_var in self._alloced_vars:
            codes.append(f"\tdelete[] {alloced_var};")
        codes += ["\tcleanup();", "\treturn;", "}", "}"]
        self._created_vars.add(var)
        return codes

    def _create_length_var_with_fuzz_input(self, var: Var) -> list[str]:
        codes: list[str] = []
        codes += self._create_var_with_fuzz_input(var, "C")
        codes.append(f"if ({var} > {config.MAX_BUFFER_LENGTH})" + " {")
        codes.append(f'\tprintf("[!] {var} (%hu) is too large!\\n", {var});')
        if config.HARNESS_DEBUG:
            codes.append(f"\t{var} = {config.MAX_BUFFER_LENGTH};")
        else:
            for alloced_var in self._alloced_vars:
                codes.append(f"\tdelete[] {alloced_var};")
            codes.append("\tcleanup();")
            codes.append("\treturn;")
        codes.append("}")
        return codes

    def _create_path_var_with_fuzz_input(self, var: Var) -> list[str]:
        codes: list[str] = []

        # generate path String
        buf_var = var.get_buf()
        codes.append(f"char {buf_var}[0x21]" + r"{};")
        global _normal_file_count
        codes.append(f'snprintf({buf_var}, 0x20, "/tmp/%d_{_normal_file_count}", pid);')

        codes.append(f"auto {var}" + "{" + f"env->NewStringUTF({buf_var})" + "};")
        self._created_vars.add(var)

        # generate file content from fuzz input
        fp_var = Var.create_file_pointer()
        fp_size = fp_var.get_length()
        fp_content = fp_var.get_buf()
        codes += self._create_length_var_with_fuzz_input(fp_size)
        codes.append(f"auto {fp_content}" + "{new " + f"char[8*{fp_size}]" + "};")
        codes.append(f"fread({fp_content}, sizeof(char), 8*{fp_size}, {_FUZZ_INPUT_FD});")
        self._created_vars.add(fp_content)
        self._alloced_vars.add(fp_content)

        # create file
        codes.append(f"auto {fp_var}" + "{fopen(" + f'{buf_var}, "wb")' + "};")
        codes.append(f"fwrite({fp_content}, sizeof(char), 8*{fp_size}, {fp_var});")
        codes.append(f"fclose({fp_var});")
        self._created_vars.add(fp_var)

        return codes

    def _create_var_with_fuzz_input(self, var: Var, var_desc: str) -> list[str]:
        codes: list[str] = []
        if var in self._created_vars:
            return codes
        if var_desc in dex_types.TYPE_DESCRIPTOR:  # primitive types
            assert var_desc != "V"
            ctype = "j" + dex_types.TYPE_DESCRIPTOR[var_desc]
            codes.append(ctype + " " + var.name + r"{};")
            codes.append(f"fread(&{var}, sizeof({ctype}), 1, {_FUZZ_INPUT_FD});")
        elif var_desc == "Ljava/lang/String;":  # String
            length_var = var.get_length()
            if length_var not in self._created_vars:
                codes += self._create_length_var_with_fuzz_input(length_var)
            buf_var = var.get_buf()
            if buf_var not in self._created_vars:
                self._created_vars.add(buf_var)
                if var.__str__() != "temp_str":  # elem of String[]
                    self._alloced_vars.add(buf_var)
                codes.append(f"auto {buf_var}" + "{new " + f"char[{length_var}]" + "};")
                codes.append(f"fread({buf_var}, sizeof(char), {length_var}, {_FUZZ_INPUT_FD});")
            codes.append(f"auto {var}" + "{" + f"env->NewStringUTF({buf_var})" + "};")
        elif var_desc == "Ljava/nio/ByteBuffer;":  # ByteBuffer
            length_var = var.get_length()
            if length_var not in self._created_vars:
                codes += self._create_length_var_with_fuzz_input(length_var)
            buf_var = var.get_buf()
            if buf_var not in self._created_vars:
                self._created_vars.add(buf_var)
                self._alloced_vars.add(buf_var)
                codes.append(f"auto {buf_var}" + "{new " + f"jbyte[{length_var}]" + "};")
                codes.append(f"fread({buf_var}, sizeof(jbyte), {length_var}, {_FUZZ_INPUT_FD});")
            codes.append(
                f"auto {var}" + "{" + f"env->NewDirectByteBuffer({buf_var}, {length_var})" + "};"
            )
        elif var_desc.startswith("L") and var_desc.endswith(";"):  # object
            cls_var = Var.from_descriptor(var_desc)
            if cls_var not in self._created_vars:
                codes += self._FindClass(var_desc)
            obj_var = cls_var.get_obj()
            if obj_var not in self._created_vars:
                codes += self._AllocObject(cls_var)
        elif var_desc.startswith("["):  # array
            length_var = var.get_length()
            if length_var not in self._created_vars:
                codes += self._create_length_var_with_fuzz_input(length_var)
            if var_desc[1:] == "Ljava/lang/String;":
                # note: mock GC cannot release all buffers allocated by String[]
                codes.append(
                    f"auto {var}"
                    + "{"
                    + f'env->NewObjectArray({length_var}, env->FindClass("java/lang/String"), env->NewStringUTF(""))'
                    + "};"
                )
                codes.append(f"for (jchar i = 0; i < {length_var}; i++)" + " {")
                elem_var = Var(VarType.VALUE, "temp_str")
                codes += self._create_var_with_fuzz_input(elem_var, var_desc[1:])
                codes.append(f"env->SetObjectArrayElement({var}, i, {elem_var});")
                codes.append("}")
                self._created_vars.add(var)
                return codes
            if var_desc[1:] in dex_types.TYPE_DESCRIPTOR:
                codes.append(
                    f"auto {var}"
                    + "{"
                    + f"env->New{dex_types.TYPE_DESCRIPTOR[var_desc[1:]].capitalize()}Array({length_var})"
                    + "};"
                )
            else:
                raise NotImplementedError(f"creating {var_desc} array is not implemented yet!")
            buf_var = var.get_buf()
            if buf_var not in self._created_vars:
                self._created_vars.add(buf_var)
                self._alloced_vars.add(buf_var)
                ctype = "j" + dex_types.TYPE_DESCRIPTOR[var_desc[1:]]
                codes.append(f"auto {buf_var}" + "{new " + f"{ctype}[{length_var}]" + "};")
                codes.append(f"fread({buf_var}, sizeof({ctype}), {length_var}, {_FUZZ_INPUT_FD});")
                codes.append(
                    f"env->Set{dex_types.TYPE_DESCRIPTOR[var_desc[1:]].capitalize()}ArrayRegion({var}, 0, {length_var}, {buf_var});"
                )
                codes.append("check_JNI_exception();")
        else:
            raise InvalidStateError(f"unknown type: {var_desc}")
        self._created_vars.add(var)
        return codes

    def _GetFieldID(
        self, cls_var: Var, field_name: str, field_type: str, static: bool
    ) -> list[str]:
        fieldID_var = cls_var.get_fieldID(field_name)
        assert fieldID_var not in self._created_vars
        self._created_vars.add(fieldID_var)
        return [
            f"auto {fieldID_var}"
            + "{env->Get"
            + ("Static" if static else "")
            + f'FieldID({cls_var}, "{field_name}", "{field_type}")'
            + "};",
            "check_JNI_exception();",
        ]

    def _get_ret_var(self, param_source: operand.Operand) -> Var:
        assert param_source.type == operand.OpType.METH
        method_analysis = param_source.get_method_analysis()
        assert method_analysis
        ret_var = (
            Var.from_descriptor(method_analysis.get_class_name())
            .get_methodID(method_analysis)
            .get_return_val()
        )
        return ret_var

    def _SetField(self, f: field.Field) -> list[str]:
        fld = f.analysis.get_field()
        codes: list[str] = []

        classname = fld.get_class_name()
        cls_var = Var.from_descriptor(classname)
        if cls_var not in self._created_vars:
            codes += self._FindClass(classname)

        static = "static" in fld.get_access_flags_string()
        obj_var = cls_var.get_obj()
        if not static and obj_var not in self._created_vars:
            codes += self._AllocObject(cls_var)

        # get fieldID
        fieldID_var = cls_var.get_fieldID(fld.get_name())
        field_type = fld.get_descriptor()
        if fieldID_var not in self._created_vars:
            codes += self._GetFieldID(cls_var, fld.get_name(), field_type, static)

        # get value of field
        var = fieldID_var.get_field_val()
        init_vals = set(val for val in f.sources if val.is_const())
        if init_vals:
            if var not in self._created_vars:
                codes += self._create_var_with_init_vals(var, fld.get_descriptor(), init_vals)
        elif f.producers:
            for source in f.sources:
                ret_var = self._get_ret_var(source)
                if ret_var in self._created_vars:
                    codes.append(f"auto {var}" + "{" + f"{ret_var}" + "};")
                    self._created_vars.add(var)
                    break
            else:
                util.log(LogLevel.DEBUG, "  producer was in loop, ignore it")
                codes += self._create_var_with_fuzz_input(var, field_type)
        else:
            if var not in self._created_vars:
                codes += self._create_var_with_fuzz_input(var, field_type)

        # set field
        code = "env->Set" + ("Static" if static else "")
        if field_type in dex_types.TYPE_DESCRIPTOR:
            code += dex_types.TYPE_DESCRIPTOR[field_type].capitalize()
        else:
            code += "Object"
        code += "Field(" + (cls_var.name if static else obj_var.name) + f", {fieldID_var}, {var});"
        codes.append(code)
        codes.append("check_JNI_exception();")
        codes.append(f'printf("[+] set field {fld.get_name()} finished!\\n");')

        return codes

    def _GetField(self, field_analysis: FieldAnalysis) -> list[str]:
        fld = field_analysis.get_field()
        codes: list[str] = []

        classname = fld.get_class_name()
        cls_var = Var.from_descriptor(classname)
        if cls_var not in self._created_vars:
            codes += self._FindClass(classname)

        static = "static" in fld.get_access_flags_string()
        obj_var = cls_var.get_obj()
        if not static and obj_var not in self._created_vars:
            codes += self._AllocObject(cls_var)

        # get fieldID
        fieldID_var = cls_var.get_fieldID(fld.get_name())
        field_type = fld.get_descriptor()
        if fieldID_var not in self._created_vars:
            codes += self._GetFieldID(cls_var, fld.get_name(), field_type, static)

        # get field
        var = fieldID_var.get_field_val()
        if var in self._created_vars:
            return codes
        code = f"auto {var}" + "{env->Get" + ("Static" if static else "")
        if field_type in dex_types.TYPE_DESCRIPTOR:
            code += dex_types.TYPE_DESCRIPTOR[field_type].capitalize()
        else:
            code += "Object"
        code += "Field(" + (cls_var.name if static else obj_var.name) + f", {fieldID_var})" + "};"
        codes.append(code)
        codes.append("check_JNI_exception();")
        codes.append(f'printf("[+] get field {fld.get_name()} finished!\\n");')
        self._created_vars.add(var)

        return codes

    def _pass_args(self, args: list[Argument]) -> str:
        """
        pass args for function call. Only called by `_CallMethod` and `_direct_call`.
        """
        code = ""
        for arg in args:
            if arg is None:
                code += ", nullptr"
            elif type(arg) == str:
                code += f', "{arg}"'
            else:
                code += f", {arg}"
        return code

    def _CallMethod(self, target_method: MethodAnalysis, args: list[Argument]) -> list[str]:
        static = "static" in target_method.access
        cls_var = Var.from_descriptor(target_method.get_class_name())
        codes: list[str] = []

        # no need to add methodID_varname to self._created_vars
        methodID_var = cls_var.get_methodID(target_method)
        codes.append(
            f"auto {methodID_var}"
            + "{env->Get"
            + ("Static" if static else "")
            + f'MethodID({cls_var}, "{target_method.name}", "{target_method.descriptor.replace(" ", "")}")'
            + "};"
        )
        codes.append("check_JNI_exception();")

        code = "env->Call" + ("Static" if static else "")
        _, _, method_rtype = target_method.descriptor.partition(")")
        if method_rtype in dex_types.TYPE_DESCRIPTOR:
            code += dex_types.TYPE_DESCRIPTOR[method_rtype].capitalize()
        else:
            code += "Object"
        code += (
            "Method(" + (cls_var.name if static else cls_var.get_obj().name) + f", {methodID_var}"
        )
        code += self._pass_args(args)

        if method_rtype == "V":
            code += ");"
        else:  # create and save return value to a var
            ret_var = methodID_var.get_return_val()
            self._created_vars.add(ret_var)
            code = f"auto {ret_var}" + "{" + code + ")};"

        codes.append(f'printf("[*] call method {target_method.name}...\\n");')
        codes.append(code)
        codes.append("check_JNI_exception();")
        codes.append(f'printf("[+] call method {target_method.name} finished!\\n");')
        return codes

    def _direct_call(self, target_method: MethodAnalysis, args: list[Argument]) -> list[str]:
        codes: list[str] = []
        symbol = Var.from_symbol(self._native_lib, target_method)
        native_api = api.find_api(self._native_lib, target_method)
        assert native_api
        binary_offset = native_api.address
        thiz = Var.from_descriptor(target_method.get_class_name())
        if "static" not in target_method.access:
            thiz = thiz.get_obj()
        if symbol.name.startswith("sub_"):
            func_addr = symbol.get_addr()
            codes.append(f"auto {func_addr}" + "{base_addr + " + hex(binary_offset) + "};")
            code = f"reinterpret_cast<decltype(&{symbol})>({func_addr})(jnimock::env, {thiz}"
        else:
            code = f"{symbol}(jnimock::env, {thiz}"
        code += self._pass_args(args)

        _, _, method_rtype = target_method.descriptor.partition(")")
        if method_rtype == "V":
            code += ");"
        else:  # create and save return value to a var
            ret_var = (
                Var.from_descriptor(target_method.get_class_name())
                .get_methodID(target_method)
                .get_return_val()
            )
            self._created_vars.add(ret_var)
            code = f"auto {ret_var}" + "{" + code + ")};"

        codes.append(f'printf("[*] call method {target_method.name}...\\n");')
        codes.append(code)
        codes.append(f'printf("[+] call method {target_method.name} finished!\\n");')
        return codes

    def _generate_harness_codes(self) -> None:
        """
        write `self._art_codes` and `self._mock_codes`
        """

        def synthesis_arg_with_source(
            param: parameter.Parameter, codes: list[str], delays: list[int]
        ) -> Var | int | float | str | None:
            """
            :return arg: int/string if const source, else synthesised var
            """
            if (
                "path" in self._enabled_semantics
                and Attribute.PATH in param.attribute
                and param.descriptor == "Ljava/lang/String;"
            ):
                util.log(LogLevel.WARN, f"sources {param.sources} of PATH is ignored")
                arg = Var.from_descriptor(param.descriptor)
                codes += self._create_path_var_with_fuzz_input(arg)
                return arg

            if Attribute.FD in param.attribute and param.descriptor == "I":
                raise NotImplementedError(
                    f"can't synthesize file descriptor argument {param.sources}！"
                )

            if len(param.sources) > 1:
                # more than 1 const values, or more than 1 return value sources
                param.prune()
                if any(src.is_const() for src in param.sources):
                    arg_desc = util.normalize_classname(param.descriptor)
                    arg = Var.from_descriptor(arg_desc)
                    if arg_desc.startswith("L") and arg_desc.endswith(";"):
                        arg = arg.get_obj()
                    codes += self._create_var_with_init_vals(arg, param.descriptor, param.sources)
                    return arg
                for param_source in param.sources:
                    if param_source.type in (operand.OpType.METH, operand.OpType.FIELD):
                        param.sources = {param_source}
                        break
                else:
                    raise InvalidStateError(f"can't find return value or field in {param.sources}")
            else:
                param_source = param.sources.pop()
                param.sources.add(param_source)
            match param_source.type:
                case operand.OpType.TYPE:
                    classname = param_source.points_to
                    assert classname
                    arg = Var.from_descriptor(classname).get_obj()
                case operand.OpType.FIELD:
                    classname, field_name, _ = param_source.get_field_info()
                    if jenum.is_enum(classname):  # enum field
                        arg = Var.from_descriptor(param.descriptor)
                        if param.descriptor.startswith("L") and param.descriptor.endswith(";"):
                            arg = arg.get_obj()
                        codes += self._create_var_with_init_vals(
                            arg, param.descriptor, param.sources
                        )
                        return arg
                    field_val_var = (
                        Var.from_descriptor(classname).get_fieldID(field_name).get_field_val()
                    )
                    if field_val_var not in self._created_vars:
                        fld = util.get_field_analysis_by_name(classname, field_name)
                        codes += self._GetField(fld)
                    arg = field_val_var
                case operand.OpType.METH:
                    ret_var = self._get_ret_var(param_source)
                    if ret_var not in self._created_vars:
                        if config.IGNORE_RETURN_VAL_OF_FUZZABLE_TYPE:
                            codes += self._create_var_with_fuzz_input(ret_var, param.descriptor)
                        else:
                            raise InvalidStateError(f"can't find return value {param_source}")
                    arg = ret_var
                case operand.OpType.LITERAL:
                    assert type(param_source.value) == int
                    arg = util.get_literal_value(param_source.value, param.descriptor)
                case operand.OpType.STRING:
                    assert param_source.points_to is not None
                    var = Var.from_descriptor(param.descriptor)
                    codes += self._create_var_with_init_vals(var, param.descriptor, {param_source})
                    arg = var
                case operand.OpType.NEW_STRING:
                    var = Var.from_descriptor(param.descriptor)
                    codes += self._create_var_with_fuzz_input(var, param.descriptor)
                    arg = var
                case operand.OpType.NEW_BUFFER | operand.OpType.NEW_ARRAY:
                    var = Var.from_descriptor(param.descriptor)
                    if param_source.value != -1:
                        length_var = var.get_length()
                        codes += self._create_var_with_init_vals(
                            length_var,
                            "I",
                            {operand.Operand((operand.OpType.LITERAL, param_source.value))},
                        )
                    codes += self._create_var_with_fuzz_input(var, param.descriptor)
                    arg = var
                case operand.OpType.RAW:
                    raise NotImplementedError(f"raw: {param_source}")
                case operand.OpType.ARRAY_LEN:
                    if param_source.points_to:
                        delays.append(i)
                        return 0
                    else:
                        raise NotImplementedError(f"array-length: {param_source}")
                case operand.OpType.STRING_LEN:
                    util.log(LogLevel.WARN, "STRING_LEN is not implemented yet!")
                    var = Var.from_descriptor(param.descriptor)
                    codes += self._create_length_var_with_fuzz_input(var)
                    arg = var
                case operand.OpType.NULL_REF:
                    arg = None
                case _:
                    raise NotImplementedError(param_source.type)

            return arg

        def synthesis_array_length(param: parameter.Parameter, var_count_before: int) -> Var | None:
            assert len(param.sources) == 1
            param_source = param.sources.pop()
            param.sources.add(param_source)
            assert param_source.points_to

            global _normal_var_count
            saved_normal_var_count = _normal_var_count
            array_length_var = None
            while _normal_var_count >= var_count_before:
                array_var = Var.from_descriptor(param_source.points_to)
                if array_var in self._created_vars:
                    array_length_var = array_var.get_length()
                    assert array_length_var in self._created_vars
                    _normal_var_count = saved_normal_var_count
                    return array_length_var
                _normal_var_count -= 2
            util.log(LogLevel.WARN, "can't find array of array-length")
            _normal_var_count = saved_normal_var_count
            return array_length_var

        # construct classes and objects
        construct_code: list[str] = []
        for node in self._sequence:
            if type(node) != method.Method:
                continue
            # create param object for every method
            for param in node.params:
                if param.descriptor in shared.UNSUPPORTED_TYPES:
                    raise WontImplementError(
                        f"unsupported type {param.descriptor} of method {node}"
                    )
                if not param.sources:
                    continue
                classnames: list[str] = []
                for param_source in param.sources:
                    if param_source.type == operand.OpType.TYPE:
                        assert param_source.points_to
                        classnames.append(param_source.points_to)
                if not classnames:
                    continue
                assert (
                    len(classnames) == 1
                ), f"there're {len(classnames)} param sources: {classnames}"
                classname = classnames[0]
                cls_var = Var.from_descriptor(classname)
                if cls_var not in self._created_vars:
                    construct_code += self._FindClass(classname)
                if cls_var.get_obj() not in self._created_vars:
                    construct_code += self._AllocObject(cls_var)
            # create `jclass/jobject this` for every method
            cls_var = Var.from_descriptor(node.analysis.class_name)
            if cls_var not in self._created_vars:
                construct_code += self._FindClass(node.analysis.class_name)
            if "static" not in node.analysis.access and cls_var.get_obj() not in self._created_vars:
                construct_code += self._AllocObject(cls_var)
        construct_code.append(f'printf("[+] class/object creation finished!\\n");')
        self._art_codes.append(construct_code)
        self._mock_codes.append(construct_code)

        # generate codes for every node:
        for node in self._sequence:
            util.log(LogLevel.DEBUG, f"generating codes for {node}")
            codes: list[str] = []

            # SetField for Field
            if type(node) == field.Field:
                util.log(LogLevel.DEBUG, f"- {node.sources}")
                codes += self._SetField(node)
                self._art_codes.append(codes)
                self._mock_codes.append(codes)
                continue

            assert type(node) == method.Method
            if "native" in node.analysis.access and len(node.params) > 6:
                util.log(
                    LogLevel.WARN,
                    f"native api {node.analysis.name} in sequence has more than 8 args",
                )

            # create params and CallMethod for Method
            args: list[Argument] = []
            array_len_idxs: list[int] = []
            var_count_before = _normal_var_count
            effective_params: list[parameter.Parameter] = []
            for original_param in node.params:
                effective_attribute = original_param.attribute
                if "path" not in self._enabled_semantics:
                    effective_attribute &= ~Attribute.PATH
                if "size" not in self._enabled_semantics:
                    effective_attribute &= ~Attribute.SIZE
                effective_sources = set(original_param.sources)
                if "array-len" not in self._enabled_semantics:
                    effective_sources = {
                        source
                        for source in effective_sources
                        if source.type != operand.OpType.ARRAY_LEN
                    }
                effective_params.append(
                    parameter.Parameter(
                        original_param.reg,
                        original_param.descriptor,
                        effective_attribute,
                        effective_sources,
                        original_param.traced,
                    )
                )

            for i, param in enumerate(effective_params):
                if not param.descriptor.startswith("["):
                    param.sources = set(
                        src for src in param.sources if src.type != operand.OpType.NEW_ARRAY
                    )
                util.log(LogLevel.DEBUG, f"- {param}")

                if param.descriptor == "Ljava/lang/Object;":
                    util.log(LogLevel.WARN, f"use null Object, ignore sources {param.sources}")
                    param.sources = {operand.NULL_REF}
                if operand.UNKNOWN in param.sources:
                    param.sources.remove(operand.UNKNOWN)
                if config.IGNORE_RETURN_VAL_OF_FUZZABLE_TYPE and (
                    param.descriptor.startswith("[")
                    or param.descriptor
                    in (
                        "Ljava/lang/String;",
                        "Ljava/nio/ByteBuffer;",
                    )
                ):
                    param.sources = set(
                        source
                        for source in param.sources
                        if source.type
                        not in (
                            operand.OpType.METH,
                            operand.OpType.RETURN_VALUE,
                            operand.OpType.FIELD,
                            operand.OpType.ARGUMENT,
                        )
                    )
                if not param.sources:  # create param with fuzz input
                    arg = Var.from_descriptor(param.descriptor)
                    if (
                        param.descriptor.startswith("L")
                        and param.descriptor.endswith(";")
                        and param.descriptor not in {"Ljava/nio/ByteBuffer;", "Ljava/lang/String;"}
                    ):
                        arg = arg.get_obj()
                    if param not in self._created_vars:
                        if Attribute.FD in param.attribute:
                            raise NotImplementedError("can't synthesize file descriptor argument!")
                        elif Attribute.PATH in param.attribute:
                            codes += self._create_path_var_with_fuzz_input(arg)
                        elif Attribute.SIZE in param.attribute:
                            codes += self._create_length_var_with_fuzz_input(arg)
                        else:
                            codes += self._create_var_with_fuzz_input(arg, param.descriptor)
                    args.append(arg)
                    continue
                args.append(synthesis_arg_with_source(param, codes, array_len_idxs))
            for array_len_idx in array_len_idxs:
                array_length_var = synthesis_array_length(
                    effective_params[array_len_idx], var_count_before
                )
                if array_length_var is None:
                    array_length_var = Var.from_descriptor(
                        effective_params[array_len_idx].descriptor
                    )
                    codes += self._create_length_var_with_fuzz_input(array_length_var)
                args[array_len_idx] = array_length_var

            art_code = codes + self._CallMethod(node.analysis, args)
            self._art_codes.append(art_code)
            if self._mock_enable:
                mock_code = codes + self._direct_call(node.analysis, args)
                self._mock_codes.append(mock_code)

    def output_harness(self, apkname: str, classname: str, api_namesig: str) -> None:
        """
        save the generated harness to HARNESS_PATH/<apkname>/<classname>/<apiname>/<id>/
        """

        def copy_and_custom_templates(harness_path: str) -> None:
            """
            copy ./harness_templates/<env> to destination, and modify Makefile and run.sh.

            :param harness_path: e.g. HARNESS_PATH/<apkname>/<classname>/<apiname>/<id>/art
            """

            def replace_old_string_with_new_string(
                file: Path, str_pairs: list[tuple[str, str]]
            ) -> None:
                """
                :param str_pairs: [(substring to match the line, string to be added at the line tail), ...]
                """
                content = file.read_text().splitlines()
                new_content: list[str] = []
                for line in content:
                    for substr, new_str in str_pairs:
                        if substr in line:
                            line += new_str
                            break
                    new_content.append(line)
                file.write_text("\n".join(new_content))

            def fill_fuzz_script(filename: str) -> None:
                file = Path(os.path.join(harness_path, filename))
                inst_ranges = ",".join(f"{config.LIB64_PATH}/{lib}" for lib in _instrument_libs)
                replace_old_string_with_new_string(
                    file,
                    [
                        ("LD_LIBRARY_PATH=", f"{config.LIB64_PATH}:/system/lib64"),
                        ("AFL_QEMU_INST_RANGES=", inst_ranges),
                    ],
                )

            harness_type = os.path.basename(harness_path)
            templates_path = os.path.join(
                os.path.dirname(__file__), "harness_templates", harness_type
            )
            shutil.copytree(templates_path, harness_path)
            libname = self._native_lib.removeprefix("lib").removesuffix(".so")

            # link target library in Makefile's `LDFLAGS`
            replace_old_string_with_new_string(
                Path(os.path.join(harness_path, "Makefile")),
                [
                    (
                        "LDFLAGS=",
                        f" -L{config.LIB64_PATH} -Wl,-rpath={config.LIB64_PATH} -l{libname}",
                    )
                ],
            )

            # add `config.LIB64_PATH` to `LD_LIBRARY_PATH`
            replace_old_string_with_new_string(
                Path(os.path.join(harness_path, "run.sh")),
                [("LD_LIBRARY_PATH=", f"{config.LIB64_PATH}:/system/lib64")],
            )

            # instrument target library in fuzz.sh's `AFL_QEMU_INST_RANGES`
            fill_fuzz_script("quick_fuzz.sh")
            fill_fuzz_script("slow_fuzz.sh")

        # create/find destination harness path
        classname = classname.removeprefix("L").removesuffix(";").replace("/", "_")
        api_namesig = api_namesig.replace("/", "_").replace(" ", "")
        harness_path = os.path.join(config.HARNESS_PATH, apkname, classname, api_namesig)
        os.makedirs(harness_path, exist_ok=True)
        existing_ids = []
        for entry in os.scandir(harness_path):
            if not entry.is_dir():
                continue
            prefix = entry.name.split("_", maxsplit=1)[0]
            if prefix.isdigit():
                existing_ids.append(int(prefix))
        harness_id = max(existing_ids, default=-1) + 1
        disabled_semantics = [
            hint for hint in SEMANTIC_HINTS if hint not in self._enabled_semantics
        ]
        if not disabled_semantics:
            semantics_suffix = "_all_on"
        elif len(disabled_semantics) == len(SEMANTIC_HINTS):
            semantics_suffix = "_all_off"
        else:
            semantics_suffix = "_" + "_".join(
                f"{hint}_off" for hint in disabled_semantics
            )
        harness_path = os.path.join(
            harness_path,
            f"{harness_id}{semantics_suffix}",
        )
        os.mkdir(harness_path)

        apk_path = os.path.join(config.APK_PATH, apkname + ".apk")
        if not os.path.exists(apk_path):
            apk_path = os.path.join(config.APK_PATH, apkname + ".jar")
            assert os.path.exists(apk_path), f"{apk_path} not exist!"

        # output art harness
        art_harness_path = os.path.join(harness_path, "art")
        copy_and_custom_templates(art_harness_path)
        with open(os.path.join(art_harness_path, "harness.cpp"), "w") as f:
            f.write('#include "main.hpp"\n')
            f.write('const char APK_PATH[]{"' + apk_path + '"};\n')
            f.write(
                'const char LIB_PATH[]{"'
                + os.path.join(config.LIB64_PATH, self._native_lib)
                + '"};\n'
            )
            f.write("void cleanup() { }\n")
            f.write(
                "void check_JNI_exception() {\n\tif (env->ExceptionCheck()) {\n\t\tenv->ExceptionDescribe();\n\texit(0);\n\t}\n}\n"
            )
            f.write("void fuzz_one_input() {\n")
            for art_code in self._art_codes:
                for code in art_code:
                    f.write("\t" + code + "\n")
                f.write("\n")
            for alloced_var in self._alloced_vars:
                f.write(f"\tdelete[] {alloced_var};\n")
            f.write("}\n")

        # output mock harness
        if not self._mock_enable:
            return
        mock_harness_path = os.path.join(harness_path, "mock")
        copy_and_custom_templates(mock_harness_path)
        with open(os.path.join(mock_harness_path, "harness.cpp"), "w") as f:
            f.write('#include "main.hpp"\n')
            if self._dynamic_registered:
                f.write('extern "C" jint JNI_OnLoad(JavaVM *vm, void *reserved);\n')
            for declare_code in self._declare_codes:
                f.write(declare_code + "\n")
            f.write('const char APK_PATH[]{"' + apk_path + '"};\n')
            f.write("void cleanup() { jnimock::garbage_collect(); }\n")
            f.write("void check_JNI_exception() { }\n")
            f.write("void fuzz_one_input() {\n")
            for mock_code in self._mock_codes:
                for code in mock_code:
                    f.write("\t" + code.replace("env->", "jnimock::env->") + "\n")
                f.write("\n")
            f.write("\tcleanup();\n")
            for alloced_var in self._alloced_vars:
                f.write(f"\tdelete[] {alloced_var};\n")
            f.write("}\n")
