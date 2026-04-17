import ctypes
import idc
import idaapi
import idautils
import ctypes
import re

import shared
import function
import api
import operand
from shared_def import *


class JNIOnLoadFamilyFunction(function.APIFamilyFunction):
    _native_apis: set[api.API]

    def __init__(
        self, ea: int, env_arg: int | None, _api_arg_index: list[int | None] = list(range(8))
    ):
        self._native_apis = set()
        super().__init__(ea, env_arg, _api_arg_index)
        next_ea = 0
        if self.name == "JNI_OnLoad":
            next_ea = self._JNI_OnLoad_init()
            assert self.env_offset is not None
            self._analyze(next_ea)

    @classmethod
    def _create_callee(
        cls, ea: int, env_arg: int | None, api_arg_index: list[int | None] = list(range(8))
    ):
        return cls(ea, env_arg, api_arg_index)

    @property
    def native_apis(self):
        return self._native_apis

    def _JNI_OnLoad_init(self) -> int:
        """
        find and analyze `vm->GetEnv` to get var `env`.
        Write `self.env_offset`.

        :return ea: address of vm->GetEnv call.
        """

        def get_env_offset(ea: int) -> int | None:
            """
            get stack offset of var `env`

            :param ea: address of vm->GetEnv call
            """
            print(f"[DEBUG] get_env_offset on {hex(ea)} {self.insts[ea].string}")
            offset = 0
            trace_reg = [1, 1 + shared.X0]
            prev_ea = ea
            while prev_ea:
                prev_ea = self._prev_inst(prev_ea)
                if not prev_ea:
                    continue
                inst = self.insts[prev_ea]
                if inst.is_STR() and inst.operands[1].reg == 1 + shared.X0:
                    # STR XZR, [X1,#-0x30]!
                    if "]!" not in inst.string:
                        continue
                    offset += ctypes.c_int32(inst.operands[1].addr).value
                    continue
                if not (
                    inst.opcode.startswith("MOV")
                    or inst.opcode.startswith("ADD")
                    or inst.opcode.startswith("SUB")
                ):
                    continue
                if inst.operands[0].reg not in trace_reg:
                    continue
                if not self._points_to_stack(prev_ea, inst.operands[1].reg):
                    assert inst.opcode.startswith("ADD") and inst.operands_str[2].endswith(
                        "@PAGEOFF"
                    )
                    return inst.operands[2].value
                if not inst.opcode.startswith("MOV"):
                    assert inst.operands[2].type == operand.OpType.o_imm
                if inst.opcode.startswith("ADD"):
                    offset += ctypes.c_int32(inst.operands[2].value).value
                elif inst.opcode.startswith("SUB"):
                    offset -= ctypes.c_int32(inst.operands[2].value).value
                if inst.operands[1].reg == shared.SP:
                    return offset
                trace_reg = [inst.operands[1].reg]
            print(f"[ERROR] analyze_env_offset {hex(ea)} failed!")
            return None

        assert self.name == "JNI_OnLoad" and self.env_offset is None
        for ea in idautils.FuncItems(self.start_ea):
            inst = self.insts[ea]
            if not inst.opcode.startswith("BL"):
                continue
            elif inst.operands[0].type == operand.OpType.o_reg:
                # find vm->GetEnv
                offset = self._trace_jni_offset(ea)
                if offset and offset in shared.JVMFUNCS and shared.JVMFUNCS[offset] == "GetEnv":
                    self._env_offset = get_env_offset(ea)
                    if self.env_offset is None:
                        break
                    return ea
        print(f"[WARN] no var `env` in JNI_OnLoad, try X0...")
        self._env_arg = shared.X0
        self._env_offset = 0
        return 0

    def _analyze_RegisterNatives(self, ea: int) -> None:
        """
        analyze env->RegisterNatives or android::AndroidRuntime::registerNativeMethods,
        and write `self._native_apis`

        :param ea: address of RegisterNative call
        """

        def trace_nMethods(ea: int, reg: int) -> int:
            """
            :param ea: sink
            :param reg: sink
            """
            result_type, value = self._trace_sink_to_source(ea, reg)
            if result_type != Trace.IMM:
                print(f"[WARN] can't find the value of nMethods")
                return nMethods_UNKNOWN
            assert type(value) == int
            return value

        print(f"[DEBUG] analyzing RegisterNatives of {hex(ea)}")
        nMethods_UNKNOWN = 0xFFFF
        nMethods: int = 0
        prev_ea = ea
        while prev_ea:
            prev_ea = self._prev_inst(prev_ea)
            if not prev_ea:
                raise InvalidStateError(
                    f"analyze_RegisterNatives {hex(ea)} can't find JNINativeMethods!"
                )
            inst = self.insts[prev_ea]
            if nMethods == 0 and inst.operands[0].reg == 3 + shared.X0:
                if not (inst.opcode.startswith("MOV") or inst.is_LDR()):
                    continue
                if inst.is_LDR():
                    nMethods = trace_nMethods(prev_ea, inst.operands[0].reg)
                elif inst.operands[1].type == operand.OpType.o_reg:
                    print(
                        f"[DEBUG] nMethods is not an immediate value, trying to trace the reg value..."
                    )
                    nMethods = trace_nMethods(prev_ea, inst.operands[1].reg)
                elif inst.operands[1].type == operand.OpType.o_imm:
                    nMethods = inst.operands[1].value
                else:
                    raise InvalidStateError(f"2nd operand of {inst} is neither reg nor imm")
                assert nMethods
                prev_ea = ea
            elif nMethods and inst.operands[0].reg == 2 + shared.X0:
                if inst.opcode.startswith("ADD"):
                    # ADRP X2, #off_BC4AF8@PAGE
                    # ADD  X2, X2, #off_BC4AF8@PAGEOFF
                    _, _, methods_varname = inst.string.partition(", #")
                    methods_varname, _, _ = methods_varname.partition("@PAGEOFF")
                    methods = idaapi.get_name_ea(0, methods_varname)
                elif inst.opcode.startswith("ADRL"):
                    # Arm64 doc: ADRL assembles to two instructions, an ADRP followed by ADD.
                    # ADRL X2, off_AA000
                    methods = inst.operands[1].value
                elif inst.is_LDR():
                    # ADRP X2, #methods_ptr@PAGE
                    # LDR  X2, [X2,#methods_ptr@PAGEOFF] ; methods
                    _, _, methods_varname = inst.operands_str[1].partition(",#")
                    methods_varname = methods_varname.removesuffix("@PAGEOFF]")
                    methods_varname = methods_varname.removesuffix("_ptr")
                    methods = idaapi.get_name_ea(0, methods_varname)
                elif inst.opcode.startswith("MOV"):
                    # MOV X21, X2
                    # MOV X2, X21
                    result_type, value = self._trace_sink_to_source(prev_ea, inst.operands[1].reg)
                    if result_type != Trace.MEM:
                        print(f"[ERROR] can't analyze JNINativeMethods!")
                        break
                    assert type(value) == int
                    methods = value
                else:
                    raise InvalidStateError("RegisterNatives: Wrong JNINativeMethods param!")
                if methods == idc.BADADDR:
                    print(f"[WARN] can't find JNINativeMethods address")
                    break
                for i in range(nMethods):
                    method = methods + i * 0x18
                    java_name = bytes.decode(idc.get_strlit_contents(idc.get_qword(method)))
                    if not (java_name and re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", java_name)):
                        print(f"[DEBUG] invalid java name {java_name}, stop finding methods")
                        break
                    signature = bytes.decode(idc.get_strlit_contents(idc.get_qword(method + 0x8)))
                    if not (signature and signature.startswith("(") and ")" in signature):
                        print(f"[DEBUG] invalid signature {signature}, stop finding methods")
                        break
                    fnPtr: int = idc.get_qword(method + 0x10)
                    if fnPtr == idc.BADADDR or fnPtr != idc.get_func_attr(
                        fnPtr, idc.FUNCATTR_START
                    ):
                        print(f"[DEBUG] invalid func pointer {hex(fnPtr)}, stop finding methods")
                        break
                    binary_name = idc.get_func_name(fnPtr)
                    native_api = api.API(fnPtr, binary_name, java_name, signature)
                    self._native_apis.add(native_api)
                break

    def _merge_analysis_results(self, callee: function.APIFamilyFunction) -> None:
        super()._merge_analysis_results(callee)
        if isinstance(callee, JNIOnLoadFamilyFunction):
            self._native_apis |= callee._native_apis
