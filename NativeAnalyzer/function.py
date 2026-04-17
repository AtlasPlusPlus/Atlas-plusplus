from __future__ import annotations

import ctypes
import idc
import idaapi
import idautils
import ctypes
import networkx as nx

import instruction
import operand
import shared
from shared_def import *


def _can_skip_callee(callee_ea: int, callee_name: str) -> bool:
    """
    judge whether the callee should be skipped.
    """
    return (
        callee_ea == idc.BADADDR
        or callee_ea != idc.get_func_attr(callee_ea, idc.FUNCATTR_START)
        or idc.get_segm_name(callee_ea) == "extern"
        or callee_name in shared.FUNC_WHITELIST
    )


class Function:
    _insts: dict[int, instruction.Instruction]
    _name: str
    _start_ea: int
    _has_cycle: bool

    _inst_count: int
    _loop_count: int
    _cyc_complexity: int
    _call_depth: int
    _risksite_count: int

    def __init__(self, ea: int):
        # if in cache, skip
        if ea in shared.constructed_funcbases:
            for k, v in vars(shared.constructed_funcbases[ea]).items():
                setattr(self, k, v)
            return
        shared.constructed_funcbases[ea] = self

        self._name = idc.get_func_name(ea)
        demangled_name = idc.demangle_name(self._name, idc.INF_SHORT_DN)
        if demangled_name:
            self._name = demangled_name
        self._start_ea = idc.get_func_attr(ea, idc.FUNCATTR_START)

        # record all insts and build CFG
        self._insts = {}
        CFG: nx.DiGraph[int] = nx.DiGraph()
        for bb in idaapi.FlowChart(idaapi.get_func(ea)):
            CFG.add_node(bb.start_ea)
            CFG.add_edges_from((bb.start_ea, next_bb.start_ea) for next_bb in bb.succs())
            bb_ea = bb.start_ea
            while bb_ea < bb.end_ea:
                inst = instruction.Instruction(bb_ea, bb)
                self._insts[bb_ea] = inst
                bb_ea = idc.next_head(bb_ea)
        self._has_cycle = not nx.is_directed_acyclic_graph(CFG)

        # calculate initial heuristics, without heuristics of callees
        self._inst_count = len(self.insts)
        self._loop_count = sum(1 for _ in nx.simple_cycles(CFG, 30))
        self._cyc_complexity = len(CFG.edges) - len(CFG.nodes) + 2
        self._call_depth = 0
        self._risksite_count = 0

        # calculate final heuristics, with heuristics of callees
        self.__analyze_callees()
        self._call_depth += 1

    def __analyze_callees(self):
        """
        analyze callees and update heuristics
        """
        visited_callee: set[int] = {self.start_ea}
        for ea in idautils.FuncItems(self.start_ea):
            inst = self.insts[ea]
            if not inst.is_branch():
                continue

            # only analyze direct call
            if inst.operands[0].type not in {operand.OpType.o_far, operand.OpType.o_near}:
                continue
            callee_name = inst.operands_str[0].removeprefix(".").removeprefix("j_")
            callee_ea = idc.get_name_ea_simple(callee_name)
            if _can_skip_callee(callee_ea, callee_name):
                if any(keyword in callee_name for keyword in shared.RISKY_API_KEYWORDS):
                    self._risksite_count += 1
                continue
            if callee_ea in visited_callee:
                continue

            # update caller's heuristics
            if callee_ea in shared.constructed_funcbases:
                callee = shared.constructed_funcbases[callee_ea]
            else:
                callee = Function(callee_ea)
            self._inst_count += callee.inst_count
            self._loop_count += callee.loop_count
            self._cyc_complexity += callee.cyc_complexity
            if callee.call_depth > self._call_depth:
                self._call_depth = callee.call_depth
            self._risksite_count += callee.risksite_count
            visited_callee.add(callee_ea)

    @property
    def insts(self):
        return self._insts

    @property
    def name(self):
        return self._name

    @property
    def start_ea(self):
        return self._start_ea

    @property
    def has_cycle(self):
        return self._has_cycle

    @property
    def inst_count(self):
        return self._inst_count

    @property
    def loop_count(self):
        return self._loop_count

    @property
    def cyc_complexity(self):
        return self._cyc_complexity

    @property
    def call_depth(self):
        return self._call_depth

    @property
    def risksite_count(self):
        return self._risksite_count


class APIFamilyFunction(Function):
    """
    Functions related to APIs. Precisely, functions with dataflow from Java.

    e.g. API and its callees whom API's parameters flow to.
    """

    _env_arg: int | None  # denote which argument/var is JNIEnv*. For JNI_OnLoad it denotes vm_arg
    _env_offset: int | None  # int only if it's JNI_OnLoad

    _has_cycle: bool
    _jni_calls: set[int]  # {jni_call_offset, ...}. filled by `find_jni_calls` method

    # "_api_arg_index[2] = 1" means X2 is originally jclass/jobject `thiz` (X1) of native api
    _api_arg_index: list[int | None]
    # "_attr[2] & Attribute.PATH == Attribute.PATH" means X2 is a file path
    _attr: list[Attribute]

    # [(api_arg_index, class name, field name), ...]
    _set_field_info: set[tuple[int, str, str]]
    _get_field_info: set[tuple[int, str, str]]

    def __init__(
        self, ea: int, env_arg: int | None, _api_arg_index: list[int | None] = list(range(8))
    ):
        super().__init__(ea)
        self._env_arg = env_arg
        self._env_offset = None

        self._jni_calls = set()

        self._api_arg_index = _api_arg_index
        self._set_field_info = set()
        self._get_field_info = set()
        self._attr = [Attribute.NONE for _ in range(8)]

        print(
            f"[INFO] constructed {self.name}, env_arg: {self.env_arg}, api_arg_index: {self.api_arg_index}"
        )
        shared.api_related_funcs[self.start_ea] = self

        if self.name != "JNI_OnLoad":
            self._analyze()

    @classmethod
    def _create_callee(
        cls, ea: int, env_arg: int | None, api_arg_index: list[int | None] = list(range(8))
    ):
        return cls(ea, env_arg, api_arg_index)

    @property
    def env_arg(self):
        return self._env_arg

    @property
    def env_offset(self):
        return self._env_offset

    @property
    def jni_calls(self):
        return self._jni_calls

    @property
    def api_arg_index(self):
        return self._api_arg_index

    @property
    def set_field_info(self):
        return self._set_field_info

    @property
    def get_field_info(self):
        return self._get_field_info

    @property
    def attr(self):
        return self._attr

    def _prev_inst(self, ea: int) -> int | None:
        """
        Get addr of prev inst. It only chooses one prev_bb.
        """
        bb = self.insts[ea].bb
        if ea > bb.start_ea:
            prev_ea = idc.prev_head(ea)
        else:  # prev_ea == bb.start_prev_ea
            if self.has_cycle:
                for prev_bb in bb.preds():
                    if prev_bb.id < bb.id:
                        break
                else:
                    prev_bb = None
            else:
                prev_bb = next(bb.preds(), None)
            if prev_bb:
                prev_ea = idc.prev_head(prev_bb.end_ea)
            else:
                prev_ea = None
        return prev_ea

    def _prev_insts(self, ea: int):
        prev_ea = ea
        while prev_ea and prev_ea >= self.start_ea:
            yield prev_ea
            if prev_ea == self.start_ea:
                break
            prev_ea = self._prev_inst(prev_ea)

    def _points_to_stack(self, ea: int, reg: int) -> bool:
        """
        Judge whether reg (at ea) points to stack

        :param ea: address of `LDR Xa, [Xb, #offset]`
        :param reg: base register
        """
        if reg == shared.SP:
            return True
        prev_ea = self._prev_inst(ea)
        if not prev_ea:
            return False
        result_type, value = self._trace_sink_to_source(prev_ea, self.insts[ea].operands[1].reg)
        return result_type == Trace.REG and type(value) == int and value == shared.SP

    def _trace_sink_to_source(self, ea: int, reg: int) -> TraceResult:
        """
        Perform bottom-to-up taint analysis.

        :param ea, reg: sink
        :return source:
        """

        def analyze_memcpy(ea: int, reg: int) -> int | None:
            """
            if current `reg` is dest of memcpy, return the addr of source assignment inst.

            :param ea: addr of memcpy call
            :return src_ea: None if dest is not `reg`
            """
            src_ea = None
            dest = None
            for ea in self._prev_insts(ea):
                inst = self.insts[ea]
                if not inst.operands:
                    continue
                if inst.operands[0].reg == 1 + shared.X0:
                    if not (inst.opcode.startswith("MOV") or inst.is_algo_MOV() or inst.is_LDR()):
                        print("[WARN] can't find the source of memcpy")
                        return
                    src_ea = ea
                elif inst.operands[0].reg == shared.X0:
                    if not inst.opcode.startswith("MOV"):
                        print("[WARN] can't find the dest of memcpy")
                        return
                    dest = reg
                    if inst.operands[1].reg != reg:
                        return
                if dest is not None and src_ea is not None:
                    return src_ea

        # print(f"[DEBUG] trace_sink_to_source: {hex(ea)} {self.insts[ea].string}, reg: {reg}")
        for ea in self._prev_insts(ea):
            inst = self.insts[ea]
            if inst.opcode.startswith("BL") and inst.operands_str[0].removeprefix(".") == "memcpy":
                prev_ea = analyze_memcpy(ea, reg)
                if prev_ea is not None:
                    print(f"[DEBUG] traced to source of memcpy at {hex(ea)}")
                    return self._trace_sink_to_source(prev_ea, 1 + shared.X0)
            if reg == shared.X0 and inst.opcode.startswith("BL"):
                offset = self._trace_jni_offset(ea)
                if (
                    offset
                    and offset in shared.JNIFUNCS
                    and shared.JNIFUNCS[offset] in {"GetStringUTFChars", "GetStringChars"}
                ):
                    return self._trace_sink_to_source(ea, shared.X0 + 1)
                print(f"[DEBUG] traced to return value of {hex(ea)} {inst.string}, stopped.")
                return Trace.RET, ea
            if not inst.operands or inst.operands[0].type != operand.OpType.o_reg:
                continue

            if inst.is_LDP() or inst.is_LDR():
                if inst.is_LDR():
                    if (
                        inst.operands[0].reg != reg
                        or inst.operands[1].type != operand.OpType.o_displ
                    ):
                        continue
                    if self.env_offset is not None and inst.operands[1].addr == self.env_offset:
                        if inst.operands_str[1].endswith("@PAGEOFF]"):
                            return Trace.MEM, inst.operands[1].addr
                        else:
                            return Trace.STACK, inst.operands[1].addr
                    reg_loc = 0
                    offset = ctypes.c_int32(inst.operands[1].addr).value
                    extra_offset = 0
                    base_reg = inst.operands[1].reg
                else:  # inst.is_LDP()
                    if inst.operands[0].reg == reg:
                        reg_loc = 0
                        extra_offset = 0
                    elif inst.operands[1].reg == reg:
                        reg_loc = 1
                        if inst.operands_str[1].startswith("X"):
                            extra_offset = 8
                        elif inst.operands_str[1].startswith("W"):
                            extra_offset = 4
                        else:
                            raise NotImplementedError(
                                "operand register of LDP or LDNP is not X nor W!"
                            )
                    else:
                        continue
                    if inst.operands[2].type != operand.OpType.o_displ:
                        continue
                    offset = ctypes.c_int32(inst.operands[2].addr).value
                    base_reg = inst.operands[2].reg
                if self._points_to_stack(ea, base_reg):
                    # only for stack we trace the offset strictly
                    # e.g. trace `STRH.W R1, [SP,#0x1F8+var_1F4]` from `LDRSH.W R0, [SP,#0x1F8+var_1F4]`
                    if self.env_offset is not None:
                        if inst.is_LDR() and offset == self.env_offset:
                            return Trace.STACK, offset
                        # inst.is_LDP()
                        if reg_loc == 0 and offset == self.env_offset:
                            return Trace.STACK, offset
                        if reg_loc == 1 and offset + extra_offset == self.env_offset:
                            return Trace.STACK, offset + extra_offset
                    st_ea = ea
                    while st_ea:
                        st_ea = self._prev_inst(st_ea)
                        if not st_ea:
                            continue
                        st_inst = self.insts[st_ea]
                        if not (st_inst.is_STR() or st_inst.is_STP()):
                            continue
                        if (
                            st_inst.is_STR()
                            and st_inst.operands[1].type == operand.OpType.o_displ
                            and st_inst.operands[1].reg == base_reg
                            and ctypes.c_int32(st_inst.operands[1].addr).value
                            == offset + extra_offset
                        ):
                            reg = st_inst.operands[0].reg
                            break
                        if (
                            st_inst.is_STP()
                            and st_inst.operands[2].type == operand.OpType.o_displ
                            and st_inst.operands[2].reg == base_reg
                        ):
                            st_offset = ctypes.c_int32(st_inst.operands[2].addr).value
                            if st_offset == offset:
                                reg = st_inst.operands[reg_loc].reg
                                break
                            if reg_loc == 0 and st_offset + extra_offset == offset:
                                reg = st_inst.operands[1].reg
                                break
                            elif reg_loc == 1 and st_offset == offset + extra_offset:
                                reg = st_inst.operands[0].reg
                                break
                    else:
                        # maybe arguments passed through stack, or other cases
                        print(f"[DEBUG] can't trace the stack STR/STP of {inst.string}")
                        return Trace.STACK, None
                    return self._trace_sink_to_source(st_ea, reg)
                else:
                    reg = base_reg
                continue
            if inst.operands[0].reg != reg:
                continue
            if inst.opcode.startswith("MOV"):  # reg/imm -> reg: MOVS, MOV.W, MOVS.W, ...
                match inst.operands[1].type:
                    case operand.OpType.o_reg:
                        reg = inst.operands[1].reg
                    case operand.OpType.o_imm:
                        return Trace.IMM, inst.operands[1].value
                    case _:
                        raise InvalidStateError(
                            f"MOV's 2nd operand type must be `o_reg` or `o_imm`: {inst.string}"
                        )
            elif inst.is_algo_MOV():  # reg -> reg: ADD, SUB, ...
                if inst.opcode.startswith("ADD") and inst.operands[1].reg == shared.SP:
                    # ADD X29, SP, #0x190
                    return Trace.REG, inst.operands[1].reg
                reg = inst.operands[1].reg
            elif inst.opcode.startswith("ADR"):
                if inst.opcode.startswith("ADRP"):
                    # ADRP X2, #(aIvllegalOptionF_11+0x15)@PAGE ; "inPreferredConfig"
                    # ADRP X1, #off_47108@PAGE
                    _, _, addr_name = inst.string.partition(", #")
                    addr_name, _, _ = addr_name.partition("@PAGE")
                    addr_name = addr_name.removeprefix("(").removesuffix(")")
                    base, _, offset = addr_name.partition("+")
                    addr = idaapi.get_name_ea(0, base)
                    if offset:
                        offset = int(offset, 16)
                        addr += offset
                else:  # ADRL or ADR
                    # ADRL X1, aA  ; "a+"
                    # ADR  X1, aW  ; "w"
                    addr = inst.operands[1].value
                if addr == idc.BADADDR:
                    _, _, string = inst.string.partition('; "')
                    string = string.removesuffix('"')
                    if string and '"...' not in string:
                        return Trace.STR, string
                return Trace.MEM, addr
            elif (
                any(inst.opcode.startswith(op) for op in {"ADD", "SUB"})
                and len(inst.operands) == 3
                and inst.operands[1].type == operand.OpType.o_reg
            ):
                reg = inst.operands[1].reg

        return Trace.REG, reg

    def _trace_jni_offset(self, ea: int) -> int | None:
        """
        Trace offset of env->*. Also judge whether it is a JNI function.

        :param ea: address of BLR/BLX
        :return offset: None if it's not a JNI function
        """
        print(
            f"[DEBUG] trace_jni_offset of {self.name} {self.env_arg} {hex(ea)} {self.insts[ea].string}"
        )
        reg = self.insts[ea].operands[0].reg
        offset = None

        # get offset
        prev_ea = ea
        trace_stack = False
        while prev_ea:
            prev_ea = self._prev_inst(prev_ea)
            if not prev_ea:
                continue
            inst = self.insts[prev_ea]
            if trace_stack:
                if not inst.is_STR():
                    continue
                if inst.operands[1].reg != stack_reg or inst.operands[1].addr != stack_offset:
                    continue
                reg = inst.operands[0].reg
                trace_stack = False
            elif (
                inst.is_LDR()
                and inst.operands[1].type == operand.OpType.o_displ
                and inst.operands[0].reg == reg
            ):
                if self._points_to_stack(prev_ea, inst.operands[1].reg):
                    stack_reg = inst.operands[1].reg
                    stack_offset = inst.operands[1].addr
                    trace_stack = True
                    continue
                offset = inst.operands[1].addr
                reg = inst.operands[1].reg
                break
        if offset is None:
            return offset
        assert prev_ea is not None
        ea = prev_ea

        # judge whether it's a JNI function
        result_type, value = self._trace_sink_to_source(ea, reg)
        if type(value) != int:
            return None
        if self.env_offset is not None and (result_type == Trace.STACK or result_type == Trace.MEM):
            return offset
        if result_type == Trace.REG and value == self.env_arg:
            return offset
        return None

    def _merge_analysis_results(self, callee: APIFamilyFunction) -> None:
        """
        merge callee's results to self.

        Merge
        - self.jni_calls
        - self.get_field_info
        - self.set_field_info
        - self.attr
        """
        self._jni_calls |= callee.jni_calls
        self._set_field_info |= callee.set_field_info
        self._get_field_info |= callee.get_field_info
        for callee_arg in range(8):
            origin = callee.api_arg_index[callee_arg]
            if origin is None:
                continue
            # arg = self.api_arg_index.find(origin)
            arg = next((i for i, arg in enumerate(self.api_arg_index) if arg == origin), None)
            if arg is None:
                continue
            self.attr[arg] |= callee.attr[callee_arg]

    def _analyze_RegisterNatives(self, ea: int):
        """
        implemented by derived class JNI_OnLoad

        :param ea: callsite of RegisterNatives
        """
        pass

    def _analyze(self, start_ea=0) -> None:
        """
        analyze self and callees recursively.

        Write
        - self.jni_calls
        - self.get_field_info
        - self.set_field_info
        - self.attr
        """
        print(f"[DEBUG] analyze {self.name}")
        for ea in idautils.FuncItems(self.start_ea):
            if ea <= start_ea:
                continue
            inst = self.insts[ea]
            if not inst.is_branch():  # BL, BLR, BLX, BR(tail)
                continue

            # find jni calls in this function
            if inst.operands[0].type == operand.OpType.o_reg:
                if inst.string.endswith("switch jump"):
                    continue
                offset = self._trace_jni_offset(ea)
                if offset and offset in shared.JNIFUNCS:
                    self.jni_calls.add(offset)
                    if shared.JNIFUNCS[offset] == "RegisterNatives":
                        self._analyze_RegisterNatives(ea)
                    elif shared.JNIFUNCS[offset].endswith("Field"):
                        if shared.JNIFUNCS[offset].startswith("Get"):
                            isSetField = False
                        else:
                            isSetField = True
                        self._analyze_field(ea, isSetField)
                continue

            # analyze callees (only direct call)
            if inst.operands[0].type not in {operand.OpType.o_far, operand.OpType.o_near}:
                continue
            callee_name = inst.operands_str[0].removeprefix(".").removeprefix("j_")
            if callee_name in shared.REGISTER_NATIVES_WRAPPER:
                self._analyze_RegisterNatives(ea)
                continue
            if callee_name in shared.FILE_API:
                self._analyze_file_api(ea, callee_name)
                continue
            callee_ea = idc.get_name_ea_simple(callee_name)
            if _can_skip_callee(callee_ea, callee_name) or callee_ea == self.start_ea:
                continue

            # skip analysis for analyzed functions
            if callee_ea in shared.api_related_funcs:
                fc = shared.api_related_funcs[callee_ea]
                self._merge_analysis_results(fc)
                continue

            if callee_name.startswith("_ZN7_JNIEnv"):
                fc = self._create_callee(callee_ea, shared.X0)
                self._merge_analysis_results(fc)
                continue

            # check whether it passes `env` to the callee and which arg it is
            passed_env_arg = None
            api_arg_index: list[int | None] = [None, None, None, None, None, None, None, None]
            if not inst.opcode.startswith("BL"):  # B
                for i in range(8):
                    result_type, value = self._trace_sink_to_source(ea, i + shared.X0)
                    if type(value) != int:
                        continue
                    if self.env_offset is not None and (
                        result_type == Trace.STACK or result_type == Trace.MEM
                    ):
                        passed_env_arg = i + shared.X0
                        continue
                    if result_type == Trace.REG:
                        if value < shared.X0 or value > 7 + shared.X0:
                            continue
                        if value == self.env_arg:
                            passed_env_arg = i + shared.X0
                        api_arg_index[i] = self.api_arg_index[value - shared.X0]
            else:  # BL
                prev_ea = ea
                passed_args = None
                while prev_ea:
                    prev_ea = self._prev_inst(prev_ea)
                    if not prev_ea:
                        continue
                    inst = self.insts[prev_ea]
                    if inst.is_STR() or inst.is_STP():
                        continue
                    if not (inst.opcode.startswith("MOV") or inst.is_algo_MOV() or inst.is_LDR()):
                        break
                    if inst.operands[0].reg < shared.X0 or inst.operands[0].reg > 7 + shared.X0:
                        # not regs for arguments
                        continue
                    if passed_args is None:
                        end_reg = inst.operands[0].reg + 1
                        start_reg = shared.X0
                        passed_args = set(range(start_reg, end_reg))

                    if inst.operands[0].reg in passed_args:
                        passed_args.remove(inst.operands[0].reg)
                    if inst.operands[1].type not in {operand.OpType.o_reg, operand.OpType.o_displ}:
                        continue
                    result_type, value = self._trace_sink_to_source(prev_ea, inst.operands[0].reg)
                    if type(value) != int:
                        continue
                    if self.env_offset is not None:
                        if result_type == Trace.STACK or result_type == Trace.MEM:
                            passed_env_arg = inst.operands[0].reg
                        continue
                    if result_type != Trace.REG:
                        continue
                    if value < shared.X0 or value > 7 + shared.X0:
                        continue
                    if value == self.env_arg:
                        passed_env_arg = inst.operands[0].reg
                    api_arg_index[inst.operands[0].reg - shared.X0] = self.api_arg_index[
                        value - shared.X0
                    ]
                if passed_args is None:
                    passed_args = set(range(shared.X0, 4 + shared.X0))
                for passed_arg in passed_args:
                    prev_ea = self._prev_inst(ea)
                    if not prev_ea:
                        continue
                    result_type, value = self._trace_sink_to_source(prev_ea, passed_arg)
                    if type(value) != int:
                        continue
                    if self.env_offset is not None:
                        if result_type == Trace.STACK or result_type == Trace.MEM:
                            passed_env_arg = passed_arg
                        continue
                    if result_type != Trace.REG:
                        continue
                    if value < shared.X0 or value > 7 + shared.X0:
                        continue
                    if value == self.env_arg:
                        passed_env_arg = passed_arg
                    api_arg_index[passed_arg - shared.X0] = self.api_arg_index[value - shared.X0]
            if all(arg is None for arg in api_arg_index) and passed_env_arg is None:
                continue
            callee_name = idc.get_func_name(callee_ea)
            if idc.demangle_name(callee_name, idc.INF_SHORT_DN):
                callee_name = idc.demangle_name(callee_name, idc.INF_SHORT_DN)
            print(f"[DEBUG] caller: {self.name}, callee: {callee_name}")
            fc = self._create_callee(callee_ea, passed_env_arg, api_arg_index)
            self._merge_analysis_results(fc)
        print(f"[DEBUG] {self.name} analyzed, jni_calls: {self.jni_calls}")

    def _analyze_file_api(self, ea: int, api_name: str) -> None:
        """
        analyze which arg is path string and write `self.attr`

        :param ea: address of file API call
        :param api_name:
        """
        print(f"[DEBUG] analyzing file api {api_name} from {self.name}@{hex(ea)}")
        if api_name in ("fopen", "dlopen"):
            target_reg = shared.X0
        else:
            target_reg = shared.X0 + 1
        prev_ea = self._prev_inst(ea)
        assert prev_ea is not None
        result_type, value = self._trace_sink_to_source(prev_ea, target_reg)
        if result_type == Trace.REG:  # arg -> target_reg
            assert type(value) == int
            if shared.X0 <= value < shared.X0 + 8:
                self.attr[value - shared.X0] |= Attribute.PATH
            return
        if result_type != Trace.RET:
            return

        # ret value -> target_reg, only support GetStringUTFChars currently
        assert type(value) == int
        callee_ea = value
        inst = self.insts[callee_ea]
        callee_name = inst.operands_str[0].removeprefix(".").removeprefix("j_")
        if inst.operands[0].type == operand.OpType.o_reg:
            if inst.string.endswith("switch jump"):
                return
            offset = self._trace_jni_offset(callee_ea)
            if not (
                offset
                and offset in shared.JNIFUNCS
                and shared.JNIFUNCS[offset] == "GetStringUTFChars"
            ):
                return
        elif callee_name != "_ZN7JNIEnv_17GetStringUTFCharsEP8_jstringPh":
            return

        # trace path jstring from GetStringUTFChars callsite
        result_type, value = self._trace_sink_to_source(callee_ea, shared.X0 + 1)
        assert result_type == Trace.REG and type(value) == int
        self.attr[value - shared.X0] |= Attribute.PATH

    def _analyze_field(self, ea: int, isSetField: bool) -> None:
        """
        analyze Get/Set*Field, track fieldname, classname and class/object reg index.
        Write `self.set_field_info` or `self.get_field_info`

        :param ea: address of Get/Set*Field call
        :param isSetField: True for SetField, False for GetField
        :param static: True for Get/SetStatic*Field
        """

        def get_str_from_mem(addr: int) -> str | None:
            """
            :addr: memory address
            :return str: None if the address is not a string
            """
            if addr == idc.BADADDR:
                return
            string = idc.get_strlit_contents(addr)
            if string is not None:
                string = str(string, encoding="utf-8")
            return string

        print(f"[DEBUG] analyze Get/Set*Field at {hex(ea)}")
        if isSetField:
            # trace X3 (value) of Set*Field. if SetField to 0, ignore
            result_type, value = self._trace_sink_to_source(ea, 3 + shared.X0)
            if (result_type == Trace.IMM and value == 0) or (
                result_type == Trace.REG and value == shared.XZR
            ):
                print(f"[DEBUG] analyze_field: {hex(ea)} ignore SetField to 0")
                return

        # trace X1 (jobject/jclass) of Get/Set*Field
        result_type, value = self._trace_sink_to_source(ea, 1 + shared.X0)
        if result_type != Trace.REG:
            print(
                f"[DEBUG] analyze_field: {hex(ea)} target jobject/jclass is not from api argument!"
            )
            return
        assert type(value) == int
        if value < shared.X0 or value > 7 + shared.X0:
            print(
                f"[DEBUG] analyze_field: {hex(ea)} target jobject/jclass is not from api argument!"
            )
            return
        target = self.api_arg_index[value - shared.X0]
        if target is None:
            print(
                f"[WARN] analyze_field: {hex(ea)} can't find target jobject/jclass from api argument!"
            )
            return

        # trace X2 (jfieldID) of Get/Set*Field to find Get*FieldID
        result_type, value = self._trace_sink_to_source(ea, 2 + shared.X0)
        if result_type != Trace.RET or type(value) != int:
            print(f"[WARN] {hex(ea)}: fieldID is not from a return value!")
            return
        inst = self.insts[value]
        assert inst.opcode.startswith("BL")
        if inst.operands[0].type in (operand.OpType.o_near, operand.OpType.o_far):
            print(f"[WARN] {hex(value)}: fieldID is not from env->GetFieldID!")
            return
        offset = self._trace_jni_offset(value)
        assert offset in shared.JNIFUNCS and shared.JNIFUNCS[offset].endswith("FieldID")
        ea = value

        # trace X2 (field name) of Get*FieldID
        result_type, value = self._trace_sink_to_source(ea, 2 + shared.X0)
        if result_type == Trace.MEM and type(value) == int:
            value = get_str_from_mem(value)
        if type(value) != str:
            print(f"[WARN] {hex(ea)}: field name is not from a string!")
            return
        field_name = value

        # trace X1 (jclass) of Get*FieldID
        class_name = ""
        result_type, value = self._trace_sink_to_source(ea, 1 + shared.X0)
        assert type(value) == int
        if result_type == Trace.REG:  # jclass from arg
            assert shared.X0 <= value <= 7 + shared.X0
            ri = self.api_arg_index[value - shared.X0]
        elif result_type == Trace.RET:  # jclass from return value
            ea = value
            offset = self._trace_jni_offset(value)
            assert offset in shared.JNIFUNCS

            # trace X1 (class name) of FindClass, ignore GetObjectClass
            result_type, value = self._trace_sink_to_source(ea, 1 + shared.X0)
            if shared.JNIFUNCS[offset] == "FindClass":
                if result_type == Trace.MEM and type(value) == int:
                    value = get_str_from_mem(value)
                assert type(value) == str
                class_name = value

        field_info = (target, class_name, field_name)
        if isSetField:
            self.set_field_info.add(field_info)
        else:
            self.get_field_info.add(field_info)
