from __future__ import annotations

__desc__ = ""

import os
import json
from dataclasses import dataclass
from androguard.core.analysis.analysis import (
    ClassAnalysis,
    MethodAnalysis,
    FieldAnalysis,
    DEXBasicBlock,
)
from collections import defaultdict, OrderedDict
from typing import Literal, Iterator
from .. import config
from . import util
from . import shared
from . import instruction
from . import operand
from . import parameter
from . import jenum
from .shared_def import *


@dataclass
class Method:
    """
    Node of Method Dependency Graph.

    Use full_name (with spaces) as hash
    """

    _analysis: MethodAnalysis
    _params: list[parameter.Parameter]
    _insts: dict[int, instruction.Instruction]  # {offset1: inst1, ...}, sequently inserted

    def __init__(self, analysis: MethodAnalysis, attributes: list[Attribute] | None = None):
        self._analysis = analysis
        descriptors, _, _ = analysis.descriptor.removeprefix("(").partition(")")
        descriptors = descriptors.split()
        param_num = len(descriptors)
        if "native" in analysis.access:
            param_regs = list(range(param_num))
        else:
            param_regs: list[int] = []
            if "params" in analysis.method.get_information():
                param_regs: list[int] = [
                    reg for reg, _ in analysis.method.get_information()["params"]
                ]
        if not attributes:
            attributes = [Attribute.IGNORE for _ in range(param_num)]
        self._params = [
            parameter.Parameter(
                param_regs[i],
                descriptors[i],
                attributes[i] if i < 6 else Attribute.IGNORE,
                set(),
                False,
            )
            for i in range(param_num)
        ]

        # complement exception for control flow graph
        for bb in self.analysis.basic_blocks:
            bb_exception_analysis = bb.get_exception_analysis()
            if not bb_exception_analysis:
                continue
            for _, _, handler_bb in bb_exception_analysis.exceptions:
                handler_bb: DEXBasicBlock
                handler_bb.get_prev
                handler_bb.set_fathers((-1, -1, bb))

        # parse and record all instructions
        self._insts = {}
        if "native" in analysis.access:
            return
        for offset, inst in analysis.method.get_instructions_idx():
            inst = instruction.Instruction(inst)
            self._insts[offset] = inst

    def _prev_insts_offset(self, offset: int) -> Iterator[int]:
        """
        get offsets of prev instructions (offset itself included).

        It only chooses one prev_bb
        """
        offsets = list(self.insts.keys())
        while offset >= 0:
            yield offset
            bb = self.analysis.basic_blocks.get_basic_block(offset)
            assert bb
            idx = offsets.index(offset)
            while offset > bb.start:
                idx -= 1
                offset = offsets[idx]
                yield offset
            prev_bbs = bb.get_prev()
            if not prev_bbs:
                return
            prev_bb = prev_bbs[0]
            offset = prev_bb.end - prev_bb.get_last().get_length()

    def trace_source(self, offset: int, sink: operand.Operand) -> operand.Operand:
        """
        Perform bottom-to-up taint analysis.
        """
        for offset in self._prev_insts_offset(offset):
            inst = self._insts[offset]
            sink = inst.backward_propogate(sink)
            if sink.type == operand.OpType.NEW_ARRAY:
                sizes = self._trace_array_size(offset)
                if len(sizes) > 1:
                    util.log(LogLevel.DEBUG, f"array size has more than 1 value: {sizes}")
                if sizes:
                    return operand.Operand((operand.OpType.NEW_ARRAY, sizes.pop().value))
                return sink
            elif sink.type == operand.OpType.ARRAY_LEN:
                # TODO: reimplement array-len
                if sink.points_to:
                    return sink
                if offset:
                    prev_offsets = self._prev_insts_offset(offset)
                    _ = next(prev_offsets)
                    array = self.trace_source(next(prev_offsets), inst.operands[-1])
                else:
                    array = inst.operands[-1]
                match array.type:
                    case operand.OpType.REGISTER:
                        desc = None
                        for param in self._params:
                            if param.reg == array.value:
                                desc = param.descriptor
                    case operand.OpType.NEW_ARRAY:
                        desc = array.points_to
                    case operand.OpType.METH:
                        assert array.points_to
                        desc = array.points_to.split("->")[-1].rsplit(")")[-1]
                    case operand.OpType.FIELD:
                        _, _, desc = array.get_field_info()
                    case _:
                        raise NotImplementedError(array)
                assert desc
                return operand.Operand((operand.OpType.ARRAY_LEN.value, -1, desc))
            elif sink.type == operand.OpType.STRING_LEN:
                return operand.Operand((operand.OpType.STRING_LEN, offset, self.analysis.full_name))
            elif sink.type == operand.OpType.OFFSET:
                assert type(sink.value) == int
                print(f"sink: {sink}, {hex(offset)}, {hex(sink.value)}")
                return self.trace_source(offset + sink.value * 2, sink)
            elif sink.type == operand.OpType.METH:
                if (
                    sink.points_to
                    == "Ljava/nio/ByteBuffer;->allocateDirect(I)Ljava/nio/ByteBuffer;"
                ):
                    sizes = self._trace_buffer_size(offset)
                    if len(sizes) > 1:
                        util.log(LogLevel.DEBUG, f"buffer size has more than 1 value: {sizes}")
                    if sizes:
                        return operand.Operand((operand.OpType.NEW_BUFFER, sizes.pop().value))
                    return sink
            if sink.type not in {
                operand.OpType.REGISTER,
                operand.OpType.RETURN_VALUE,
            }:
                break
        return sink

    def _trace_buffer_size(self, offset: int) -> set[operand.Operand]:
        """
        :param offset: the offset of `invoke Ljava/nio/ByteBuffer;->allocateDirect(I)Ljava/nio/ByteBuffer;`
        :return: all possible literal sizes of the new buffer
        """
        inst = self._insts[offset]
        assert (
            inst.operands[-1].points_to
            == "Ljava/nio/ByteBuffer;->allocateDirect(I)Ljava/nio/ByteBuffer;"
        )
        size_sink = inst.operands[0]
        prev_offsets = self._prev_insts_offset(offset)
        _ = next(prev_offsets)
        prev_offset = next(prev_offsets)
        sizes = [
            size
            for size in self.trace_sources(prev_offset, size_sink)
            if size.type == operand.OpType.LITERAL
        ]
        return set(sizes)

    def _trace_array_size(self, offset: int) -> set[operand.Operand]:
        """
        :param offset: the offset of `new-array` inst
        :return: all possible literal sizes of the new array
        """
        inst = self._insts[offset]
        assert inst.analysis.get_name() == "new-array"
        size_sink = inst.operands[1]
        prev_offsets = self._prev_insts_offset(offset)
        _ = next(prev_offsets)
        prev_offset = next(prev_offsets)
        sizes = [
            size
            for size in self.trace_sources(prev_offset, size_sink)
            if size.type == operand.OpType.LITERAL
        ]
        return set(sizes)

    def trace_sources(self, offset: int, sink: operand.Operand) -> set[operand.Operand]:
        """
        trace sources of `sink` at `offset`
        """

        sources: set[operand.Operand] = set()
        source = self.trace_source(offset, sink)
        if source.type == operand.OpType.REGISTER:  # param -> sink
            param = None
            for param in self._params:
                if param.reg == source.value:
                    param.attribute |= Attribute.TRACE
                    break
            assert param
            self.trace_params()
            for param_source in param.sources:
                sources.add(param_source)
        else:
            sources.add(source)
        return sources

    def trace_params(self) -> None:
        """
        trace argument passes from callers recursively.
        write `self.arg_src` and `self.arg_attr`
        """
        # refuse to trace if all params should be traced have already been traced
        if all(
            Attribute.TRACE in param.attribute and param.traced == True for param in self._params
        ):
            return

        for cls, method_analysis, callsite in self.analysis.get_xref_from():
            caller = get_method(method_analysis)
            if "<init>" in self.analysis.name and any(
                self.analysis.get_class_name() in caller_arg.descriptor
                for caller_arg in caller.params
            ):
                continue
            util.log(
                LogLevel.DEBUG,
                f"tracing params for {self.analysis.name}, callsite: {hex(callsite)} of {caller.analysis.full_name}",
            )
            call_inst = caller.insts[callsite]
            next_idx = 0
            if "static" not in self.analysis.access:
                # skip `this` for non-static method
                next_idx = 1
            for callee_param in self._params:
                pass_idx = next_idx
                if callee_param.descriptor in {
                    "J",
                    "D",
                }:  # long and double need 2 regs to represent
                    next_idx += 2
                else:
                    next_idx += 1
                if Attribute.TRACE not in callee_param.attribute:
                    continue
                pass_reg = call_inst.operands[pass_idx]
                param_source = caller.trace_source(callsite, pass_reg)

                # update callee param source
                if param_source.type == operand.OpType.FIELD:  # field -> param
                    _, field_name, _ = param_source.get_field_info()
                    if any(keyword in field_name.casefold() for keyword in shared.SIZE_KEYWORDS):
                        callee_param.attribute |= Attribute.SIZE
                    if (
                        any(keyword in field_name.casefold() for keyword in shared.PATH_KEYWORDS)
                        and callee_param.descriptor == "Ljava/lang/String;"
                    ):
                        callee_param.attribute |= Attribute.PATH
                    if param_source.is_external():
                        util.log(LogLevel.DEBUG, f"ignore external source {param_source}")
                    else:
                        callee_param.sources.add(param_source)
                elif param_source.type == operand.OpType.REGISTER:  # param -> param
                    # update caller param attribute
                    if (
                        param_source.value
                        == caller.analysis.method.get_information()["registers"][-1]
                    ):
                        # this -> param
                        this_name = caller.analysis.get_class_name()
                        this = operand.Operand((operand.OpType.TYPE.value, 0, this_name))
                        callee_param.sources.add(this)
                    else:
                        for i, caller_arg in enumerate(caller._params):
                            if caller_arg.reg == param_source.value:
                                caller_arg.attribute |= callee_param.attribute
                                callee_param.sources.add(
                                    operand.Operand((operand.OpType.ARGUMENT, i))
                                )
                                break
                        else:
                            raise InvalidStateError("can't find the relevant caller param")
                elif param_source.type == operand.OpType.TYPE:  # <init> -> param
                    if param_source.is_external() or param_source.is_interface():
                        raise WontImplementError(param_source)
                    callee_param.sources.add(param_source)
                elif param_source.type == operand.OpType.METH:  # return value -> param
                    assert param_source.points_to
                    method_name = param_source.points_to.split(";->")[-1].split("(")[0]
                    if any(keyword in method_name.casefold() for keyword in shared.SIZE_KEYWORDS):
                        callee_param.attribute |= Attribute.SIZE
                    if (
                        any(keyword in method_name.casefold() for keyword in shared.PATH_KEYWORDS)
                        and callee_param.descriptor == "Ljava/lang/String;"
                    ):
                        callee_param.attribute |= Attribute.PATH
                    if method_name in shared.FD_METHODS and callee_param.descriptor == "I":
                        callee_param.attribute |= Attribute.FD
                    if param_source.is_external():
                        util.log(LogLevel.DEBUG, f"ignore external source {param_source}")
                    elif param_source.is_interface():
                        util.log(LogLevel.DEBUG, f"ignore interface {param_source}")
                    else:
                        callee_param.sources.add(param_source)
                elif param_source.type == operand.OpType.ARRAY_LEN:  # array-length -> param
                    if param_source.points_to != "Ljava/lang/Object;":
                        callee_param.sources.add(param_source)
                elif param_source.type in (
                    operand.OpType.LITERAL,  # literal -> param
                    operand.OpType.STRING,  # string -> param
                    operand.OpType.NEW_STRING,  # new string -> param
                    operand.OpType.NEW_ARRAY,  # new array -> param
                    operand.OpType.NEW_BUFFER,  # new buffer -> param
                    operand.OpType.STRING_LEN,  # string length -> param
                ):
                    callee_param.sources.add(param_source)
                else:
                    raise NotImplementedError(param_source.type)
                callee_param.traced = True
            assert call_inst.operands[next_idx].type == operand.OpType.METH
            if all(Attribute.TRACE not in caller_arg.attribute for caller_arg in caller._params):
                continue
            if self == caller:
                for callee_param in self._params:
                    callee_param.sources = {
                        src for src in callee_param.sources if src.type != operand.OpType.ARGUMENT
                    }
                continue

            # trace params for caller recursively
            caller.trace_params()
            util.log(LogLevel.DEBUG, f"traced params for {self.analysis.full_name}:")
            for callee_param in self._params:
                if Attribute.TRACE not in callee_param.attribute:
                    continue
                for callee_arg_source in callee_param.sources:
                    if callee_arg_source.type == operand.OpType.ARGUMENT:
                        assert type(callee_arg_source.value) == int
                        caller_arg = caller._params[callee_arg_source.value]
                        callee_param.attribute |= caller_arg.attribute
                        callee_param.sources.remove(callee_arg_source)
                        if caller_arg.sources:
                            callee_param.sources |= caller_arg.sources
                        elif jenum.is_enum(caller_arg.descriptor):
                            for value in jenum.get_enum_vals(caller_arg.descriptor):
                                callee_param.sources.add(
                                    operand.Operand((operand.OpType.LITERAL, value))
                                )
                        else:
                            callee_param.sources.add(operand.Operand((operand.OpType.UNKNOWN, -1)))
                        break
                util.log(LogLevel.DEBUG, f"- {callee_param}")

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        return self.analysis.full_name

    def __eq__(self, method: object) -> bool:
        if type(method) == Method:
            return self.analysis.full_name == method.analysis.full_name
        return False

    def __hash__(self) -> int:
        return (self.analysis.full_name).__hash__()

    @property
    def analysis(self):
        return self._analysis

    @property
    def insts(self):
        return self._insts

    @property
    def params(self):
        return self._params


# {classname: {name&sig: method1, ...}, ...}
_methods: defaultdict[str, dict[str, Method]] = defaultdict(dict)


def get_method(method: MethodAnalysis, attributes: list[Attribute] | None = None) -> Method:
    """
    get the method. create it if it doesn't exist.

    Note: the method created has no attribute!
    """
    classname = method.get_class_name()
    name_sig = method.name + method.get_descriptor()
    if name_sig in _methods[classname]:
        return _methods[classname][name_sig]
    name_sig = method.name + method.get_descriptor()
    m = Method(method, attributes)
    _methods[classname][name_sig] = m
    return m
