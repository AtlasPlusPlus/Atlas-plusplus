from androguard.core import dex
from androguard.core.dex import dex_types
from dataclasses import dataclass
from . import operand
from . import jenum


@dataclass
class Instruction:
    analysis: dex.Instruction
    operands: list[operand.Operand]

    def __init__(self, analysis: dex.Instruction):
        self.analysis = analysis
        self.operands = []
        for op_tuple in analysis.get_operands():
            self.operands.append(operand.Operand(op_tuple))

    def backward_propogate(self, sink: operand.Operand) -> operand.Operand:
        """
        get source from dest

        :param sink: dest
        :return source:
        """
        inst_type = self.analysis.get_op_value()
        if sink.type == operand.OpType.RETURN_VALUE:
            if not self.analysis.get_name().startswith("invoke"):
                return sink
            assert self.operands[-1].points_to
            cls_name, _, method_namesig = self.operands[-1].points_to.partition("->")
            if cls_name == "Ljava/lang/String;" and method_namesig == "length()I":
                return operand.Operand((operand.OpType.STRING_LEN, -1))
            elif inst_type == 0x6E and jenum.is_enum(cls_name) and method_namesig == "ordinal()I":
                # invoke-virtual
                # continue to trace the enum class
                return self.operands[0]
            return self.operands[-1]
        elif sink.type == operand.OpType.OFFSET:
            assert inst_type in dex.DALVIK_OPCODES_PAYLOAD
            return self.operands[0]

        # do nothing if current inst has nothing to do with `sink`
        if not self.operands:
            return sink
        if 0x59 <= inst_type <= 0x5F:  # iput*
            if self.operands[2].value != sink.value:  # trace field instead of object
                return sink
        elif 0x4B <= inst_type <= 0x51 or 0x67 <= inst_type <= 0x6D:
            # for aput: trace array instead of index
            # for sput: trace field
            if self.operands[1].value != sink.value:
                return sink
        elif inst_type == 0x23:
            if sink.value not in {self.operands[0].value, self.operands[1].value}:
                return sink
        else:
            if self.operands[0].value != sink.value:
                return sink

        if 0x01 <= inst_type <= 0x09:  # move, move-object
            return self.operands[-1]
        elif 0x0A <= inst_type <= 0x0D:  # move-result
            return operand.Operand((operand.OpType.RETURN_VALUE, -1))
        elif 0x0E <= inst_type <= 0x11:  # return*
            return sink
        elif 0x12 <= inst_type <= 0x1C:  # const
            return self.operands[-1]
        elif 0x1D <= inst_type <= 0x20:
            return sink
        elif 0x21 <= inst_type <= 0x26:
            if inst_type == 0x21:  # array-length
                return operand.Operand((operand.OpType.ARRAY_LEN, -1))
            elif inst_type == 0x22:  # new-instance
                new_obj = self.operands[-1]
                assert new_obj.points_to
                if new_obj.points_to == "Ljava/lang/String;":
                    return operand.Operand((operand.OpType.NEW_STRING, -1))
                elif new_obj.points_to == "Ljava/nio/ByteBuffer;":
                    return operand.Operand((operand.OpType.NEW_BUFFER, -1))
                else:
                    return self.operands[-1]
            elif inst_type == 0x23:  # new-array
                desc = self.operands[-1].points_to
                assert desc
                if sink.value == self.operands[0].value:
                    return operand.Operand((operand.OpType.NEW_ARRAY.value, -1, desc))
                elif sink.value == self.operands[1].value:
                    return operand.Operand((operand.OpType.ARRAY_LEN.value, -1, desc))
            elif inst_type == 0x26:  # fill-array-data
                return self.operands[-1]
            raise NotImplementedError(self)
        elif 0x27 <= inst_type <= 0x2C:
            return sink
        elif 0x2D <= inst_type <= 0x3D:
            return sink
        elif 0x44 <= inst_type <= 0x4A:  # aget*
            # trace array instead of index
            return self.operands[1]
        elif 0x4B <= inst_type <= 0x51:  # aput*
            return self.operands[0]
        elif 0x52 <= inst_type <= 0x58:  # iget*
            return self.operands[-1]
        elif 0x59 <= inst_type <= 0x5F:  # iput*
            return self.operands[0]
        elif 0x60 <= inst_type <= 0x66:  # sget*
            return self.operands[-1]
        elif 0x67 <= inst_type <= 0x6D:  # sput*
            return self.operands[0]
        elif 0x6E <= inst_type <= 0x78:  # invoke*
            return sink
        elif 0x79 <= inst_type <= 0x7A:
            return sink
        elif 0x7B <= inst_type <= 0x8F:  # unary op
            return self.operands[-1]
        elif 0x90 <= inst_type <= 0xAF:  # arithmetic op, e.g. a = b + c
            # only trace the first source reg
            return self.operands[1]
        elif 0xB0 <= inst_type <= 0xCF:  # arithmetic op, e.g. a += b
            # not trace b
            return sink
        elif 0xD0 <= inst_type <= 0xE2:  # arithmetic op, e.g. a = b + 1
            return self.operands[1]
        elif inst_type == 0x0300:
            raise NotImplementedError(self)
        elif 0xF3FF <= inst_type <= 0xFEFF:
            raise NotImplementedError(self)
        else:
            raise NotImplementedError(self)

    def __str__(self) -> str:
        return self.analysis.get_name() + " " + self.analysis.get_output()

    def __repr__(self) -> str:
        return self.__str__()
