import idc
import idaapi
from ida_gdl import BasicBlock

import operand


class Instruction:
    _ea: int
    _bb: BasicBlock
    _opcode: str  # e.g 'SUB'
    _operands: list[operand.Operand]
    _string: str  # e.g. 'SUB             SP, SP, #0x130'
    _operands_str: list[str]

    def __init__(self, ea: int, bb: BasicBlock):
        self._ea = ea
        self._bb = bb
        self._opcode = idc.print_insn_mnem(ea)
        self._string = idc.GetDisasm(ea)

        inst = idaapi.insn_t()
        idaapi.decode_insn(inst, ea)
        self._operands = []
        for i in range(8):
            op = inst.ops[i]
            if not op.type:
                break
            self._operands.append(operand.Operand(op))

        self._operands_str = []
        for i in range(8):
            operand_str = idc.print_operand(ea, i)
            if not operand_str:
                break
            self._operands_str.append(operand_str)

        assert len(self._operands) == len(self._operands_str)

    @property
    def ea(self):
        return self._ea

    @property
    def bb(self):
        return self._bb

    @property
    def opcode(self):
        return self._opcode

    @property
    def operands(self):
        return self._operands

    @property
    def string(self):
        return self._string

    @property
    def operands_str(self):
        return self._operands_str

    def is_LDR(self) -> bool:
        return any(
            self.opcode.startswith(op)
            for op in {"LDR", "LDAR", "LDAPR", "LDAXR", "LDLAR", "LDTR", "LDUR", "LDXR"}
        )

    def is_STR(self) -> bool:
        return any(
            self.opcode.startswith(op) for op in {"STR", "STLLR", "STLR", "STTR", "STUR"}
        )  # no "STLXR", "STXR"

    def is_LDP(self) -> bool:
        return any(self.opcode.startswith(op) for op in {"LDP", "LDNP", "LDXP"})

    def is_STP(self) -> bool:
        return any(self.opcode.startswith(op) for op in {"STP", "STNP"})  # no "STLXP", "STXP"

    def is_branch(self) -> bool:
        return self.opcode in {"B", "BR"} or self.opcode.startswith("BL")

    def is_algo_MOV(self) -> bool:
        return (
            any(self.opcode.startswith(op) for op in {"ADD", "SUB"})
            and len(self.operands) == 3
            and self.operands[1].type == operand.OpType.o_reg
            and self.operands[2].type == operand.OpType.o_imm
        )
