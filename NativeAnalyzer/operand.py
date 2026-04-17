from enum import Enum, auto


class OpType(Enum):
    """
    see https://cpp.docs.hex-rays.com/group__o__.html
    """

    o_void = 0
    o_reg = auto()
    o_mem = auto()
    o_phrase = auto()  # [reg]
    o_displ = auto()  # [reg+N]
    o_imm = auto()
    o_far = auto()
    o_near = auto()
    o_idpspec0 = auto()
    o_idpspec1 = auto()
    o_idpspec2 = auto()
    o_idpspec3 = auto()
    o_idpspec4 = auto()
    o_idpspec5 = auto()
    undocumented = auto()

    @classmethod
    def _missing_(cls, value):
        print(f"[DEBUG] unknown OpType {value}")
        return OpType.undocumented


class Operand:
    """
    see https://cpp.docs.hex-rays.com/classop__t.html

    we must have this class to save member values of `op_t *`
    """

    _type: OpType
    _reg: int  # reg number. e.g. 129 for X0, 0xA1 for SP
    _value: int
    _addr: int

    def __init__(self, operand):
        assert operand.type
        self._type = OpType(operand.type)
        self._reg = operand.reg
        self._value = operand.value
        self._addr = operand.addr

    @property
    def type(self):
        return self._type

    @property
    def reg(self):
        return self._reg

    @property
    def value(self):
        return self._value

    @property
    def addr(self):
        return self._addr
