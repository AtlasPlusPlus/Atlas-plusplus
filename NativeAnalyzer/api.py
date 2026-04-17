from dataclasses import dataclass
import re


@dataclass
class API:
    address: int
    binary_name: str
    java_name: str
    signature: str
    value: float  # -1, will be calculated by Java Analyzer
    inst_count: int
    cyc_complexity: int
    loop_count: int
    call_depth: int
    risksite_count: int
    jni_calls: list[str]
    read: list[tuple[int, str, str]]  # [(api_arg_index, class name, field name), ...]
    write: list[tuple[int, str, str]]
    attr: list[int]

    def __init__(self, address: int, binary_name: str, java_name: str = "", signature: str = ""):
        self.address = address
        self.binary_name = binary_name
        self.java_name = java_name
        self.signature = signature
        self.value = -1
        self.inst_count = 0
        self.cyc_complexity = 0
        self.loop_count = 0
        self.call_depth = 0
        self.risksite_count = 0
        self.jni_calls = []
        self.read = []
        self.write = []
        self.attr = []

    def __hash__(self) -> int:
        return self.address


def extract_names(binary_name: str) -> tuple[str, str, str]:
    """
    parse staticly-linked native API's Java name and argument signature from its binary_name.

    from https://github.com/NativeSummary/native_summary_bai/blob/main/pre_analysis/symbol_parser.py

    :return (class_name, method_name, signature_without_rtype): class_name is a.b.c.d
    """
    sig = ""
    assert binary_name[:5] == "Java_"
    binary_name = binary_name[5:]

    def match2chr(match) -> str:
        return chr(int(match.group(1), 16))

    binary_name = re.sub(r"_0([a-z0-9]{4})", match2chr, binary_name)
    binary_name = binary_name.replace("_2", ";").replace("_3", "[")
    # no undersocre, because sig cannot startwith underscore.
    # but may start with '['now
    parts: list[str] = re.split(r"__(?=[a-zA-Z\[])", binary_name)
    assert len(parts) < 3
    if len(parts) == 2:
        full_method, sig = parts
    else:
        full_method = binary_name
    # has undersocre, because method name and classname can contain underscore
    parts = re.split(r"_(?=[a-zA-Z_])", full_method)
    method_name = parts[-1].replace("_1", "_")
    cls_name = ".".join(parts[0:-1]).replace("_1", "_")
    if sig:
        sig = "/".join(re.split(r"_(?=[a-zA-Z])", sig))
        sig = "(" + sig + ")"
    return cls_name, method_name, sig
