"""
Find native apis and analyze their risk dimensions, field r/w info, jni calls, and param attributes.
Record analysis results in API_PATH/<apkname>/<libname>.json
"""

from __future__ import annotations

import idc
import ida_loader
import idautils
import json
import ida_pro
import time
import sys
from pathlib import Path
from contextlib import redirect_stdout

import shared
import function
import api
import jni_onload
from shared_def import *


def _find_native_apis() -> list[api.API]:
    """
    find native apis through static registration and dynamic registration

    :return native_apis:
    """
    native_apis: dict[int, api.API] = {}  # {addr: API, ...}
    for func_addr in idautils.Functions():
        func_name = idc.get_func_name(func_addr)
        if func_name.startswith("Java_"):
            if func_addr not in native_apis:
                native_apis[func_addr] = api.API(func_addr, func_name)
        elif func_name == "JNI_OnLoad":
            func = jni_onload.JNIOnLoadFamilyFunction(
                func_addr, shared.X0, [None, None, None, None, None, None, None, None]
            )

            for native_api in func.native_apis:
                native_apis[native_api.address] = native_api
    return list(native_apis.values())


def _analyze_native_apis(result_folder: Path, libname: str) -> None:
    """
    find and record analysis results to `*.json`
    """
    results: list[dict] = []
    native_apis = _find_native_apis()
    print(f"[INFO] there're {len(native_apis)} native apis")
    for api_info in native_apis:
        print(f"[INFO] analyzing native api {api_info.binary_name}@{hex(api_info.address)}")
        if not api_info.java_name:
            _, api_info.java_name, api_info.signature = api.extract_names(api_info.binary_name)

        shared.api_related_funcs.clear()
        native_api = function.APIFamilyFunction(api_info.address, shared.X0)

        api_info.inst_count = native_api.inst_count
        api_info.cyc_complexity = native_api.cyc_complexity
        api_info.loop_count = native_api.loop_count
        api_info.call_depth = native_api.call_depth
        api_info.risksite_count = native_api.risksite_count

        api_info.jni_calls = [shared.JNIFUNCS[offset] for offset in native_api.jni_calls]
        api_info.write = list(native_api.set_field_info)
        api_info.read = list(native_api.get_field_info)
        api_info.attr = [
            attr.value for attr in native_api.attr[2:]
        ]  # skip `JNIEnv *env` and `thiz`
        api_info = vars(api_info)
        api_info["address"] = hex(api_info["address"])
        results.append(api_info)

    result_file = result_folder / (libname + ".json")
    with result_file.open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)


def main():
    sys.setrecursionlimit(10000)
    if ida_loader.get_file_type_name() != "ELF64 for ARM64 (Shared object)":
        raise NotImplementedError("Unsupported architecture!")
    start_time = time.time()
    idc.auto_wait()  # get complete function list
    ida_time = time.time()

    path = Path(idc.get_input_file_path().removesuffix(".i64"))
    libname = path.name
    apkpath = path.parent.parent / "api" / idc.ARGV[1]
    assert apkpath.is_dir()
    logpath = apkpath / (libname + ".log")
    with logpath.open("w", encoding="utf-8") as log_file:
        with redirect_stdout(log_file):
            _analyze_native_apis(apkpath, libname)
            end_time = time.time()
            print(
                f"ida analysis time: {round(ida_time-start_time, 2)}, custom analysis time: {round(end_time-ida_time, 2)}"
            )
    ida_pro.qexit(0)


if __name__ == "__main__":
    main()
