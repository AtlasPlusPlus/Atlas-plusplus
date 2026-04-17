"""
launch IDA Python script `ida_main.py` for libraries.
"""

import argparse
import os
import multiprocessing
import subprocess
import zipfile
import shlex
from .. import config


SCRIPT = __file__.replace("__main__.py", "ida_main.py")


def run(cmd: list[str]) -> None:
    """
    the worker function in `multiprocessing.Pool()`
    """
    proc = subprocess.run(cmd, stdout=subprocess.DEVNULL)
    if proc.returncode:
        print(
            f'{cmd[-1].rsplit("/")[-1]} failed! run command manually to check the reason. e.g. /path/to/ida -S"/path/to/ida_main.py apkname" /path/to/target_lib'
        )


def main():
    multiprocessing.set_start_method("fork", force=True)
    parser = argparse.ArgumentParser()
    parser.add_argument("apkname", help="target apk name, e.g. SamsungCamera")
    parser.add_argument(
        "-l",
        "--libname",
        help="target library name, e.g. libPanoramaInterface_arcsoft.so. None for all libraries of target apk.",
    )
    args = parser.parse_args()

    # extract libraries in the apk to LIB64_PATH
    apk_path = os.path.join(config.APK_PATH, args.apkname + ".apk")
    if not os.path.exists(apk_path):
        apk_path = os.path.join(config.APK_PATH, args.apkname + ".jar")
        assert os.path.exists(apk_path), f"{apk_path} not exist!"

    subprocess.run(
        ["unzip", "-j", "-o", apk_path, "lib/arm64-v8a/*.so", "-d", config.LIB64_PATH],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    libnames: list[str] = []
    with zipfile.ZipFile(apk_path, "r") as apk_file:
        for file in apk_file.namelist():
            if file.startswith("lib/arm64-v8a") and file.endswith(".so"):
                libnames.append(file.removeprefix("lib/arm64-v8a/"))

    result_path = os.path.join(config.API_PATH, args.apkname)
    os.makedirs(result_path, exist_ok=True)

    if args.libname:
        libnames = [args.libname]
    cmds: list[list[str]] = []
    for libname in libnames:
        libpath = os.path.join(config.LIB64_PATH, libname)
        if os.path.exists(libpath + ".i64"):
            libpath += ".i64"
        cmd = shlex.split(f'{config.IDA_PATH} -A -S"{SCRIPT} {args.apkname}" {libpath}')
        cmds.append(cmd)

    print("analyzing...")
    with multiprocessing.Pool() as pool:
        pool.map(run, cmds)

    print("cleaning...")
    for path, dirs, files in os.walk(config.LIB64_PATH):
        for filename in files:
            if (
                filename.endswith(".asm")
                or filename.endswith(".til")
                or filename.endswith(".nam")
                or filename.endswith(".id0")
                or filename.endswith(".id1")
                or filename.endswith(".id2")
            ):
                os.remove(os.path.join(path, filename))
    print("finished!")


if __name__ == "__main__":
    main()
