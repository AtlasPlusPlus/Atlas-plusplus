import os
import sys

# customize these two PATHs if needed
IDA_PATH = (
    r"C:\Program Files\IDA Professional 9.1\ida.exe"
    if sys.platform == "win32"
    else os.path.expanduser("~/ida-pro-9.1/idat")
)
WORK_PATH = os.path.expanduser("~/Atlas++Exp")

APK_PATH = os.path.join(WORK_PATH, "apk")
LIB64_PATH = os.path.join(WORK_PATH, "lib64")
API_PATH = os.path.join(WORK_PATH, "api")
HARNESS_PATH = os.path.join(WORK_PATH, "harness")
for dir in (APK_PATH, LIB64_PATH, API_PATH, HARNESS_PATH):
    os.makedirs(dir, exist_ok=True)

API_VALUE_THRESHOLD = 0
MAX_BUFFER_LENGTH = 512  # default single buffer max length from fuzz input

# options
# it's recommended to ignore the RETURN_VALUE source of array, ByteBuffer, String.
IGNORE_RETURN_VAL_OF_FUZZABLE_TYPE = True
HARNESS_DEBUG = False  # set it to True when checking harness correctness
SHOW_GRAPH = True  # show graph (and block!) after every API sequence generated
