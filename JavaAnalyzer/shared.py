__desc__ = "define and store global vars that other files can read/write"

from androguard.core.analysis.analysis import Analysis, ExternalMethod
from androguard.core.dex import EncodedMethod
import networkx as nx
from .shared_def import *

log_level = LogLevel.DEBUG
analysis: Analysis
call_graph: nx.DiGraph  # node is EncodedMethod or ExternalMethod

PACKAGE_PREFIX_WHITELIST = [
    "android",
    "androidx",
    "com/android",
    "com/google",
    "com/sec/android",
    "com/snap",
    "java",
    "kotlin",
    "org",
]  # skip some "standard" packages (prefix) for efficiency

INIT_KEYWORDS = ["init", "create"]
DEINIT_KEYWORDS = ["deinit", "release", "destroy"]
SIZE_KEYWORDS = ["size", "length", "width", "height"]
PATH_KEYWORDS = ["file", "path"]
FD_METHODS = {"getFd"}

UNSUPPORTED_TYPES = {
    "Landroid/content/Context;",
    "Landroid/graphics/Bitmap;",
}

# common dependency of a native library
IGNORE_NEEDED_LIBRARIES = {
    "libm.so",
    "liblog.so",
    "libdl.so",
    "libc.so",
    "libc++.so",
    "libstdc++.so",
    "libz.so",
    "libjnigraphics.so",
    "libandroid.so",
    "libnativehelper.so",
    "libjsoncpp.so",
    "libutils.so",
    "libui.so",
    "libnativewindow.so",
    "libjs.so",
    "libGLESv2.so",
    "libEGL.so",
    "libandroid_runtime.so",
    "libgui.so",
    "libbinder.so",
    "libcutils.so",
}
