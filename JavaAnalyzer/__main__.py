import argparse
import os
import time
import androguard
import androguard.misc
import androguard.util
import networkx as nx
import matplotlib.pyplot as plt

from .. import config
from . import util
from .shared_def import *
from . import shared
from . import api
from . import method
from . import dependency
from . import harness
from . import field


def _parse_semantic_hint(value: str) -> str:
    if value not in harness.SEMANTIC_HINTS:
        choices = ", ".join(harness.SEMANTIC_HINTS)
        raise argparse.ArgumentTypeError(
            f"unknown semantic hint '{value}'; choose from: {choices}"
        )
    return value


def _parse_semantics(value: str) -> frozenset[str]:
    terms = [term.strip() for term in value.split(",")]
    if not terms or any(not term for term in terms):
        raise argparse.ArgumentTypeError("semantic specification contains an empty item")
    if terms == ["all"]:
        return harness.ALL_SEMANTIC_HINTS
    if terms == ["none"]:
        return frozenset()

    if terms[0] == "all":
        enabled = set(harness.ALL_SEMANTIC_HINTS)
        seen: set[str] = set()
        for term in terms[1:]:
            if not term.startswith("-") or len(term) == 1:
                raise argparse.ArgumentTypeError(
                    "items after 'all' must be exclusions such as '-path'"
                )
            hint = _parse_semantic_hint(term[1:])
            if hint in seen:
                raise argparse.ArgumentTypeError(f"duplicate semantic hint '-{hint}'")
            seen.add(hint)
            enabled.remove(hint)
        return frozenset(enabled)

    if any(term in {"all", "none"} or term.startswith("-") for term in terms):
        raise argparse.ArgumentTypeError(
            "use 'all,-path' for exclusions, or list the exact enabled hints"
        )

    enabled: set[str] = set()
    for term in terms:
        hint = _parse_semantic_hint(term)
        if hint in enabled:
            raise argparse.ArgumentTypeError(f"duplicate semantic hint '{hint}'")
        enabled.add(hint)
    return frozenset(enabled)


def _semantic_names(semantics: frozenset[str]) -> str:
    names = [hint for hint in harness.SEMANTIC_HINTS if hint in semantics]
    return ",".join(names) if names else "none"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("apkname", help="target apk name, e.g. SamsungCamera")
    parser.add_argument(
        "-c",
        "--classname",
        help='target classname, e.g. "Lcom/samsung/android/panorama/InterfaceNative;". None for all classes of target apk.',
    )
    parser.add_argument(
        "--semantics",
        type=_parse_semantics,
        default=harness.ALL_SEMANTIC_HINTS,
        metavar="SPEC",
        help=(
            "enabled semantic hints: all (default), none, an exact list such as "
            "path,size,array-len, or exclusions such as all,-path"
        ),
    )
    args = parser.parse_args()
    enabled = _semantic_names(args.semantics)
    disabled = _semantic_names(harness.ALL_SEMANTIC_HINTS - args.semantics)
    util.log(
        LogLevel.INFO,
        f"semantic hints: enabled=[{enabled}], disabled=[{disabled}]",
    )
    apk_path = os.path.join(config.APK_PATH, args.apkname)
    if not os.path.exists(apk_path):
        apk_path = apk_path + ".apk" if os.path.exists(apk_path + ".apk") else apk_path + ".jar"
    assert os.path.isfile(apk_path)

    util.log(LogLevel.INFO, f"start to analyze {apk_path}")
    androguard.util.set_log("CRITICAL")
    start_time = time.time()
    apk, dexs, shared.analysis = androguard.misc.AnalyzeAPK(apk_path)
    androguard_time = time.time()
    shared.call_graph = shared.analysis.get_call_graph()
    util.log(LogLevel.INFO, f"androguard initial analysis finished")

    api.parse_api_json(args.apkname)
    api.add_rwa_info()
    for cls in shared.analysis.get_internal_classes():
        # skip standard classes
        if any(cls.name[1:].startswith(pkgname) for pkgname in shared.PACKAGE_PREFIX_WHITELIST):
            continue
        if args.classname and cls.name != args.classname:
            continue
        native_lib = api.get_class_lib(cls)
        if not native_lib:
            util.log(LogLevel.DEBUG, f"native library of {cls.name} not found")
            continue
        util.log(LogLevel.INFO, f"class: {cls.name}, native library: {native_lib}")

        dependency_graphs: dict[str, nx.DiGraph[method.Method | field.Field]] = {}
        for target_method in api.get_valuable_apis(cls, native_lib):
            target_method = method.get_method(target_method)
            dependency_graph: nx.DiGraph[method.Method | field.Field] = nx.DiGraph()
            dependency.add_node(dependency_graph, target_method)
            util.log(LogLevel.INFO, f"vanilla dependency graph: {dependency_graph}")
            dependency.post_process(dependency_graph, target_method)
            util.log(LogLevel.INFO, f"processed dependency graph: {dependency_graph}")
            method_namesig = target_method.analysis.name + target_method.analysis.descriptor
            dependency_graphs[method_namesig] = dependency_graph

        harness.get_instrument_libraries(native_lib)
        for method_namesig, dependency_graph in dependency_graphs.items():
            if any(
                DG != dependency_graph and dependency.contains(DG, dependency_graph)
                for DG in dependency_graphs.values()
            ):
                continue
            if any(node for node in dependency_graph if dependency_graph.nodes[node]["virtual"]):
                util.log(LogLevel.INFO, "there're more than 1 sequences")
            try:
                all_api_sequences = dependency.generate_all_api_sequences(dependency_graph)
                for api_sequence in all_api_sequences:
                    util.log(LogLevel.INFO, f"api sequence:")
                    for node in api_sequence:
                        util.log(LogLevel.INFO, f"- {node}")
                    h = harness.Harness(native_lib, api_sequence, args.semantics)
                    h.output_harness(args.apkname, cls.name, method_namesig)
            except NotImplementedError as wie:
                util.log(LogLevel.ERROR, f"{wie}")
            if config.SHOW_GRAPH:
                nx.draw(dependency_graph)
                plt.show()

    end_time = time.time()
    util.log(
        LogLevel.INFO,
        f"androguard analysis time: {round(androguard_time-start_time, 2)}, custom analysis time: {round(end_time-androguard_time, 2)}",
    )


if __name__ == "__main__":
    main()
