__desc__ = "create and use the dependency graph"

import networkx as nx
from androguard.core.analysis.analysis import ClassAnalysis, MethodAnalysis, FieldAnalysis
from collections import defaultdict
from typing import Iterator
from dataclasses import dataclass
import itertools
from . import method
from . import operand
from . import util
from . import shared
from . import jenum
from . import parameter
from . import field
from . import name
from . import instruction
from .shared_def import *
from .. import config


def add_node(DG: nx.DiGraph, node: method.Method) -> None:
    """
    analyze dependency of `node` and generate its subgraph, then add `node` to `DG`

    :return: true if the node is in DG
    """

    def add_producers(
        DG: nx.DiGraph,
        producers: list[method.Method],
        mid: field.Field | parameter.Parameter,
        consumer: method.Method | field.Field,
    ) -> None:
        """
        add producers/writers as dependency of reader
        """
        if not producers:
            return
        target_node = consumer
        if len(producers) > 1:
            # create `one_of` virtual node
            DG.add_node(mid, virtual=True)
            if mid != consumer:
                DG.add_edge(mid, consumer)
            target_node = mid
        for producer in producers:
            add_node(DG, producer)
            DG.add_edge(producer, target_node)

    if node in DG:
        return
    util.log(LogLevel.DEBUG, f"add node: {node}")
    DG.add_node(node, virtual=False)
    for param in node.params:
        param.attribute |= Attribute.TRACE
    node.trace_params()

    # add dependency according to fields read
    write_fields = [(wt_cls, wt_field) for wt_cls, wt_field, _ in node.analysis.get_xref_write()]
    for rd_cls, rd_field, _ in node.analysis.get_xref_read():
        # only consider REAL rd_field
        if (rd_cls, rd_field) in write_fields:
            continue
        fld = field.get_field(rd_field)
        if fld.writers:
            add_producers(DG, fld.writers, fld, node)
            continue
        DG.add_node(fld, virtual=False)
        DG.add_edge(fld, node)
        if any(src.is_const() for src in fld.sources):
            continue
        add_producers(DG, fld.producers, fld, fld)

    # add dependency according to param source
    for param in node.params:
        if not param.sources:
            continue
        param.prune()
        if any(src.is_const() for src in param.sources):
            continue

        # turn FIELD source to const/METH
        sources: set[operand.Operand] = set()
        for param_source in param.sources:
            if param_source.type == operand.OpType.FIELD:
                class_name, field_name, _ = param_source.get_field_info()
                # skip writer of Enum
                if jenum.is_enum(class_name):
                    continue
                field_analysis = util.get_field_analysis_by_name(class_name, field_name)
                fld = field.get_field(field_analysis)
                param.attribute |= fld.attribute
                if fld.writers:
                    # field will be left alone if it's written indirectly
                    sources.add(param_source)
                    continue
                if sources:
                    continue
                consts = set(source for source in fld.sources if source.is_const())
                if consts:
                    sources |= consts
                    continue
                for producer in fld.producers:
                    points_to = f"{producer.analysis.get_class_name()}->{producer.analysis.name}{producer.analysis.get_descriptor()}"
                    sources.add(operand.Operand((operand.OpType.METH.value, 0, points_to)))
            else:
                sources.add(param_source)
        param.sources = sources

        # add method dependency if any
        if not param.sources:
            continue
        param.prune()
        if any(src.is_const() for src in param.sources):
            continue
        if any(src.type == operand.OpType.FIELD for src in param.sources):
            writers: set[method.Method] = set()
            for src in param.sources:
                if src.type == operand.OpType.FIELD:
                    class_name, field_name, _ = src.get_field_info()
                    field_analysis = util.get_field_analysis_by_name(class_name, field_name)
                    fld = field.get_field(field_analysis)
                    writers |= set(fld.writers)
            add_producers(DG, list(writers), param, node)
            continue
        if len(param.sources) > 1 and any(src.type != operand.OpType.METH for src in param.sources):
            util.log(
                LogLevel.DEBUG, f"ignore {len(param.sources)} sources of different types: {param}"
            )
            param.sources.clear()
            continue
        producers: set[method.Method] = set()
        for src in param.sources:
            if src.type == operand.OpType.METH:
                method_analysis = src.get_method_analysis()
                if (not method_analysis) or method_analysis.is_external():
                    continue
                producer = method.get_method(method_analysis)
                if producer != node:
                    producers.add(producer)
        if config.IGNORE_RETURN_VAL_OF_FUZZABLE_TYPE and (
            param.descriptor.startswith("[")
            or param.descriptor in ("Ljava/lang/String;", "Ljava/nio/ByteBuffer;")
        ):
            util.log(LogLevel.DEBUG, f"ignore return value source of argument {param.descriptor}")
            return
        add_producers(DG, list(producers), param, node)


def _is_judge(node: MethodAnalysis) -> bool:
    """
    guess whether the node is a judge method
    """
    return "is" in node.name.casefold() and node.get_descriptor().split(")")[-1] == "Z"


def _is_deinit(node: MethodAnalysis) -> bool:
    """
    guess whether the node is a native deinit
    """
    return (not _is_judge(node)) and any(
        keyword in node.name.casefold() for keyword in shared.DEINIT_KEYWORDS
    )


def _is_init(node: MethodAnalysis) -> bool:
    """
    guess whether the node is a native init
    """
    return (
        (not _is_deinit(node))
        and (not _is_judge(node))
        and any(keyword in node.name.casefold() for keyword in shared.INIT_KEYWORDS)
    )


def _find_most_similar_func(src_name: str, methods: list[MethodAnalysis]) -> method.Method | None:
    """
    if there're more than 1 inits/deinits, find the most similar one
    """
    most_similar_func = None
    max_similarity = -1
    for method_analysis in methods:
        similarity = name.get_name_similarity(src_name, method_analysis.name)
        if similarity > max_similarity:
            max_similarity = similarity
            most_similar_func = method.get_method(method_analysis)
    return most_similar_func


def _get_init(node: method.Method) -> method.Method | None:
    """
    guess the relative native init

    :return: init node if any
    """
    assert not _is_init(node.analysis)
    cls = shared.analysis.get_class_analysis(node.analysis.get_class_name())
    inits: list[MethodAnalysis] = []
    for method_analysis in cls.get_methods():
        if "native" not in method_analysis.access:
            continue
        if _is_init(method_analysis):
            inits.append(method_analysis)
    return _find_most_similar_func(node.analysis.name, inits)


def _get_deinit(node: method.Method) -> method.Method | None:
    """
    guess the relative native deinit

    :return: deinit node if any
    """
    assert not _is_deinit(node.analysis)
    cls = shared.analysis.get_class_analysis(node.analysis.get_class_name())
    deinits: list[MethodAnalysis] = []
    for method_analysis in cls.get_methods():
        if "native" not in method_analysis.access:
            continue
        if _is_deinit(method_analysis):
            deinits.append(method_analysis)
    return _find_most_similar_func(node.analysis.name, deinits)


def _add_guessed_dependency(DG: nx.DiGraph) -> None:
    """
    add guessed native init nodes as dependency
    """
    # create native init node for every Method node
    nodes = [node for node in nx.topological_sort(DG) if type(node) == method.Method]
    for node in nodes[::-1]:
        if "native" not in node.analysis.access:
            continue
        if _is_init(node.analysis):
            continue
        init = _get_init(node)
        if not init:
            util.log(LogLevel.WARN, f"can't guess init of {node}")
            continue
        if init in nodes or any(
            nx.has_path(shared.call_graph, node.analysis.get_method(), init.analysis.get_method())
            for node in nodes
        ):
            continue
        if init not in DG:
            util.log(LogLevel.WARN, f"use guessed dependency: {init}")
        add_node(DG, init)
        if not nx.has_path(DG, node, init):
            DG.add_edge(init, node)


def _add_post_dependency(DG: nx.DiGraph) -> None:
    """
    add (guessed) native deinit nodes as post-dependency,
    because the construction process only considers pre-dependency.
    """

    def get_path_ends(
        DG: nx.DiGraph, start: method.Method | field.Field | parameter.Parameter
    ) -> Iterator[method.Method]:
        if not DG.out_degree[start]:
            assert type(start) == method.Method
            yield start
        for next_node in DG.succ[start]:
            yield from get_path_ends(DG, next_node)

    # create native deinit node for every path from native init node
    nodes = [node for node in nx.topological_sort(DG) if type(node) == method.Method]
    for node in nodes[::-1]:
        if "native" not in node.analysis.access:
            continue
        if not _is_init(node.analysis):
            continue
        deinit = _get_deinit(node)
        if not deinit:
            util.log(LogLevel.WARN, f"can't find deinit of {node}")
            continue

        add_node(DG, deinit)
        DG.remove_edges_from([(deinit, next_node) for next_node in DG.succ[deinit]])
        if deinit in DG.successors(node):
            DG.remove_edge(node, deinit)
        for path_end in list(get_path_ends(DG, node)):
            if path_end != deinit:
                DG.add_edge(path_end, deinit)


def _can_delete(vnode: field.Field | parameter.Parameter) -> bool:
    if type(vnode) == field.Field and (not vnode.writers) and vnode.writers:
        return False
    return True


def _merge_virtual_nodes(DG: nx.DiGraph) -> None:
    """
    if the subgraph of virtual nodes are same, delete reduntant virtual nodes
    """
    all_vnode_preds: set[frozenset[method.Method]] = set()
    reduntant_vnodes = []
    for vnode in DG:
        if not DG.nodes[vnode]["virtual"]:
            continue
        if not _can_delete(vnode):
            continue
        vnode_preds = frozenset(DG.predecessors(vnode))
        if vnode_preds in all_vnode_preds:
            util.log(LogLevel.DEBUG, f"remove reduntant virtual node {vnode}")
            reduntant_vnodes.append(vnode)
        else:
            all_vnode_preds.add(vnode_preds)
    DG.remove_nodes_from(reduntant_vnodes)


def _backward_dfs_until_virual_node(
    DG: nx.DiGraph, root: method.Method | field.Field | parameter.Parameter
) -> Iterator[method.Method | field.Field | parameter.Parameter]:
    """
    get subgraph nodes to generate the subgraph which doesn't contain virtual nodes in middle of any path to root.
    """
    yield root
    if not DG.nodes[root]["virtual"]:
        for prev_node in DG.pred[root]:
            yield from _backward_dfs_until_virual_node(DG, prev_node)


def _find_root(DG: nx.DiGraph) -> method.Method | field.Field:
    """
    root is the target API, whose out degree is 0.
    """
    for node in DG:
        if DG.out_degree(node) == 0:
            return node
    raise InvalidStateError(f"can't find root of graph {DG}")


def _prune_virtual_nodes(DG: nx.DiGraph) -> None:
    """
    if one pred of a vnode is on necessary path, remove all non-necessary preds of the vnode.
    """

    def is_necessary(DG: nx.DiGraph, node: method.Method) -> bool:
        root = _find_root(DG)
        return node in _backward_dfs_until_virual_node(DG, root)

    unnecessary_nodes = []
    for node in DG:
        if not DG.nodes[node]["virtual"]:
            continue
        if any(DG.nodes[prev_node]["virtual"] for prev_node in DG.predecessors(node)):
            raise NotImplementedError("virtual node has a virtual node pred!")
        if any(is_necessary(DG, prev_node) for prev_node in DG.predecessors(node)):
            unnecessary_nodes += [
                prev_node for prev_node in DG.predecessors(node) if not is_necessary(DG, prev_node)
            ]
    DG.remove_nodes_from(unnecessary_nodes)


def post_process(DG: nx.DiGraph, target_api: method.Method) -> None:
    """
    process the graph after creation
    """
    for cycle in nx.recursive_simple_cycles(DG):
        DG.remove_nodes_from(cycle)
    DG.remove_nodes_from([node for node in DG if not nx.has_path(DG, node, target_api)])

    name.pre_process(DG)
    _add_guessed_dependency(DG)
    _add_post_dependency(DG)
    _merge_virtual_nodes(DG)
    _prune_virtual_nodes(DG)


def generate_all_api_sequences(
    DG: nx.DiGraph,
) -> list[list[method.Method | field.Field]]:
    """
    generate all api sequences from dependency graph.

    1. Get top-level subgraph, which doesn't contain virtual nodes in middle of any path to root.
    Topological sort the top-subgraph.
    [node1, node2, vnode1, ..., vnode2]

    2. Unfold virtual nodes (replace a virtual node with all sequences of it,
    or add all sequences of it before the virtual node).
    Sequence is a list of nodes: S1 = [node1], S3 = [node3, node4]
    [S1, S2, [S3, S4], ..., [S5, S6]]

    3. Cartesian product to get all sequences of sequences.
    [S1, S2, S3, ..., S5], [S1, S2, S3, ..., S6], [S1, S2, S4, ..., S5], [S1, S2, S4, ..., S6]

    4. unfold sequences to nodes.
    [node1, node2, node3, node4, ..., ...], ...

    :return all_api_sequences: list[APISequence]. APISequence is list[Method | Field].
    "Field" means "no writer found, fill it with fuzz input".
    """

    all_api_sequences: list[list[method.Method | field.Field]] = []

    # consider subgraph of top nodes only, because other nodes will be considered recursively
    top_nodes = list(_backward_dfs_until_virual_node(DG, _find_root(DG)))
    top_sub_DG: nx.DiGraph[method.Method | field.Field | parameter.Parameter] = DG.subgraph(
        top_nodes
    )

    # step1: [node1, node2, vnode1, ..., vnode2]
    topological_result: list[method.Method | field.Field | parameter.Parameter] = list(
        nx.topological_sort(top_sub_DG)
    )

    # step2: [S1, S2, [S3, S4], ..., [S5, S6]]
    sequences_to_product: list[list[list[method.Method | field.Field]]] = []
    for node in topological_result:
        if not top_sub_DG.nodes[node]["virtual"]:
            assert type(node) == method.Method or type(node) == field.Field
            sequences_to_product.append([[node]])
        else:
            sub_DG_sequences: list[list[method.Method | field.Field | None]] = []
            for root in DG.predecessors(node):
                if any(not DG.nodes[succ]["virtual"] for succ in DG.successors(root)):
                    sub_DG_sequences.append([None])
                    continue
                sub_DG_nodes = [n for n in DG.nodes if nx.has_path(DG, n, root)]
                sub_DG = DG.subgraph(sub_DG_nodes)
                sub_DG_sequences += generate_all_api_sequences(sub_DG)
            sequences_to_product.append(sub_DG_sequences)
            assert type(node) == field.Field or type(node) == parameter.Parameter
            if not _can_delete(node):
                assert type(node) == field.Field
                sequences_to_product.append([[node]])

    # step3: [S1, S2, S3, ..., S5], [S1, S2, S3, ..., S6], [S1, S2, S4, ..., S5], [S1, S2, S4, ..., S6]
    for raw_sequence in itertools.product(*sequences_to_product):
        # step4, step5: [node1, node2, node3, ...], [node1, node2, node4, ...]
        sequence: list[method.Method | field.Field] = []
        for s in raw_sequence:
            for node in s:
                if node is not None:
                    sequence.append(node)
        # remove duplicate method
        all_api_sequences.append(list(dict.fromkeys(sequence)))

    return all_api_sequences


def contains(DG1: nx.DiGraph, DG2: nx.DiGraph) -> bool:
    """
    judge whether `DG1` contains `DG2`.
    """
    for node in DG2.nodes:
        if node not in DG1:
            return False
    for node in DG2.nodes:
        for succ in DG2.successors(node):
            if not nx.has_path(DG1, node, succ):
                return False
    return True
