__desc__ = """guess init and deinit methods"""

import re
import networkx as nx
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from . import method
from . import shared
from .shared_def import *

_method_names: list[str] = []


def _split_funcname(name: str) -> str:
    parts = re.split(r"_|(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", name)
    words = [part.lower() for part in parts if part]
    return " ".join(words)


def pre_process(DG: nx.DiGraph) -> None:
    global _method_names, _cosine_sim
    for node in DG:
        if type(node) != method.Method:
            continue
        cls = shared.analysis.get_class_analysis(node.analysis.get_class_name())
        for method_analysis in cls.get_methods():
            _method_names.append(_split_funcname(method_analysis.name))
    vectorizer = TfidfVectorizer()
    _method_names = list(set(_method_names))
    tfidf_matrix = vectorizer.fit_transform(_method_names)
    _cosine_sim = cosine_similarity(tfidf_matrix, tfidf_matrix)


def get_name_similarity(name1: str, name2: str) -> float:
    name1 = _split_funcname(name1)
    name2 = _split_funcname(name2)
    for i, row in enumerate(_cosine_sim):
        if _method_names[i] != name1:
            continue
        for j, val in enumerate(row):
            if _method_names[j] == name2:
                return val
    raise InvalidStateError("can't get name similarity")
