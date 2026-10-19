"""Tests for the keyword retriever.

The retriever's ranking determines what knowledge the RAG pipeline sees, so
these tests pin down the field weighting (applies_to > keywords > title > text)
and the deterministic tie-breaking by id.
"""

from src.RAG.knowledge import KnowledgeSnippet
from src.RAG.retriever import KeywordRetriever


def _snippet(id_, *, applies_to=None, keywords=None, title="", text=""):
    return KnowledgeSnippet(
        id=id_,
        title=title,
        text=text,
        source="TEST",
        applies_to=applies_to or [],
        keywords=keywords or [],
    )


def test_retrieve_returns_only_matching_snippets():
    retriever = KeywordRetriever(
        [
            _snippet("match", keywords=["encryption"]),
            _snippet("nomatch", keywords=["logging"]),
        ]
    )
    results = retriever.retrieve("encryption", k=5)
    assert [s.id for s in results] == ["match"]


def test_applies_to_outweighs_text():
    # One snippet matches on the high-weight applies_to field, the other only in
    # free text. The applies_to match must rank first.
    retriever = KeywordRetriever(
        [
            _snippet("text_only", text="public_access is risky"),
            _snippet("applies", applies_to=["public_access"]),
        ]
    )
    results = retriever.retrieve("public_access", k=2)
    assert results[0].id == "applies"


def test_k_limits_results():
    retriever = KeywordRetriever(
        [_snippet(f"s{i}", keywords=["x"]) for i in range(5)]
    )
    assert len(retriever.retrieve("x", k=3)) == 3


def test_ties_broken_by_id_deterministically():
    # Identical scores -> stable order by snippet id.
    retriever = KeywordRetriever(
        [
            _snippet("b", keywords=["x"]),
            _snippet("a", keywords=["x"]),
        ]
    )
    results = retriever.retrieve("x", k=2)
    assert [s.id for s in results] == ["a", "b"]


def test_no_match_returns_empty():
    retriever = KeywordRetriever([_snippet("s", keywords=["x"])])
    assert retriever.retrieve("completely_unrelated", k=5) == []
