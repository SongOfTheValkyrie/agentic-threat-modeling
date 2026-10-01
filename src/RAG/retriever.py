import re
from dataclasses import dataclass
from typing import Protocol

from src.RAG.knowledge import KnowledgeSnippet

# Field weights: `applies_to` holds the precise retrieval hooks (component
# types / situations), so a match there is worth most; free-form text is worth
# least. These are deliberately simple and can be tuned later.
WEIGHT_APPLIES_TO = 3.0
WEIGHT_KEYWORDS = 2.0
WEIGHT_TITLE = 1.0
WEIGHT_TEXT = 0.5

_TOKEN_RE = re.compile(r"[a-z0-9_]+")


def _tokenize(text: str) -> set[str]:
    return set(_TOKEN_RE.findall(text.lower()))


@dataclass
class ScoredSnippet:
    snippet: KnowledgeSnippet
    score: float


class Retriever(Protocol):
    """Selects the most relevant knowledge snippets for a text query."""

    def retrieve(self, query: str, k: int) -> list[KnowledgeSnippet]:
        ...


class KeywordRetriever:
    """Simple, deterministic retriever based on weighted token overlap.

    No embeddings or external services: it scores each snippet by how many
    query tokens overlap its fields, weighting the structured ``applies_to`` and
    ``keywords`` fields above free text. Kept behind the ``Retriever`` protocol
    so it can be swapped for an embedding- or vector-DB-backed retriever as the
    corpus grows, without touching the RAG pipeline.
    """

    def __init__(self, snippets: list[KnowledgeSnippet]):
        self._snippets = snippets

    def _score(self, query_tokens: set[str], snippet: KnowledgeSnippet) -> float:
        applies_to = _tokenize(" ".join(snippet.applies_to))
        keywords = _tokenize(" ".join(snippet.keywords))
        title = _tokenize(snippet.title)
        text = _tokenize(snippet.text)

        return (
            WEIGHT_APPLIES_TO * len(query_tokens & applies_to)
            + WEIGHT_KEYWORDS * len(query_tokens & keywords)
            + WEIGHT_TITLE * len(query_tokens & title)
            + WEIGHT_TEXT * len(query_tokens & text)
        )

    def score_all(self, query: str) -> list[ScoredSnippet]:
        """All snippets with a positive score, highest first (ties by id)."""
        query_tokens = _tokenize(query)
        scored = [
            ScoredSnippet(snippet=s, score=self._score(query_tokens, s))
            for s in self._snippets
        ]
        scored = [s for s in scored if s.score > 0]
        scored.sort(key=lambda s: (-s.score, s.snippet.id))
        return scored

    def retrieve(self, query: str, k: int) -> list[KnowledgeSnippet]:
        return [s.snippet for s in self.score_all(query)[:k]]
