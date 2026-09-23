import json
from pathlib import Path

from pydantic import BaseModel, Field

from src.models.threat import StrideCategory


class KnowledgeSnippet(BaseModel):
    """A single unit of security knowledge in the RAG corpus.

    Content is paraphrased from public security frameworks (STRIDE, OWASP
    Top 10, CWE, CIS/AWS guidance); the ``source`` field records the originating
    reference (e.g. "CWE-311", "OWASP A02:2021") for traceability and
    attribution. The corpus is intentionally broader than the benchmark
    architectures so retrieval must select what is relevant rather than map one
    snippet onto one ground-truth threat.
    """

    id: str
    title: str
    text: str
    # Originating reference(s), e.g. "CWE-311", "OWASP A05:2021", "CIS AWS S3".
    source: str
    # STRIDE categories this knowledge is relevant to.
    stride_categories: list[StrideCategory] = Field(default_factory=list)
    # Component types / situations this snippet applies to, used as retrieval
    # hooks (e.g. "object_store", "data_store", "web_api", "public_access").
    applies_to: list[str] = Field(default_factory=list)
    # Additional free-form retrieval terms.
    keywords: list[str] = Field(default_factory=list)


DEFAULT_KNOWLEDGE_BASE = "data/knowledge_base.json"


def load_knowledge_base(
    path: str | Path = DEFAULT_KNOWLEDGE_BASE,
) -> list[KnowledgeSnippet]:
    """Load and validate the security knowledge corpus.

    Raises ValueError if snippet ids are not unique, since duplicate ids would
    make retrieval results ambiguous.
    """
    with open(path) as f:
        data = json.load(f)

    snippets = [KnowledgeSnippet.model_validate(s) for s in data["snippets"]]

    ids = [s.id for s in snippets]
    duplicates = {i for i in ids if ids.count(i) > 1}
    if duplicates:
        raise ValueError(f"Duplicate snippet ids in knowledge base: {sorted(duplicates)}")

    return snippets
