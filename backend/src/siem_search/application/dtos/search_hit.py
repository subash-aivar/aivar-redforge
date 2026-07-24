"""SearchHit / SearchResultPage — the Search Engine's read-only result
shapes (M44E §5). Neither type is ever written anywhere; both are
read-once, immutable projections of whatever `ISearchProvider`
returned.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping


@dataclass(frozen=True, slots=True)
class SearchHit:
    entity_type: str
    entity_id: str
    score: float
    snippet: str | None = None
    source: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.entity_id.strip():
            raise ValueError("SearchHit.entity_id must be a non-empty string")
        if self.score < 0.0:
            raise ValueError(f"SearchHit.score must be >= 0, got {self.score}")


@dataclass(frozen=True, slots=True)
class SearchResultPage:
    hits: tuple[SearchHit, ...]
    total_hits: int
    page_size: int
    offset: int
    has_more: bool

    def __post_init__(self) -> None:
        if self.total_hits < len(self.hits):
            raise ValueError("SearchResultPage.total_hits cannot be smaller than len(hits)")
        if self.page_size <= 0:
            raise ValueError("SearchResultPage.page_size must be positive")
        if self.offset < 0:
            raise ValueError("SearchResultPage.offset must be non-negative")
