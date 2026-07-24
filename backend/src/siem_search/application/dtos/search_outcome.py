"""Immutable search-outcome DTOs (M44E §5).

Read-once outcomes returned synchronously to the caller — never
persisted. The Search Engine's responsibility ends at producing these;
it never calculates analytics, never aggregates statistics, never
builds dashboards.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from siem_search.application.dtos.search_hit import SearchResultPage


class SearchStatus(StrEnum):
    SUCCEEDED = "succeeded"
    REJECTED = "rejected"
    UNSUPPORTED_PROVIDER = "unsupported_provider"
    FAILED = "failed"
    PARTIALLY_SUCCEEDED = "partially_succeeded"


@dataclass(frozen=True, slots=True)
class SearchFailure:
    stage: str
    error_type: str
    message: str


@dataclass(frozen=True, slots=True)
class SearchOutcome:
    status: SearchStatus
    page: SearchResultPage | None = None
    failures: tuple[SearchFailure, ...] = ()

    def __post_init__(self) -> None:
        page_required = self.status == SearchStatus.SUCCEEDED
        if page_required and self.page is None:
            raise ValueError(f"{self.status} SearchOutcome must carry a page")
        if not page_required and self.page is not None:
            raise ValueError(f"{self.status} SearchOutcome must not carry a page")


@dataclass(frozen=True, slots=True)
class BatchSearchResult:
    status: SearchStatus
    outcomes: tuple[SearchOutcome, ...] = field(default_factory=tuple)

    @property
    def succeeded_count(self) -> int:
        return sum(1 for o in self.outcomes if o.status == SearchStatus.SUCCEEDED)

    @property
    def failed_count(self) -> int:
        return len(self.outcomes) - self.succeeded_count
