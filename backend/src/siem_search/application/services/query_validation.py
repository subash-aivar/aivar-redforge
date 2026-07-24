"""Query-validation stages for the Search Engine (M44E §6).

Every stage is a pure function that either returns successfully or
raises one of `siem_search.application.exceptions`'s typed domain
errors — never a bare `ValueError`. `SearchApplicationService`
orchestrates these stages and translates a raised error into a
`SearchFailure` entry on the returned outcome.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from siem_search.application.exceptions import (
    InvalidFilterError,
    InvalidPaginationError,
    InvalidSortError,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from siem_search.domain.value_objects.sort_field import SortField

MAX_PAGE_SIZE = 1000


def validate_pagination(page_size: int, offset: int) -> None:
    if page_size <= 0:
        raise InvalidPaginationError(f"page_size must be positive, got {page_size}")
    if page_size > MAX_PAGE_SIZE:
        raise InvalidPaginationError(f"page_size must be <= {MAX_PAGE_SIZE}, got {page_size}")
    if offset < 0:
        raise InvalidPaginationError(f"offset must be non-negative, got {offset}")


def validate_filters(filters: Mapping[str, object]) -> None:
    for key in filters:
        if not key.strip():
            raise InvalidFilterError("filter keys must be non-empty strings")


def validate_sort(sort: Sequence[SortField]) -> None:
    seen: set[str] = set()
    for entry in sort:
        if entry.field_name in seen:
            raise InvalidSortError(f"duplicate sort field {entry.field_name!r}")
        seen.add(entry.field_name)
