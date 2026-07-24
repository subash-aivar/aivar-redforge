from __future__ import annotations

import pytest

from siem_search.application.exceptions import (
    InvalidFilterError,
    InvalidPaginationError,
    InvalidSortError,
)
from siem_search.application.services.query_validation import (
    validate_filters,
    validate_pagination,
    validate_sort,
)
from siem_search.domain.value_objects.enums import SortDirection
from siem_search.domain.value_objects.sort_field import SortField


def test_validate_pagination_valid() -> None:
    validate_pagination(page_size=50, offset=0)


def test_validate_pagination_rejects_non_positive_page_size() -> None:
    with pytest.raises(InvalidPaginationError):
        validate_pagination(page_size=0, offset=0)


def test_validate_pagination_rejects_oversized_page_size() -> None:
    with pytest.raises(InvalidPaginationError):
        validate_pagination(page_size=10_000, offset=0)


def test_validate_pagination_rejects_negative_offset() -> None:
    with pytest.raises(InvalidPaginationError):
        validate_pagination(page_size=50, offset=-1)


def test_validate_filters_valid() -> None:
    validate_filters({"category": "authentication"})


def test_validate_filters_rejects_blank_key() -> None:
    with pytest.raises(InvalidFilterError):
        validate_filters({"": "x"})


def test_validate_sort_valid() -> None:
    validate_sort([SortField(field_name="occurred_at", direction=SortDirection.DESC)])


def test_validate_sort_rejects_duplicate_field() -> None:
    with pytest.raises(InvalidSortError):
        validate_sort(
            [
                SortField(field_name="occurred_at"),
                SortField(field_name="occurred_at", direction=SortDirection.DESC),
            ]
        )
