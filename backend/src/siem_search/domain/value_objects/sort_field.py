"""SortField — one field in a search query's sort order (M37 §10)."""

from __future__ import annotations

from dataclasses import dataclass

from siem_search.domain.value_objects.enums import SortDirection


@dataclass(frozen=True, slots=True)
class SortField:
    field_name: str
    direction: SortDirection = SortDirection.ASC

    def __post_init__(self) -> None:
        if not self.field_name.strip():
            raise ValueError("SortField.field_name must be a non-empty string")
