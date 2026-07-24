"""GroupByField — one field an analytics aggregation is grouped by
(M44F §1), mirroring `siem_search.domain.value_objects.sort_field`."""

from __future__ import annotations

from dataclasses import dataclass

from siem_analytics.domain.exceptions.domain_exceptions import InvalidGroupByFieldError


@dataclass(frozen=True, slots=True)
class GroupByField:
    field_name: str

    def __post_init__(self) -> None:
        if not self.field_name.strip():
            raise InvalidGroupByFieldError()
