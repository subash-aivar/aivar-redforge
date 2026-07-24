"""Query-validation stages for the Analytics Engine (M44F §6).

Every stage is a pure function that either returns successfully or
raises one of `siem_analytics.application.exceptions`'s typed domain
errors — never a bare `ValueError`. `AnalyticsApplicationService`
orchestrates these stages and translates a raised error into an
`AnalyticsFailure` entry on the returned outcome.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from siem_analytics.application.exceptions import InvalidFilterError, InvalidGroupingError

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from siem_analytics.domain.value_objects.group_by_field import GroupByField


def validate_filters(filters: Mapping[str, object]) -> None:
    for key in filters:
        if not key.strip():
            raise InvalidFilterError("filter keys must be non-empty strings")


def validate_group_by(group_by: Sequence[GroupByField]) -> None:
    seen: set[str] = set()
    for entry in group_by:
        if entry.field_name in seen:
            raise InvalidGroupingError(f"duplicate group-by field {entry.field_name!r}")
        seen.add(entry.field_name)
