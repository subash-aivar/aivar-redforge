"""IAnalyticsProvider — the one open extension point for actually
executing an aggregation (M37 §17). No concrete implementation lives
in this milestone.

Provider owns aggregation execution only — never query validation
(that stays `AnalyticsApplicationService`'s job) and never dashboards,
executive reporting, or risk scoring (M44F's explicit scope boundary).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from redforge.shared.identifiers import EntityId
    from siem_analytics.application.dtos.analytics_metric import AnalyticsResult
    from siem_analytics.domain.value_objects.enums import (
        AnalyticsAggregationType,
        AnalyticsEntityType,
    )
    from siem_analytics.domain.value_objects.group_by_field import GroupByField
    from siem_analytics.domain.value_objects.time_range import TimeRange
    from siem_shared.domain.value_objects.schema_version import SchemaVersion


class IAnalyticsProvider(Protocol):
    """`entity_type` + `schema_version` together are the registry key
    (M44F §4), mirroring `ISearchProvider`'s (M44E) identical shape."""

    @property
    def entity_type(self) -> AnalyticsEntityType: ...

    @property
    def schema_version(self) -> SchemaVersion: ...

    def aggregate(
        self,
        tenant_id: EntityId,
        time_range: TimeRange,
        aggregation_type: AnalyticsAggregationType,
        group_by: Sequence[GroupByField],
        filters: Mapping[str, object],
    ) -> AnalyticsResult:
        """Execute one bounded aggregation. Implementations should
        raise on an aggregation shape/filter combination they cannot
        execute — the framework translates that into a `FAILED`
        outcome, it does not swallow it."""
        ...
