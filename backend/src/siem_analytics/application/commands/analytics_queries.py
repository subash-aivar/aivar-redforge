"""Immutable CQRS query objects for siem_analytics's Analytics Engine
(M44F).

One parameterized `AnalyticsQuery` (keyed by `AnalyticsEntityType`)
rather than duplicated per-entity classes — mirrors
`siem_search.application.commands.search_queries.SearchQuery` (M44E):
validation and orchestration are identical across entity types, only
the registry key differs. Construct one per target, e.g.
`AnalyticsQuery(entity_type=AnalyticsEntityType.ALERTS, ...)`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

    from redforge.shared.identifiers import EntityId
    from siem_analytics.domain.value_objects.enums import (
        AnalyticsAggregationType,
        AnalyticsEntityType,
    )
    from siem_analytics.domain.value_objects.group_by_field import GroupByField
    from siem_analytics.domain.value_objects.time_range import TimeRange


@dataclass(frozen=True, slots=True)
class AnalyticsQuery:
    tenant_id: EntityId
    entity_type: AnalyticsEntityType
    time_range: TimeRange
    aggregation_type: AnalyticsAggregationType
    schema_version_raw: str
    group_by: tuple[GroupByField, ...] = ()
    filters: Mapping[str, object] = field(default_factory=dict)
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AnalyticsBatchQuery:
    tenant_id: EntityId
    queries: tuple[AnalyticsQuery, ...] = field(default_factory=tuple)
    actor_roles: tuple[str, ...] = ()
