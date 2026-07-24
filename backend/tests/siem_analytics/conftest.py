from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from redforge.shared.identifiers import EntityId
from siem_analytics.application.commands.analytics_queries import AnalyticsQuery
from siem_analytics.application.dtos.analytics_metric import AnalyticsMetric, AnalyticsResult
from siem_analytics.domain.value_objects.enums import (
    AnalyticsAggregationType,
    AnalyticsEntityType,
    AnalyticsRole,
)
from siem_analytics.domain.value_objects.time_range import TimeRange
from siem_shared.domain.value_objects.schema_version import SchemaVersion

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from siem_analytics.domain.value_objects.group_by_field import GroupByField

VIEWER_ROLES = (AnalyticsRole.VIEWER.value,)
SCHEMA_V1_0 = SchemaVersion(1, 0)
NOW = datetime.now(UTC)
DEFAULT_TIME_RANGE = TimeRange(start=NOW - timedelta(hours=1), end=NOW)


class FakeAnalyticsProvider:
    def __init__(
        self,
        entity_type: AnalyticsEntityType,
        schema_version: SchemaVersion = SCHEMA_V1_0,
        handler: Callable[..., AnalyticsResult] | None = None,
    ) -> None:
        self._entity_type = entity_type
        self._schema_version = schema_version
        self._handler = handler

    @property
    def entity_type(self) -> AnalyticsEntityType:
        return self._entity_type

    @property
    def schema_version(self) -> SchemaVersion:
        return self._schema_version

    def aggregate(
        self,
        tenant_id: EntityId,
        time_range: TimeRange,
        aggregation_type: AnalyticsAggregationType,
        group_by: Sequence[GroupByField],
        filters: Mapping[str, object],
    ) -> AnalyticsResult:
        if self._handler is None:
            raise AssertionError("FakeAnalyticsProvider.aggregate called with no handler set")
        return self._handler(tenant_id, time_range, aggregation_type, group_by, filters)


def fixed_result(metrics: tuple[AnalyticsMetric, ...] = (), total_sample_count: int | None = None):
    def _handler(tenant_id, time_range, aggregation_type, group_by, filters):
        return AnalyticsResult(
            entity_type=AnalyticsEntityType.EVENTS.value,
            aggregation_type=aggregation_type.value,
            metrics=metrics,
            total_sample_count=(
                total_sample_count
                if total_sample_count is not None
                else sum(m.sample_count for m in metrics)
            ),
        )

    return _handler


def make_metric(group_key: dict[str, str] | None = None, value: float = 1.0, sample_count: int = 1) -> AnalyticsMetric:
    return AnalyticsMetric(group_key=group_key or {}, value=value, sample_count=sample_count)


def make_query(**overrides: object) -> AnalyticsQuery:
    defaults: dict[str, object] = {
        "tenant_id": EntityId.generate(),
        "entity_type": AnalyticsEntityType.EVENTS,
        "time_range": DEFAULT_TIME_RANGE,
        "aggregation_type": AnalyticsAggregationType.COUNT,
        "schema_version_raw": "1.0",
        "actor_roles": VIEWER_ROLES,
    }
    defaults.update(overrides)
    return AnalyticsQuery(**defaults)  # type: ignore[arg-type]
