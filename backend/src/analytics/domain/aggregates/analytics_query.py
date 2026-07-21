"""AnalyticsQuery aggregate — stored parameterized query templates (Phase 2)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from analytics.domain.events.analytics_events import AnalyticsQueryCreated
from analytics.domain.value_objects.enums import SecurityDomain

if TYPE_CHECKING:
    from datetime import datetime

    from analytics.domain.events.base import BaseDomainEvent
    from analytics.domain.value_objects.identifiers import AnalyticsQueryId, TenantId


class AnalyticsQuery:
    __slots__ = (
        "_pending_events",
        "created_at",
        "created_by",
        "domain",
        "name",
        "parameter_names",
        "query_id",
        "query_template",
        "tenant_id",
        "updated_at",
    )

    def __init__(
        self,
        query_id: AnalyticsQueryId,
        tenant_id: TenantId,
        name: str,
        query_template: str,
        domain: SecurityDomain,
        parameter_names: list[str],
        created_by: str,
        created_at: datetime,
        updated_at: datetime,
    ) -> None:
        self.query_id = query_id
        self.tenant_id = tenant_id
        self.name = name
        self.query_template = query_template
        self.domain = domain
        self.parameter_names = list(parameter_names)
        self.created_by = created_by
        self.created_at = created_at
        self.updated_at = updated_at
        self._pending_events: list[BaseDomainEvent] = []

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    @classmethod
    def create(
        cls,
        query_id: AnalyticsQueryId,
        tenant_id: TenantId,
        name: str,
        query_template: str,
        domain: SecurityDomain,
        parameter_names: list[str],
        created_by: str,
        at: datetime,
    ) -> AnalyticsQuery:
        q = cls(
            query_id,
            tenant_id,
            name,
            query_template,
            domain,
            parameter_names,
            created_by,
            at,
            at,
        )
        q._pending_events.append(
            AnalyticsQueryCreated(
                tenant_id=str(tenant_id),
                aggregate_id=str(query_id),
                name=name,
                domain=domain.value,
            )
        )
        return q
