"""IThreatReportRepository — implementation-independent (no ORM/DB
types). `tenant_id=None` addresses the global scope; a real `TenantId`
addresses that tenant's own scope only. A concrete adapter must never
return a record whose `tenant_id` does not exactly match the requested
scope, mirroring `IInfrastructureRepository`'s exact
not-found-semantics discipline.

No relationship method exists on this port by design: cross-entity
relationships are owned exclusively by `intelligence_relationships`,
which (as of M51.9 Phase H1) defines `THREAT_REPORT_TO_*`
`RelationshipType` values and supports these links today. That
capability living elsewhere is exactly why no relationship method
belongs here — adding one would duplicate a certified capability (see
the aggregate's module docstring for the full picture)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from threat_report_intel.domain.aggregates.threat_report import ThreatReport
    from threat_report_intel.domain.value_objects.enums import (
        ThreatReportLifecycleStatus,
        ThreatReportSeverity,
        TlpMarking,
    )
    from threat_report_intel.domain.value_objects.identifiers import (
        TenantId,
        ThreatReportId,
    )


class IThreatReportRepository(ABC):
    @abstractmethod
    async def save(self, record: ThreatReport) -> None: ...

    @abstractmethod
    async def get(
        self, tenant_id: TenantId | None, threat_report_id: ThreatReportId
    ) -> ThreatReport | None: ...

    @abstractmethod
    async def get_any(self, threat_report_id: ThreatReportId) -> ThreatReport | None:
        """Unscoped lookup by ID only — used exclusively to resolve a
        ThreatReport record's ownership scope (its `tenant_id`) for the
        API layer's ownership-based authorization decision. The caller
        must authorize before using anything from the returned aggregate
        beyond `.tenant_id`."""
        ...

    @abstractmethod
    async def get_by_identity(
        self, tenant_id: TenantId | None, canonical_title: str
    ) -> ThreatReport | None: ...

    @abstractmethod
    async def list(
        self,
        tenant_id: TenantId | None,
        lifecycle_status: ThreatReportLifecycleStatus | None = None,
        severity: ThreatReportSeverity | None = None,
        tlp_marking: TlpMarking | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ThreatReport]: ...
