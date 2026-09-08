"""In-memory fakes for threat_report_intel application-layer tests. No
ORM, no real I/O — pure Python collections."""

from __future__ import annotations

from typing import TYPE_CHECKING, Self

from threat_report_intel.application.ports.i_event_publisher import IEventPublisher
from threat_report_intel.application.ports.i_threat_report_repository import (
    IThreatReportRepository,
)
from threat_report_intel.application.ports.i_unit_of_work import IUnitOfWork

if TYPE_CHECKING:
    from threat_report_intel.domain.aggregates.threat_report import ThreatReport
    from threat_report_intel.domain.events.base import BaseDomainEvent
    from threat_report_intel.domain.value_objects.enums import (
        ThreatReportLifecycleStatus,
        ThreatReportSeverity,
        TlpMarking,
    )
    from threat_report_intel.domain.value_objects.identifiers import (
        TenantId,
        ThreatReportId,
    )


def _tenant_key(tenant_id: TenantId | None) -> str:
    return "" if tenant_id is None else str(tenant_id)


class InMemoryThreatReportRepository(IThreatReportRepository):
    def __init__(self) -> None:
        self._by_id: dict[str, ThreatReport] = {}

    async def save(self, record: ThreatReport) -> None:
        self._by_id[str(record.threat_report_id)] = record

    async def get(
        self, tenant_id: TenantId | None, threat_report_id: ThreatReportId
    ) -> ThreatReport | None:
        record = self._by_id.get(str(threat_report_id))
        if record is None or _tenant_key(record.tenant_id) != _tenant_key(tenant_id):
            return None
        return record

    async def get_any(self, threat_report_id: ThreatReportId) -> ThreatReport | None:
        return self._by_id.get(str(threat_report_id))

    async def get_by_identity(
        self, tenant_id: TenantId | None, canonical_title: str
    ) -> ThreatReport | None:
        for record in self._by_id.values():
            if (
                _tenant_key(record.tenant_id) == _tenant_key(tenant_id)
                and record.canonical_title == canonical_title
            ):
                return record
        return None

    async def list(
        self,
        tenant_id: TenantId | None,
        lifecycle_status: ThreatReportLifecycleStatus | None = None,
        severity: ThreatReportSeverity | None = None,
        tlp_marking: TlpMarking | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ThreatReport]:
        results = [
            r for r in self._by_id.values() if _tenant_key(r.tenant_id) == _tenant_key(tenant_id)
        ]
        if lifecycle_status is not None:
            results = [r for r in results if r.lifecycle_status is lifecycle_status]
        if severity is not None:
            results = [r for r in results if r.severity is severity]
        if tlp_marking is not None:
            results = [r for r in results if r.report_metadata.tlp_marking is tlp_marking]
        results = sorted(results, key=lambda r: r.created_at, reverse=True)
        return results[offset : offset + limit]


class FakeUnitOfWork(IUnitOfWork):
    def __init__(self, repo: InMemoryThreatReportRepository, *, fail_commit: bool = False) -> None:
        self.threat_reports = repo
        self._fail_commit = fail_commit
        self.committed = False
        self.rolled_back = False

    async def commit(self) -> None:
        if self._fail_commit:
            raise RuntimeError("simulated commit failure")
        self.committed = True

    async def rollback(self) -> None:
        self.rolled_back = True

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        if exc_type is not None:
            await self.rollback()


class RecordingEventPublisher(IEventPublisher):
    def __init__(self) -> None:
        self.published_batches: list[list[BaseDomainEvent]] = []

    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        self.published_batches.append(list(events))

    @property
    def all_published(self) -> list[BaseDomainEvent]:
        return [event for batch in self.published_batches for event in batch]
