"""In-memory fakes for ioc_intelligence application-layer tests
(M51.2 Phase A2). No ORM, no real I/O — pure Python collections."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Self

from ioc_intelligence.application.ports.i_event_publisher import IEventPublisher
from ioc_intelligence.application.ports.i_ioc_evidence_validation_port import (
    IIocEvidenceValidationPort,
)
from ioc_intelligence.application.ports.i_ioc_repository import IIocRepository
from ioc_intelligence.application.ports.i_unit_of_work import IUnitOfWork

if TYPE_CHECKING:
    from ioc_intelligence.domain.aggregates.ioc import IOC
    from ioc_intelligence.domain.events.base import BaseDomainEvent
    from ioc_intelligence.domain.value_objects.enums import EpistemicState, IocLifecycle
    from ioc_intelligence.domain.value_objects.identifiers import IocId, TenantId
    from ioc_intelligence.domain.value_objects.indicator_value import IndicatorCanonicalKey


def _tenant_key(tenant_id: TenantId | None) -> str:
    return "" if tenant_id is None else str(tenant_id)


def _now_utc() -> datetime:
    return datetime.now(UTC)


class InMemoryIocRepository(IIocRepository):
    def __init__(self) -> None:
        self._by_id: dict[str, IOC] = {}

    async def save(self, ioc: IOC) -> None:
        self._by_id[str(ioc.ioc_id)] = ioc

    async def get(self, tenant_id: TenantId | None, ioc_id: IocId) -> IOC | None:
        ioc = self._by_id.get(str(ioc_id))
        if ioc is None or _tenant_key(ioc.tenant_id) != _tenant_key(tenant_id):
            return None
        return ioc

    async def get_any(self, ioc_id: IocId) -> IOC | None:
        return self._by_id.get(str(ioc_id))

    async def get_by_canonical_key(
        self, tenant_id: TenantId | None, canonical_key: IndicatorCanonicalKey
    ) -> IOC | None:
        for ioc in self._by_id.values():
            if (
                _tenant_key(ioc.tenant_id) == _tenant_key(tenant_id)
                and ioc.canonical_key == canonical_key
            ):
                return ioc
        return None

    async def list_and_count(
        self,
        tenant_id: TenantId | None,
        *,
        lifecycle: IocLifecycle | None = None,
        epistemic_state: EpistemicState | None = None,
        ioc_type=None,
        search: str | None = None,
        confidence=None,
        source_system: str | None = None,
        validity=None,
        sort_by=None,
        sort_dir=None,
        limit: int = 50,
        offset: int = 0,
    ):
        from ioc_intelligence.application.queries.ioc_queries import (
            IocSortField,
            SortDirection,
            ValidityFilter,
        )

        sort_by = sort_by or IocSortField.CREATED_AT
        sort_dir = sort_dir or SortDirection.DESC

        results = [
            ioc
            for ioc in self._by_id.values()
            if _tenant_key(ioc.tenant_id) == _tenant_key(tenant_id)
        ]
        if lifecycle is not None:
            results = [i for i in results if i.lifecycle is lifecycle]
        if epistemic_state is not None:
            results = [i for i in results if i.epistemic_state is epistemic_state]
        if ioc_type is not None:
            results = [i for i in results if i.ioc_type is ioc_type]
        if search:
            needle = search.lower()
            results = [i for i in results if needle in i.canonical_key.normalized_value.lower()]
        if validity is ValidityFilter.VALID:
            results = [
                i
                for i in results
                if i.validity_window.valid_until is None
                or i.validity_window.valid_until > _now_utc()
            ]
        elif validity is ValidityFilter.LAPSED:
            results = [
                i
                for i in results
                if i.validity_window.valid_until is not None
                and i.validity_window.valid_until <= _now_utc()
            ]
        if confidence is not None:
            results = [
                i
                for i in results
                if any(a.confidence == confidence for a in i.source_attributions)
            ]
        if source_system:
            results = [
                i
                for i in results
                if any(a.source_system == source_system for a in i.source_attributions)
            ]

        sort_key_fn = {
            IocSortField.CREATED_AT: lambda i: i.created_at,
            IocSortField.UPDATED_AT: lambda i: i.updated_at,
            IocSortField.VALID_UNTIL: lambda i: (
                i.validity_window.valid_until is not None,
                i.validity_window.valid_until,
            ),
            IocSortField.IOC_TYPE: lambda i: i.ioc_type.value,
            IocSortField.LIFECYCLE: lambda i: i.lifecycle.value,
            IocSortField.EPISTEMIC_STATE: lambda i: i.epistemic_state.value,
        }[sort_by]
        results = sorted(results, key=sort_key_fn, reverse=(sort_dir is SortDirection.DESC))
        total = len(results)
        return results[offset : offset + limit], total

    async def list(
        self,
        tenant_id: TenantId | None,
        lifecycle: IocLifecycle | None = None,
        epistemic_state: EpistemicState | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[IOC]:
        """Test-convenience wrapper over `list_and_count` — kept only so
        the many existing ingestion-orchestrator test call sites that
        just want the items (not the total) don't all need rewriting.
        Not part of `IIocRepository`; never used by production code."""
        items, _ = await self.list_and_count(
            tenant_id,
            lifecycle=lifecycle,
            epistemic_state=epistemic_state,
            limit=limit,
            offset=offset,
        )
        return items

    async def list_lapsed_active(self, now, limit: int = 200) -> list[IOC]:
        from ioc_intelligence.domain.value_objects.enums import IocLifecycle

        results = [
            ioc
            for ioc in self._by_id.values()
            if ioc.lifecycle is IocLifecycle.ACTIVE
            and ioc.validity_window.valid_until is not None
            and ioc.validity_window.valid_until < now
        ]
        results = sorted(results, key=lambda i: i.validity_window.valid_until)
        return results[:limit]


class FakeUnitOfWork(IUnitOfWork):
    def __init__(self, repo: InMemoryIocRepository, *, fail_commit: bool = False) -> None:
        self.iocs = repo
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


class FakeEvidenceValidationPort(IIocEvidenceValidationPort):
    def __init__(self, valid_citations: set[tuple[str, str]] | None = None) -> None:
        self._valid_citations = valid_citations or set()

    async def validate(self, tenant_id: TenantId, evidence_citation: str) -> bool:
        return (str(tenant_id), evidence_citation) in self._valid_citations


class FakeLegacyIocObservationPort:
    """In-memory `ILegacyIocObservationPort` double (M51.2 Phase A5) —
    pure Python, no ORM, no real threat_intel tables."""

    def __init__(self, rows: list) -> None:
        self._rows = list(rows)

    async def find_observation(self, tenant_id: str, ioc_type: str, normalized_value: str):
        for row in self._rows:
            if row.ioc_type == ioc_type and row.normalized_value == normalized_value:
                return row
        return None

    async def list_recent_observations(self, tenant_id: str, limit: int, offset: int):
        return self._rows[offset : offset + limit]


class FakeIocEnrichmentQueryPort:
    """In-memory `IIocEnrichmentQueryPort` double — keyed by
    `(ioc_type, normalized_value, kind)`."""

    def __init__(self, entries: dict | None = None) -> None:
        self._entries = entries or {}

    async def get_latest_enrichment(
        self, tenant_id: str, ioc_type: str, normalized_value: str, kind: str
    ):
        return self._entries.get((ioc_type, normalized_value, kind))


class FakeIocCorrelationQueryPort:
    """In-memory `IIocCorrelationQueryPort` double — keyed by
    `(ioc_type, normalized_value)`."""

    def __init__(self, entries: dict | None = None) -> None:
        self._entries = entries or {}

    async def get_correlation_matches(self, tenant_id: str, ioc_type: str, normalized_value: str):
        return self._entries.get((ioc_type, normalized_value), [])
