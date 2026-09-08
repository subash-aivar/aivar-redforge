"""In-memory fakes for infrastructure_intel application-layer tests. No
ORM, no real I/O — pure Python collections."""

from __future__ import annotations

from typing import TYPE_CHECKING, Self

from infrastructure_intel.application.ports.i_event_publisher import IEventPublisher
from infrastructure_intel.application.ports.i_infrastructure_repository import (
    IInfrastructureRepository,
)
from infrastructure_intel.application.ports.i_unit_of_work import IUnitOfWork

if TYPE_CHECKING:
    from infrastructure_intel.domain.aggregates.infrastructure import Infrastructure
    from infrastructure_intel.domain.events.base import BaseDomainEvent
    from infrastructure_intel.domain.value_objects.enums import (
        CloudProvider,
        InfrastructureLifecycleStatus,
        InfrastructureType,
    )
    from infrastructure_intel.domain.value_objects.identifiers import (
        InfrastructureId,
        TenantId,
    )


def _tenant_key(tenant_id: TenantId | None) -> str:
    return "" if tenant_id is None else str(tenant_id)


class InMemoryInfrastructureRepository(IInfrastructureRepository):
    def __init__(self) -> None:
        self._by_id: dict[str, Infrastructure] = {}

    async def save(self, record: Infrastructure) -> None:
        self._by_id[str(record.infrastructure_id)] = record

    async def get(
        self, tenant_id: TenantId | None, infrastructure_id: InfrastructureId
    ) -> Infrastructure | None:
        record = self._by_id.get(str(infrastructure_id))
        if record is None or _tenant_key(record.tenant_id) != _tenant_key(tenant_id):
            return None
        return record

    async def get_any(self, infrastructure_id: InfrastructureId) -> Infrastructure | None:
        return self._by_id.get(str(infrastructure_id))

    async def get_by_identity(
        self,
        tenant_id: TenantId | None,
        infrastructure_type: InfrastructureType,
        normalized_identifier: str,
    ) -> Infrastructure | None:
        for record in self._by_id.values():
            if (
                _tenant_key(record.tenant_id) == _tenant_key(tenant_id)
                and record.infrastructure_type is infrastructure_type
                and record.normalized_identifier == normalized_identifier
            ):
                return record
        return None

    async def list(
        self,
        tenant_id: TenantId | None,
        lifecycle_status: InfrastructureLifecycleStatus | None = None,
        infrastructure_type: InfrastructureType | None = None,
        cloud_provider: CloudProvider | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Infrastructure]:
        results = [
            r for r in self._by_id.values() if _tenant_key(r.tenant_id) == _tenant_key(tenant_id)
        ]
        if lifecycle_status is not None:
            results = [r for r in results if r.lifecycle_status is lifecycle_status]
        if infrastructure_type is not None:
            results = [r for r in results if r.infrastructure_type is infrastructure_type]
        if cloud_provider is not None:
            results = [
                r
                for r in results
                if r.cloud_provider is not None and r.cloud_provider.provider is cloud_provider
            ]
        results = sorted(results, key=lambda r: r.created_at, reverse=True)
        return results[offset : offset + limit]


class FakeUnitOfWork(IUnitOfWork):
    def __init__(
        self, repo: InMemoryInfrastructureRepository, *, fail_commit: bool = False
    ) -> None:
        self.infrastructure = repo
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
