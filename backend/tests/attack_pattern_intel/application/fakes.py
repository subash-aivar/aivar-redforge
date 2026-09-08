"""In-memory fakes for attack_pattern_intel application-layer tests
(M51.3 Phase B1). No ORM, no real I/O — pure Python collections."""

from __future__ import annotations

from typing import TYPE_CHECKING, Self

from attack_pattern_intel.application.ports.i_attack_pattern_repository import (
    IAttackPatternRepository,
)
from attack_pattern_intel.application.ports.i_event_publisher import IEventPublisher
from attack_pattern_intel.application.ports.i_mitre_technique_identity_port import (
    IMitreTechniqueIdentityPort,
    MitreTechniqueSnapshot,
)
from attack_pattern_intel.application.ports.i_unit_of_work import IUnitOfWork

if TYPE_CHECKING:
    from attack_pattern_intel.domain.aggregates.attack_pattern import AttackPattern
    from attack_pattern_intel.domain.events.base import BaseDomainEvent
    from attack_pattern_intel.domain.value_objects.enums import TechniqueLifecycleStatus
    from attack_pattern_intel.domain.value_objects.identifiers import AttackPatternId, TenantId


def _tenant_key(tenant_id: TenantId | None) -> str:
    return "" if tenant_id is None else str(tenant_id)


class InMemoryAttackPatternRepository(IAttackPatternRepository):
    def __init__(self) -> None:
        self._by_id: dict[str, AttackPattern] = {}

    async def save(self, pattern: AttackPattern) -> None:
        self._by_id[str(pattern.attack_pattern_id)] = pattern

    async def get(
        self, tenant_id: TenantId | None, attack_pattern_id: AttackPatternId
    ) -> AttackPattern | None:
        pattern = self._by_id.get(str(attack_pattern_id))
        if pattern is None or _tenant_key(pattern.tenant_id) != _tenant_key(tenant_id):
            return None
        return pattern

    async def get_any(self, attack_pattern_id: AttackPatternId) -> AttackPattern | None:
        return self._by_id.get(str(attack_pattern_id))

    async def get_by_technique_id(
        self, tenant_id: TenantId | None, effective_technique_id: str
    ) -> AttackPattern | None:
        for pattern in self._by_id.values():
            if (
                _tenant_key(pattern.tenant_id) == _tenant_key(tenant_id)
                and pattern.mitre_technique_ref.effective_id == effective_technique_id
            ):
                return pattern
        return None

    async def list(
        self,
        tenant_id: TenantId | None,
        lifecycle_status: TechniqueLifecycleStatus | None = None,
        tactic_id: str | None = None,
        platform: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AttackPattern]:
        results = [
            p for p in self._by_id.values() if _tenant_key(p.tenant_id) == _tenant_key(tenant_id)
        ]
        if lifecycle_status is not None:
            results = [p for p in results if p.lifecycle_status is lifecycle_status]
        if platform is not None:
            results = [p for p in results if platform in p.platforms]
        if tactic_id is not None:
            results = [
                p for p in results if any(t.tactic_id == tactic_id for t in p.tactic_mappings)
            ]
        results = sorted(results, key=lambda p: p.created_at, reverse=True)
        return results[offset : offset + limit]


class FakeUnitOfWork(IUnitOfWork):
    def __init__(self, repo: InMemoryAttackPatternRepository, *, fail_commit: bool = False) -> None:
        self.attack_patterns = repo
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


class FakeMitreTechniqueIdentityPort(IMitreTechniqueIdentityPort):
    def __init__(self, known_technique_ids: set[str] | None = None) -> None:
        self._known = known_technique_ids or set()

    async def exists(self, technique_id: str) -> bool:
        return technique_id in self._known

    async def get_snapshot(self, technique_id: str) -> MitreTechniqueSnapshot | None:
        if technique_id not in self._known:
            return None
        return MitreTechniqueSnapshot(
            technique_id=technique_id,
            name="Fake Technique",
            tactic_ids=("TA0002",),
            platforms=("Windows",),
            is_sub_technique="." in technique_id,
            is_deprecated=False,
            is_revoked=False,
        )
