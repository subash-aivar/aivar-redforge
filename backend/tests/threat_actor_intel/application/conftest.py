"""Shared fixtures for threat_actor_intel's application-layer tests
(M51.1 Phase 2). Fake, in-memory implementations of
`IThreatActorRepository`, `IThreatActorAssociationRepository`,
`IUnitOfWork`, `IEventPublisher`, and `IEvidenceValidationPort` live
here — never in `src/`, mirroring `tests/risk_engine/application/
conftest.py`'s explicit scope boundary."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from threat_actor_intel.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from threat_actor_intel.domain.aggregates.threat_actor import ThreatActor
    from threat_actor_intel.domain.aggregates.threat_actor_association import (
        ThreatActorAssociation,
    )
    from threat_actor_intel.domain.events.base import BaseDomainEvent
    from threat_actor_intel.domain.value_objects.enums import ActivityStatus, ThreatActorOrigin
    from threat_actor_intel.domain.value_objects.identifiers import (
        ThreatActorAssociationId,
        ThreatActorId,
    )


class FakeThreatActorRepository:
    def __init__(self) -> None:
        self._by_id: dict[str, ThreatActor] = {}
        self.save_calls = 0

    async def save(self, actor: ThreatActor) -> None:
        self._by_id[str(actor.threat_actor_id)] = actor
        self.save_calls += 1

    async def get(self, threat_actor_id: ThreatActorId) -> ThreatActor | None:
        return self._by_id.get(str(threat_actor_id))

    async def list(
        self,
        status: ActivityStatus | None = None,
        origin: ThreatActorOrigin | None = None,
    ) -> list[ThreatActor]:
        results = list(self._by_id.values())
        if status is not None:
            results = [a for a in results if a.status == status]
        if origin is not None:
            results = [a for a in results if a.origin == origin]
        return results


class FakeThreatActorAssociationRepository:
    def __init__(self) -> None:
        self._by_key: dict[tuple[str, str], ThreatActorAssociation] = {}

    async def save(self, tenant_id: TenantId, association: ThreatActorAssociation) -> None:
        self._by_key[(str(tenant_id), str(association.association_id))] = association

    async def get(
        self, tenant_id: TenantId, association_id: ThreatActorAssociationId
    ) -> ThreatActorAssociation | None:
        association = self._by_key.get((str(tenant_id), str(association_id)))
        # Cross-tenant isolation: an association belonging to a
        # different tenant must never be distinguishable from
        # "doesn't exist" (mirrors risk_engine's PgEnterpriseRiskProfileRepository
        # precedent).
        if association is None or association.tenant_id != tenant_id:
            return None
        return association

    async def list_for_tenant(
        self, tenant_id: TenantId, threat_actor_id: ThreatActorId | None = None
    ) -> list[ThreatActorAssociation]:
        results = [a for (tid, _), a in self._by_key.items() if tid == str(tenant_id)]
        if threat_actor_id is not None:
            results = [a for a in results if a.threat_actor_id == threat_actor_id]
        return results


class FakeUnitOfWork:
    """Structurally satisfies `IUnitOfWork` (async commit/rollback,
    bundled repository attributes). `call_log`, if supplied, records
    "commit"/"rollback" so tests can prove commit-before-publish
    ordering. `fail_commit=True` makes `commit()` raise, to prove a
    failed commit never reaches event publishing."""

    def __init__(
        self,
        threat_actors: FakeThreatActorRepository,
        associations: FakeThreatActorAssociationRepository,
        call_log: list[str] | None = None,
        fail_commit: bool = False,
    ) -> None:
        self.threat_actors = threat_actors
        self.associations = associations
        self._call_log = call_log
        self._fail_commit = fail_commit
        self.committed = 0
        self.rolled_back = 0

    async def commit(self) -> None:
        if self._fail_commit:
            raise RuntimeError("simulated commit failure")
        self.committed += 1
        if self._call_log is not None:
            self._call_log.append("commit")

    async def rollback(self) -> None:
        self.rolled_back += 1
        if self._call_log is not None:
            self._call_log.append("rollback")

    async def __aenter__(self) -> FakeUnitOfWork:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        if exc_type is not None:
            await self.rollback()


class FakeEventPublisher:
    def __init__(self, call_log: list[str] | None = None) -> None:
        self._call_log = call_log
        self.published_batches: list[list[BaseDomainEvent]] = []

    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        self.published_batches.append(events)
        if self._call_log is not None:
            self._call_log.append("publish")

    @property
    def publish_calls(self) -> int:
        return len(self.published_batches)


class FakeEvidenceValidationPort:
    """`valid` is the default answer. `owner_tenant_id`, if set, makes
    `validate()` return `True` only when the caller's `tenant_id`
    matches — simulating a real ACL adapter rejecting a citation that
    belongs to a different tenant (test #9)."""

    def __init__(self, valid: bool = True, owner_tenant_id: TenantId | None = None) -> None:
        self.valid = valid
        self.owner_tenant_id = owner_tenant_id
        self.calls: list[tuple[TenantId, str, str, str]] = []

    async def validate(
        self,
        tenant_id: TenantId,
        referenced_entity_type: str,
        referenced_entity_id: str,
        evidence_citation: str,
    ) -> bool:
        self.calls.append(
            (tenant_id, referenced_entity_type, referenced_entity_id, evidence_citation)
        )
        if self.owner_tenant_id is not None:
            return tenant_id == self.owner_tenant_id
        return self.valid


@pytest.fixture
def tenant_id() -> TenantId:
    return TenantId.generate()


@pytest.fixture
def other_tenant_id() -> TenantId:
    return TenantId.generate()


@pytest.fixture
def threat_actor_repository() -> FakeThreatActorRepository:
    return FakeThreatActorRepository()


@pytest.fixture
def association_repository() -> FakeThreatActorAssociationRepository:
    return FakeThreatActorAssociationRepository()


@pytest.fixture
def call_log() -> list[str]:
    return []


@pytest.fixture
def unit_of_work(
    threat_actor_repository: FakeThreatActorRepository,
    association_repository: FakeThreatActorAssociationRepository,
    call_log: list[str],
) -> FakeUnitOfWork:
    return FakeUnitOfWork(threat_actor_repository, association_repository, call_log=call_log)


@pytest.fixture
def event_publisher(call_log: list[str]) -> FakeEventPublisher:
    return FakeEventPublisher(call_log=call_log)


@pytest.fixture
def evidence_validator() -> FakeEvidenceValidationPort:
    return FakeEvidenceValidationPort(valid=True)
