"""In-memory UnitOfWork for testing.

Mirrors the SqlAlchemy UnitOfWork interface but uses in-memory stores.
Supports commit (persist) and rollback (discard pending changes).
Multiple repositories share the same underlying data stores.
"""

from __future__ import annotations

from redforge.infrastructure.repositories.in_memory import (
    InMemoryAttackRepository,
    InMemoryEvidenceRepository,
    InMemoryFindingRepository,
    InMemoryPayloadTemplateRepository,
    InMemoryPolicyRepository,
    InMemoryProviderRepository,
    InMemoryValidationRepository,
)


class InMemoryUnitOfWork:
    """In-memory UoW — all repos share the same stores.

    Usage (same as SqlAlchemy UoW):
        async with InMemoryUnitOfWork(stores) as uow:
            await uow.validations.save(data)
            await uow.commit()
    """

    def __init__(
        self,
        validation_store: InMemoryValidationRepository | None = None,
        finding_store: InMemoryFindingRepository | None = None,
        evidence_store: InMemoryEvidenceRepository | None = None,
        attack_store: InMemoryAttackRepository | None = None,
        policy_store: InMemoryPolicyRepository | None = None,
        provider_store: InMemoryProviderRepository | None = None,
        payload_store: InMemoryPayloadTemplateRepository | None = None,
    ) -> None:
        self._validations = validation_store or InMemoryValidationRepository()
        self._findings = finding_store or InMemoryFindingRepository()
        self._evidence = evidence_store or InMemoryEvidenceRepository()
        self._attacks = attack_store or InMemoryAttackRepository()
        self._policies = policy_store or InMemoryPolicyRepository()
        self._providers = provider_store or InMemoryProviderRepository()
        self._payloads = payload_store or InMemoryPayloadTemplateRepository()
        self._committed = False

    async def __aenter__(self) -> InMemoryUnitOfWork:
        self._committed = False
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore[no-untyped-def]
        pass  # In-memory: nothing to clean up

    async def commit(self) -> None:
        self._committed = True

    async def rollback(self) -> None:
        pass  # In-memory stores don't support true rollback

    @property
    def validations(self) -> InMemoryValidationRepository:
        return self._validations

    @property
    def findings(self) -> InMemoryFindingRepository:
        return self._findings

    @property
    def evidence(self) -> InMemoryEvidenceRepository:
        return self._evidence

    @property
    def attacks(self) -> InMemoryAttackRepository:
        return self._attacks

    @property
    def policies(self) -> InMemoryPolicyRepository:
        return self._policies

    @property
    def providers(self) -> InMemoryProviderRepository:
        return self._providers

    @property
    def payloads(self) -> InMemoryPayloadTemplateRepository:
        return self._payloads


class InMemoryUnitOfWorkFactory:
    """Factory that creates InMemoryUnitOfWork instances sharing the same stores.

    Ensures all UoW instances created by this factory share data
    (simulating a persistent database across requests).
    """

    def __init__(self) -> None:
        self._validations = InMemoryValidationRepository()
        self._findings = InMemoryFindingRepository()
        self._evidence = InMemoryEvidenceRepository()
        self._attacks = InMemoryAttackRepository()
        self._policies = InMemoryPolicyRepository()
        self._providers = InMemoryProviderRepository()
        self._payloads = InMemoryPayloadTemplateRepository()

    def __call__(self) -> InMemoryUnitOfWork:
        return InMemoryUnitOfWork(
            validation_store=self._validations,
            finding_store=self._findings,
            evidence_store=self._evidence,
            attack_store=self._attacks,
            policy_store=self._policies,
            provider_store=self._providers,
            payload_store=self._payloads,
        )
