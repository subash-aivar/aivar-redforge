"""Evidence application lifecycle tests with in-memory fakes."""

from __future__ import annotations

from uuid import UUID, uuid7

import pytest
from tests.evidence.fakes.repos import FakeEventPublisher, FakeEvidenceUnitOfWork

from evidence.application.commands.evidence_commands import (
    CollectEvidence,
    OpenEvidenceChain,
    SealEvidenceChain,
    VerifyEvidenceIntegrity,
)
from evidence.application.exceptions import ApplicationIntegrityError
from evidence.application.services.evidence_application_service import (
    EvidenceApplicationService,
)
from evidence.domain.value_objects.enums import EVIDENCE_SEALER_ROLE
from evidence.domain.value_objects.evidence_vos import EvidenceStorageRef
from evidence.domain.value_objects.identifiers import TenantId
from evidence.infrastructure.blob.in_memory_evidence_blob_store import (
    InMemoryEvidenceBlobStore,
)
from evidence.infrastructure.kms.in_memory_key_management import InMemoryKeyManagementPort


@pytest.fixture
def svc() -> tuple[EvidenceApplicationService, FakeEvidenceUnitOfWork, InMemoryEvidenceBlobStore]:
    uow = FakeEvidenceUnitOfWork()
    blob = InMemoryEvidenceBlobStore()
    kms = InMemoryKeyManagementPort()
    events = FakeEventPublisher()

    def factory() -> FakeEvidenceUnitOfWork:
        return FakeEvidenceUnitOfWork(evidence=uow.evidence, chains=uow.chains)

    service = EvidenceApplicationService(factory, events, blob, kms)
    return service, uow, blob


@pytest.mark.asyncio
async def test_collect_verify_chain_seal_lifecycle(
    svc: tuple[EvidenceApplicationService, FakeEvidenceUnitOfWork, InMemoryEvidenceBlobStore],
) -> None:
    service, _uow, _blob = svc
    tenant = uuid7()
    engagement = uuid7()
    operation = uuid7()

    chain = await service.open_evidence_chain(
        OpenEvidenceChain(
            tenant_id=tenant,
            operation_id=operation,
            engagement_id=engagement,
        )
    )
    evidence = await service.collect_evidence(
        CollectEvidence(
            tenant_id=tenant,
            action_id=uuid7(),
            engagement_id=engagement,
            operation_id=operation,
            evidence_type="CommandOutput",
            payload=b"command-output",
            collected_by="operator-1",
        )
    )
    verified = await service.verify_evidence_integrity(
        VerifyEvidenceIntegrity(
            tenant_id=tenant,
            evidence_id=UUID(evidence.evidence_id),
        )
    )
    assert verified.status == "Verified"

    sealed = await service.seal_evidence_chain(
        SealEvidenceChain(
            tenant_id=tenant,
            chain_id=UUID(chain.chain_id),
            sealer_operator_id=uuid7(),
            sealer_role=EVIDENCE_SEALER_ROLE,
            signature="seal-sig",
        )
    )
    assert sealed.state == "Sealed"
    assert len(sealed.entries) >= 1


@pytest.mark.asyncio
async def test_tampered_blob_raises_integrity_error(
    svc: tuple[EvidenceApplicationService, FakeEvidenceUnitOfWork, InMemoryEvidenceBlobStore],
) -> None:
    service, _uow, blob = svc
    tenant = uuid7()
    evidence = await service.collect_evidence(
        CollectEvidence(
            tenant_id=tenant,
            action_id=uuid7(),
            engagement_id=uuid7(),
            operation_id=uuid7(),
            evidence_type="CommandOutput",
            payload=b"clean",
            collected_by="operator-1",
        )
    )
    blob.tamper(TenantId(tenant), EvidenceStorageRef(evidence.storage_ref))
    with pytest.raises(ApplicationIntegrityError):
        await service.verify_evidence_integrity(
            VerifyEvidenceIntegrity(
                tenant_id=tenant,
                evidence_id=UUID(evidence.evidence_id),
            )
        )
