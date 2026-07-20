"""Domain unit tests for evidence custody, seal, retention, tamper."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid7

import pytest

from evidence.domain.aggregates.evidence_chain import EvidenceChain
from evidence.domain.aggregates.execution_evidence import ExecutionEvidence
from evidence.domain.exceptions.domain_exceptions import (
    EvidenceIntegrityViolation,
    RetentionWindowActive,
    SealerRoleRequired,
)
from evidence.domain.value_objects.enums import (
    EVIDENCE_SEALER_ROLE,
    CustodyAction,
    EvidenceType,
    RetentionClass,
)
from evidence.domain.value_objects.evidence_vos import (
    CollectedBy,
    EvidenceEncryptionKeyRef,
    EvidencePayloadHash,
    EvidenceStorageRef,
)
from evidence.domain.value_objects.identifiers import (
    AttackActionRef,
    EngagementRef,
    OperationRef,
    TenantId,
)


def _tenant() -> TenantId:
    return TenantId(uuid7())


def _collect(tenant: TenantId, now: datetime, payload: bytes = b"hello") -> ExecutionEvidence:
    return ExecutionEvidence.collect(
        tenant_id=tenant,
        evidence_type=EvidenceType.COMMAND_OUTPUT,
        payload_hash=EvidencePayloadHash.from_payload(payload),
        storage_ref=EvidenceStorageRef("blob://e1"),
        encryption_key_ref=EvidenceEncryptionKeyRef("key-1", 1),
        action_ref=AttackActionRef(uuid7()),
        engagement_ref=EngagementRef(uuid7()),
        operation_ref=OperationRef(uuid7()),
        collected_by=CollectedBy("op-1"),
        retention_class=RetentionClass.STANDARD,
        now=now,
    )


def test_custody_transfer_appends_record() -> None:
    tenant = _tenant()
    now = datetime.now(UTC)
    ev = _collect(tenant, now)
    ev.transfer_custody(tenant, "analyst-2", CustodyAction.TRANSFERRED, now)
    assert len(ev.custody_chain) == 2
    assert ev.custody_chain[-1].custodian_identity == "analyst-2"


def test_verify_integrity_tamper_quarantines() -> None:
    tenant = _tenant()
    now = datetime.now(UTC)
    ev = _collect(tenant, now, b"original")
    with pytest.raises(EvidenceIntegrityViolation):
        ev.verify_integrity(
            tenant, EvidencePayloadHash.from_payload(b"tampered"), now
        )
    assert ev.quarantined is True


def test_retention_blocks_early_deletion() -> None:
    tenant = _tenant()
    now = datetime.now(UTC)
    ev = _collect(tenant, now)
    with pytest.raises(RetentionWindowActive):
        ev.request_deletion(tenant, now + timedelta(days=1))


def test_seal_requires_sealer_role() -> None:
    tenant = _tenant()
    now = datetime.now(UTC)
    op = OperationRef(uuid7())
    eng = EngagementRef(uuid7())
    chain = EvidenceChain.open(
        tenant_id=tenant,
        operation_ref=op,
        engagement_ref=eng,
        now=now,
    )
    ev = _collect(tenant, now)
    chain.add_entry(tenant, ev.evidence_id.value, ev.payload_hash.value, now)
    with pytest.raises(SealerRoleRequired):
        chain.seal(
            tenant_id=tenant,
            operator_id=uuid7(),
            sealer_role="redteam:admin",
            signature="sig",
            now=now,
        )
    chain.seal(
        tenant_id=tenant,
        operator_id=uuid7(),
        sealer_role=EVIDENCE_SEALER_ROLE,
        signature="sig",
        now=now,
    )
    assert chain.state.value == "Sealed"
