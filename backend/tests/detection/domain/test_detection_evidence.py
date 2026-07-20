"""DetectionEvidence aggregate tests — Phase 4."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from detection.domain.events.evidence_events import (
    DetectionEvidenceIntegrityFailed,
    DetectionEvidenceIntegrityVerified,
    DetectionEvidenceSubmitted,
)
from detection.domain.exceptions.domain_exceptions import EvidenceImmutable, InvalidArgument
from detection.domain.value_objects.enums import EvidenceIntegrityStatus, EvidenceType
from detection.domain.value_objects.evidence import EvidencePayloadHash
from tests.detection.phase4_helpers import make_evidence


def test_submit_emits_event() -> None:
    ev = make_evidence()
    assert ev.integrity_status == EvidenceIntegrityStatus.UNKNOWN
    assert any(isinstance(e, DetectionEvidenceSubmitted) for e in ev.pop_events())


def test_verify_success_and_tamper() -> None:
    payload = b"good-payload"
    ev = make_evidence(payload=payload)
    status = ev.verify_integrity(
        tenant_id=ev.tenant_id, actual_payload=payload, now=datetime.now(UTC)
    )
    assert status == EvidenceIntegrityStatus.VERIFIED
    assert any(isinstance(e, DetectionEvidenceIntegrityVerified) for e in ev.pop_events())

    ev2 = make_evidence(payload=payload)
    status2 = ev2.verify_integrity(
        tenant_id=ev2.tenant_id, actual_payload=b"bad", now=datetime.now(UTC)
    )
    assert status2 == EvidenceIntegrityStatus.TAMPERED
    assert any(isinstance(e, DetectionEvidenceIntegrityFailed) for e in ev2.pop_events())


def test_immutable_payload() -> None:
    ev = make_evidence()
    with pytest.raises(EvidenceImmutable):
        ev.replace_payload(b"x")


def test_requires_ref() -> None:
    from detection.domain.aggregates.detection_evidence import DetectionEvidence
    from detection.domain.value_objects.evidence import (
        EvidenceCollectedBy,
        EvidenceStorageRef,
    )
    from tests.detection.phase4_helpers import make_tenant

    tid = make_tenant()
    now = datetime.now(UTC)
    with pytest.raises(InvalidArgument):
        DetectionEvidence.submit(
            tenant_id=tid,
            evidence_type=EvidenceType.ANALYST_ANNOTATION,
            payload_hash=EvidencePayloadHash.from_payload(b"x"),
            storage_ref=EvidenceStorageRef("blob://x"),
            collected_by=EvidenceCollectedBy("a"),
            collected_at=now,
            now=now,
        )


@pytest.mark.parametrize("etype", list(EvidenceType))
def test_all_evidence_types(etype: EvidenceType) -> None:
    from detection.domain.aggregates.detection_evidence import DetectionEvidence
    from detection.domain.value_objects.evidence import (
        EvidenceCollectedBy,
        EvidenceStorageRef,
        FindingRef,
    )
    from tests.detection.phase4_helpers import make_tenant

    tid = make_tenant()
    now = datetime.now(UTC)
    ev = DetectionEvidence.submit(
        tenant_id=tid,
        evidence_type=etype,
        payload_hash=EvidencePayloadHash.from_payload(b"x"),
        storage_ref=EvidenceStorageRef(f"blob://{uuid4()}"),
        collected_by=EvidenceCollectedBy("a"),
        collected_at=now,
        now=now,
        finding_ref=FindingRef(str(uuid4())),
    )
    assert ev.evidence_type == etype


@pytest.mark.parametrize("i", range(30))
def test_hash_stable(i: int) -> None:
    payload = f"payload-{i}".encode()
    h1 = EvidencePayloadHash.from_payload(payload)
    h2 = EvidencePayloadHash.from_payload(payload)
    assert h1.value == h2.value
