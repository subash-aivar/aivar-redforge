"""Bulk Phase 4 coverage tests to lock invariants."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from detection.domain.value_objects.enums import (
    EvidenceType,
    ExceptionType,
    PackCategory,
    PackLifecycleState,
)
from detection.domain.value_objects.evidence import EvidencePayloadHash, EvidenceStorageRef
from detection.domain.value_objects.exception_vos import ExceptionApprover
from detection.domain.value_objects.pack import CoverageMatrix, PackKey
from detection.infrastructure.blob.in_memory_evidence_blob_store import (
    InMemoryEvidenceBlobStore,
)
from tests.detection.phase4_helpers import make_evidence, make_exception, make_pack


@pytest.mark.parametrize("i", range(50))
def test_pack_lifecycle_matrix(i: int) -> None:
    pack = make_pack(pack_key=f"ns.bulk{i}")
    assert pack.lifecycle_state == PackLifecycleState.DRAFT
    pack.publish(tenant_id=pack.tenant_id, now=datetime.now(UTC))
    assert pack.lifecycle_state == PackLifecycleState.PUBLISHED


@pytest.mark.parametrize("i", range(40))
def test_exception_approve_revoke_matrix(i: int) -> None:
    now = datetime.now(UTC)
    exc = make_exception(now=now, valid_hours=i + 1)
    exc.approve(tenant_id=exc.tenant_id, approver=ExceptionApprover("a"), now=now)
    exc.revoke(tenant_id=exc.tenant_id, revoker="a", reason=f"r{i}", now=now)
    assert exc.state.value == "Revoked"


@pytest.mark.parametrize("i", range(40))
@pytest.mark.asyncio
async def test_blob_store_roundtrip(i: int) -> None:
    store = InMemoryEvidenceBlobStore()
    payload = f"p{i}".encode()
    ref = EvidenceStorageRef(f"blob://t/{i}")
    await store.put(ref, payload)
    assert await store.exists(ref)
    assert await store.get(ref) == payload
    assert store.hash_payload(payload).value == EvidencePayloadHash.from_payload(payload).value


@pytest.mark.parametrize("cat", list(PackCategory))
def test_pack_categories_enum(cat: PackCategory) -> None:
    assert cat.value


@pytest.mark.parametrize("etype", list(ExceptionType))
def test_exception_types_enum(etype: ExceptionType) -> None:
    assert etype.value


@pytest.mark.parametrize("etype", list(EvidenceType))
def test_evidence_types_enum(etype: EvidenceType) -> None:
    assert etype.value


def test_coverage_matrix_from_map() -> None:
    m = CoverageMatrix.from_technique_map({"T1059": ["r1", "r2"], "T1003": ["r3"]})
    assert len(m.entries) == 2
    assert m.to_dict()["entries"][0]["rule_count"] >= 1


@pytest.mark.parametrize("i", range(20))
def test_evidence_verify_matrix(i: int) -> None:
    payload = f"ev{i}".encode()
    ev = make_evidence(payload=payload)
    status = ev.verify_integrity(
        tenant_id=ev.tenant_id, actual_payload=payload, now=datetime.now(UTC)
    )
    assert status.value == "Verified"


def test_pack_key_roundtrip() -> None:
    assert str(PackKey("acme.cloud_pack")) == "acme.cloud_pack"
