"""Shared factories for M28 Phase 4 tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from detection.domain.aggregates.detection_evidence import DetectionEvidence
from detection.domain.aggregates.detection_exception import DetectionException
from detection.domain.aggregates.detection_pack import DetectionPack
from detection.domain.value_objects.enums import (
    EvidenceType,
    ExceptionScopeKind,
    ExceptionType,
    PackCategory,
)
from detection.domain.value_objects.evidence import (
    EvidenceCollectedBy,
    EvidencePayloadHash,
    EvidenceStorageRef,
    FindingRef,
)
from detection.domain.value_objects.exception_vos import (
    AffectedRuleRefs,
    ExceptionJustification,
    ExceptionScope,
)
from detection.domain.value_objects.identifiers import TenantId
from detection.domain.value_objects.pack import PackKey, PackMaintainer
from tests.detection.phase3_helpers import make_finding


def make_tenant() -> TenantId:
    return TenantId(uuid4())


def make_pack(
    *,
    tenant_id: TenantId | None = None,
    pack_key: str = "ns.threat_pack",
    with_rule: bool = True,
    now: datetime | None = None,
) -> DetectionPack:
    tid = tenant_id or make_tenant()
    stamp = now or datetime.now(UTC)
    pack = DetectionPack.create(
        tenant_id=tid,
        pack_key=PackKey(pack_key),
        title="Threat Pack",
        category=PackCategory.THREAT_ACTOR_PACK,
        maintainer=PackMaintainer(identity="ops@example.com"),
        now=stamp,
    )
    if with_rule:
        pack.add_rule(tenant_id=tid, rule_id=str(uuid4()), now=stamp)
    return pack


def make_exception(
    *,
    tenant_id: TenantId | None = None,
    compliance_mapped: bool = False,
    acknowledged: bool = False,
    valid_hours: int = 24,
    now: datetime | None = None,
) -> DetectionException:
    tid = tenant_id or make_tenant()
    stamp = now or datetime.now(UTC)
    rule_id = str(uuid4())
    return DetectionException.request(
        tenant_id=tid,
        exception_type=ExceptionType.SUPPRESSION,
        scope=ExceptionScope(kind=ExceptionScopeKind.RULE, rule_id=rule_id),
        justification=ExceptionJustification(text="maintenance window"),
        requester="analyst@example.com",
        valid_until=stamp + timedelta(hours=valid_hours),
        affected_rules=AffectedRuleRefs(rule_ids=(rule_id,)),
        now=stamp,
        compliance_mapped=compliance_mapped,
        compliance_impact_acknowledged=acknowledged,
    )


def make_evidence(
    *,
    tenant_id: TenantId | None = None,
    payload: bytes = b"evidence-bytes",
    now: datetime | None = None,
) -> DetectionEvidence:
    tid = tenant_id or make_tenant()
    stamp = now or datetime.now(UTC)
    return DetectionEvidence.submit(
        tenant_id=tid,
        evidence_type=EvidenceType.TELEMETRY_SNAPSHOT,
        payload_hash=EvidencePayloadHash.from_payload(payload),
        storage_ref=EvidenceStorageRef(f"blob://{uuid4()}"),
        collected_by=EvidenceCollectedBy("system"),
        collected_at=stamp,
        now=stamp,
        finding_ref=FindingRef(str(uuid4())),
    )


__all__ = [
    "make_evidence",
    "make_exception",
    "make_finding",
    "make_pack",
    "make_tenant",
]
