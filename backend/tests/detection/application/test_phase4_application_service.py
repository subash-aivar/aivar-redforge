"""Phase 4 application service tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Self
from uuid import uuid4

import pytest

from detection.application.commands.phase4_commands import (
    ApproveDetectionException,
    ComputeDetectionCoverage,
    CreateDetectionPack,
    PublishDetectionPack,
    RejectDetectionException,
    RenewDetectionException,
    RequestDetectionException,
    RevokeDetectionException,
    SubmitEvidence,
    SubscribePackToTenant,
    VerifyEvidenceIntegrity,
)
from detection.application.exceptions import ApplicationValidationError
from detection.application.ports.i_event_publisher import IEventPublisher
from detection.application.ports.i_unit_of_work import IUnitOfWork
from detection.application.services.phase4_application_service import (
    PackExceptionEvidenceApplicationService,
)
from detection.domain.events.base import BaseDomainEvent
from detection.infrastructure.blob.in_memory_evidence_blob_store import (
    InMemoryEvidenceBlobStore,
)
from tests.detection.application.test_execution_finding_application_service import (
    _FakeFindings,
    _FakeRules,
)


class _FakePacks:
    def __init__(self) -> None:
        self.by_id: dict = {}
        self.by_key: dict = {}

    async def save(self, pack) -> None:
        self.by_id[(pack.pack_id.value, pack.tenant_id.value)] = pack
        self.by_key[(str(pack.pack_key), pack.tenant_id.value)] = pack

    async def find_by_id(self, pack_id, tenant_id):
        return self.by_id.get((pack_id.value, tenant_id.value))

    async def find_by_pack_key(self, pack_key, tenant_id):
        return self.by_key.get((str(pack_key), tenant_id.value))

    async def find_active_by_tenant(self, tenant_id, *, limit=100, offset=0):
        items = [p for p in self.by_id.values() if p.tenant_id == tenant_id]
        return items[offset : offset + limit]

    async def find_by_compliance_framework(self, framework_ref, tenant_id, *, limit=100, offset=0):
        return []

    async def list_by_tenant(self, tenant_id, *, limit=100, offset=0):
        items = [p for p in self.by_id.values() if p.tenant_id == tenant_id]
        return items[offset : offset + limit]


class _FakeExceptions:
    def __init__(self) -> None:
        self.by_id: dict = {}

    async def save(self, exception) -> None:
        self.by_id[(exception.exception_id.value, exception.tenant_id.value)] = exception

    async def find_by_id(self, exception_id, tenant_id):
        return self.by_id.get((exception_id.value, tenant_id.value))

    async def find_active_by_tenant(self, tenant_id, *, limit=100, offset=0):
        return []

    async def find_pending_by_tenant(self, tenant_id, *, limit=100, offset=0):
        return []

    async def find_expired_candidates(self, tenant_id, as_of, *, limit=100, offset=0):
        return []

    async def list_by_tenant(self, tenant_id, *, limit=100, offset=0):
        items = [e for e in self.by_id.values() if e.tenant_id == tenant_id]
        return items[offset : offset + limit]


class _FakeEvidence:
    def __init__(self) -> None:
        self.by_id: dict = {}

    async def save(self, evidence) -> None:
        self.by_id[(evidence.evidence_id.value, evidence.tenant_id.value)] = evidence

    async def find_by_id(self, evidence_id, tenant_id):
        return self.by_id.get((evidence_id.value, tenant_id.value))

    async def find_by_finding(self, finding_id, tenant_id, *, limit=100, offset=0):
        return []

    async def find_by_exception(self, exception_id, tenant_id, *, limit=100, offset=0):
        return []

    async def list_by_tenant(self, tenant_id, *, limit=100, offset=0):
        return list(self.by_id.values())[offset : offset + limit]


class _FakeUow(IUnitOfWork):
    def __init__(self, packs, exceptions, evidence, rules=None, findings=None) -> None:
        super().__init__()
        self.detection_packs = packs
        self.detection_exceptions = exceptions
        self.detection_evidence = evidence
        self.detection_rules = rules or _FakeRules()
        self.detection_findings = findings or _FakeFindings()
        self.telemetry_sources = None  # type: ignore[assignment]
        self.detection_executions = None  # type: ignore[assignment]

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        if not self._committed:
            await self.rollback()

    async def commit(self) -> None:
        self._committed = True

    async def rollback(self) -> None:
        self._committed = False


class _Pub(IEventPublisher):
    def __init__(self) -> None:
        self.batches: list[list[BaseDomainEvent]] = []

    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        self.batches.append(list(events))


def _svc():
    packs, excs, evid = _FakePacks(), _FakeExceptions(), _FakeEvidence()
    blob = InMemoryEvidenceBlobStore()
    pub = _Pub()

    def factory():
        return _FakeUow(packs, excs, evid)

    return PackExceptionEvidenceApplicationService(factory, pub, blob), packs, excs, evid, blob, pub


@pytest.mark.asyncio
async def test_create_publish_subscribe_pack() -> None:
    svc, _packs, *_ = _svc()
    tid = uuid4()
    dto = await svc.create_detection_pack(
        CreateDetectionPack(
            tenant_id=tid,
            pack_key="ns.phase4pack",
            title="P",
            category="ThreatActorPack",
            maintainer="m",
            rule_ids=[str(uuid4())],
        )
    )
    assert dto.lifecycle_state == "Draft"
    published = await svc.publish_detection_pack(
        PublishDetectionPack(tenant_id=tid, pack_id=__import__("uuid").UUID(dto.pack_id))
    )
    assert published.lifecycle_state == "Published"
    sub = await svc.subscribe_pack_to_tenant(
        SubscribePackToTenant(
            tenant_id=tid,
            pack_id=__import__("uuid").UUID(dto.pack_id),
            subscriber_tenant_id=str(uuid4()),
        )
    )
    assert sub.subscribed_tenants


@pytest.mark.asyncio
async def test_exception_lifecycle_app() -> None:
    svc, *_ = _svc()
    tid = uuid4()
    until = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    rid = str(uuid4())
    dto = await svc.request_detection_exception(
        RequestDetectionException(
            tenant_id=tid,
            exception_type="Suppression",
            scope_kind="Rule",
            justification="ok",
            requester="a",
            valid_until=until,
            affected_rule_ids=[rid],
            rule_id=rid,
        )
    )
    eid = __import__("uuid").UUID(dto.exception_id)
    approved = await svc.approve_detection_exception(
        ApproveDetectionException(tenant_id=tid, exception_id=eid, approver="boss")
    )
    assert approved.state == "Active"
    renewed = await svc.renew_detection_exception(
        RenewDetectionException(
            tenant_id=tid,
            exception_id=eid,
            renewer="boss",
            new_valid_until=(datetime.now(UTC) + timedelta(days=7)).isoformat(),
        )
    )
    assert renewed.state == "Active"
    revoked = await svc.revoke_detection_exception(
        RevokeDetectionException(
            tenant_id=tid, exception_id=eid, revoker="boss", reason="done"
        )
    )
    assert revoked.state == "Revoked"


@pytest.mark.asyncio
async def test_reject_exception() -> None:
    svc, *_ = _svc()
    tid = uuid4()
    until = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    rid = str(uuid4())
    dto = await svc.request_detection_exception(
        RequestDetectionException(
            tenant_id=tid,
            exception_type="RiskAccepted",
            scope_kind="Rule",
            justification="ok",
            requester="a",
            valid_until=until,
            affected_rule_ids=[rid],
            rule_id=rid,
        )
    )
    rejected = await svc.reject_detection_exception(
        RejectDetectionException(
            tenant_id=tid,
            exception_id=__import__("uuid").UUID(dto.exception_id),
            rejector="boss",
            reason="nope",
        )
    )
    assert rejected.state == "Rejected"


@pytest.mark.asyncio
async def test_compliance_ack_required() -> None:
    svc, *_ = _svc()
    tid = uuid4()
    until = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    rid = str(uuid4())
    with pytest.raises(ApplicationValidationError):
        await svc.request_detection_exception(
            RequestDetectionException(
                tenant_id=tid,
                exception_type="Suppression",
                scope_kind="Rule",
                justification="ok",
                requester="a",
                valid_until=until,
                affected_rule_ids=[rid],
                rule_id=rid,
                compliance_mapped=True,
                compliance_impact_acknowledged=False,
            )
        )


@pytest.mark.asyncio
async def test_submit_and_verify_evidence() -> None:
    svc, *_ = _svc()
    tid = uuid4()
    dto = await svc.submit_evidence(
        SubmitEvidence(
            tenant_id=tid,
            evidence_type="TelemetrySnapshot",
            payload=b"abc123",
            collected_by="sys",
            finding_id=str(uuid4()),
        )
    )
    assert dto.integrity_status == "Unknown"
    verified = await svc.verify_evidence_integrity(
        VerifyEvidenceIntegrity(
            tenant_id=tid, evidence_id=__import__("uuid").UUID(dto.evidence_id)
        )
    )
    assert verified.integrity_status == "Verified"


@pytest.mark.asyncio
async def test_compute_coverage() -> None:
    svc, *_ = _svc()
    tid = uuid4()
    report = await svc.compute_detection_coverage(
        ComputeDetectionCoverage(tenant_id=tid, in_scope_techniques=["T1059", "T1003"])
    )
    assert report.gap_count == 2
    assert report.total_in_scope == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("i", range(20))
async def test_create_pack_variants(i: int) -> None:
    svc, *_ = _svc()
    dto = await svc.create_detection_pack(
        CreateDetectionPack(
            tenant_id=uuid4(),
            pack_key=f"ns.variant{i}",
            title=f"T{i}",
            category="CustomPack",
            maintainer="m",
            rule_ids=[str(uuid4())],
        )
    )
    assert dto.pack_key.endswith(str(i))
