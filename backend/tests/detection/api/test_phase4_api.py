"""API tests for Phase 4 pack/exception/evidence/coverage/correlate."""

from __future__ import annotations

import base64
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Self
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from detection.api.dependencies import (
    get_correlation_coordinator,
    get_execution_finding_service,
    get_phase4_service,
    get_rule_service,
)
from detection.api.exception_handlers import register_detection_exception_handlers
from detection.api.v1 import router as detection_router
from detection.application.ports.i_event_publisher import IEventPublisher
from detection.application.ports.i_unit_of_work import IUnitOfWork
from detection.application.services.correlation_coordinator import CorrelationCoordinator
from detection.application.services.correlation_publisher import CorrelationPublisher
from detection.application.services.execution_finding_application_service import (
    ExecutionFindingApplicationService,
)
from detection.application.services.phase4_application_service import (
    PackExceptionEvidenceApplicationService,
)
from detection.application.services.rule_application_service import RuleApplicationService
from detection.domain.events.base import BaseDomainEvent
from detection.domain.services.correlation import CorrelationService
from detection.infrastructure.acl.degraded_adapters import (
    BehavioralSignalAdapter,
    CloudContextAdapter,
    ComplianceAdapter,
    InventoryAdapter,
    ThreatIntelAdapter,
    VulnerabilityContextAdapter,
)
from detection.infrastructure.blob.in_memory_evidence_blob_store import (
    InMemoryEvidenceBlobStore,
)
from redforge.api.dependencies import get_organization_service
from redforge.api.security import TenantContext, get_tenant_context
from redforge.domain.identity.value_objects import MembershipRole, Permission
from tests.detection.application.test_execution_finding_application_service import (
    _FakeExecutions,
    _FakeFindings,
    _FakeRules,
)
from tests.detection.application.test_execution_finding_application_service import (
    _FakeUow as _P3Uow,
)
from tests.detection.application.test_phase4_application_service import (
    _FakeEvidence,
    _FakeExceptions,
    _FakePacks,
)
from tests.detection.application.test_phase4_application_service import (
    _FakeUow as _P4Uow,
)
from tests.detection.phase3_helpers import make_finding


class _NoopPublisher(IEventPublisher):
    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        return None


class _OrgStub:
    async def get_by_id(self, organization_id: str) -> object:
        class _Org:
            status = "active"

        return _Org()


class _CombinedUow(IUnitOfWork):
    def __init__(self, p3: _P3Uow, p4: _P4Uow) -> None:
        super().__init__()
        self.detection_rules = p3.detection_rules
        self.telemetry_sources = p3.telemetry_sources
        self.detection_executions = p3.detection_executions
        self.detection_findings = p3.detection_findings
        self.detection_packs = p4.detection_packs
        self.detection_exceptions = p4.detection_exceptions
        self.detection_evidence = p4.detection_evidence

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        if not self._committed:
            await self.rollback()

    async def commit(self) -> None:
        self._committed = True

    async def rollback(self) -> None:
        self._committed = False


@pytest_asyncio.fixture
async def phase4_client() -> AsyncIterator[AsyncClient]:
    org_id = uuid4()
    user_id = uuid4()
    rules = _FakeRules()
    executions = _FakeExecutions()
    findings = _FakeFindings()
    packs = _FakePacks()
    exceptions = _FakeExceptions()
    evidence = _FakeEvidence()
    publisher = _NoopPublisher()
    blob = InMemoryEvidenceBlobStore()

    def uow_factory():
        p3 = _P3Uow(rules, executions, findings)
        p4 = _P4Uow(packs, exceptions, evidence, rules=rules, findings=findings)
        return _CombinedUow(p3, p4)

    phase4 = PackExceptionEvidenceApplicationService(uow_factory, publisher, blob)
    exec_svc = ExecutionFindingApplicationService(uow_factory, publisher)
    rule_svc = RuleApplicationService(uow_factory, publisher)
    corr = CorrelationService(
        InventoryAdapter(),
        CloudContextAdapter(),
        VulnerabilityContextAdapter(),
        ThreatIntelAdapter(),
        ComplianceAdapter(),
        BehavioralSignalAdapter(),
    )
    coordinator = CorrelationCoordinator(
        uow_factory, corr, CorrelationPublisher(publisher)
    )

    app = FastAPI()
    register_detection_exception_handlers(app)
    app.include_router(detection_router, prefix="/api/v1")

    async def _tenant() -> TenantContext:
        return TenantContext(
            user_id=str(user_id),
            email="phase4@example.com",
            organization_id=str(org_id),
            role=MembershipRole.OWNER,
            permissions=frozenset(Permission),
        )

    app.dependency_overrides[get_tenant_context] = _tenant
    app.dependency_overrides[get_organization_service] = lambda: _OrgStub()
    app.dependency_overrides[get_phase4_service] = lambda: phase4
    app.dependency_overrides[get_execution_finding_service] = lambda: exec_svc
    app.dependency_overrides[get_rule_service] = lambda: rule_svc
    app.dependency_overrides[get_correlation_coordinator] = lambda: coordinator

    # seed a finding for correlate
    finding = make_finding(tenant_id=__import__("detection.domain.value_objects.identifiers", fromlist=["TenantId"]).TenantId(org_id), now=datetime.now(UTC))
    await findings.save(finding)
    app.state.seed_finding_id = str(finding.finding_id)
    app.state.org_id = org_id

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        client.app = app  # type: ignore[attr-defined]
        yield client


@pytest.mark.asyncio
async def test_pack_api_flow(phase4_client: AsyncClient) -> None:
    client = phase4_client
    create = await client.post(
        "/api/v1/detection-packs",
        json={
            "pack_key": "ns.api_pack",
            "title": "API Pack",
            "category": "ThreatActorPack",
            "maintainer": "ops",
            "rule_ids": [str(uuid4())],
        },
    )
    assert create.status_code == 201, create.text
    pack_id = create.json()["pack_id"]
    pub = await client.post(f"/api/v1/detection-packs/{pack_id}/publish")
    assert pub.status_code == 200
    sub = await client.post(
        f"/api/v1/detection-packs/{pack_id}/subscribe",
        json={"subscriber_tenant_id": str(uuid4())},
    )
    assert sub.status_code == 200
    listing = await client.get("/api/v1/detection-packs")
    assert listing.status_code == 200
    assert listing.json()["total"] >= 1


@pytest.mark.asyncio
async def test_exception_api_flow(phase4_client: AsyncClient) -> None:
    client = phase4_client
    rid = str(uuid4())
    until = (datetime.now(UTC) + timedelta(days=2)).isoformat()
    create = await client.post(
        "/api/v1/detection-exceptions",
        json={
            "exception_type": "Suppression",
            "scope_kind": "Rule",
            "justification": "ok",
            "requester": "a",
            "valid_until": until,
            "affected_rule_ids": [rid],
            "rule_id": rid,
        },
    )
    assert create.status_code == 201, create.text
    eid = create.json()["exception_id"]
    approve = await client.post(
        f"/api/v1/detection-exceptions/{eid}/approve", json={"approver": "boss"}
    )
    assert approve.status_code == 200
    assert approve.json()["state"] == "Active"


@pytest.mark.asyncio
async def test_evidence_and_coverage_and_correlate(phase4_client: AsyncClient) -> None:
    client = phase4_client
    payload = base64.b64encode(b"hello-evidence").decode()
    ev = await client.post(
        "/api/v1/detection-evidence",
        json={
            "evidence_type": "TelemetrySnapshot",
            "payload_b64": payload,
            "collected_by": "sys",
            "finding_id": str(uuid4()),
        },
    )
    assert ev.status_code == 201, ev.text
    eid = ev.json()["evidence_id"]
    verify = await client.post(f"/api/v1/detection-evidence/{eid}/verify")
    assert verify.status_code == 200
    assert verify.json()["integrity_status"] == "Verified"

    cov = await client.get("/api/v1/detection-coverage")
    assert cov.status_code == 200

    fid = client.app.state.seed_finding_id  # type: ignore[attr-defined]
    corr = await client.post(
        f"/api/v1/detection-findings/{fid}/correlate", json={"refresh": True}
    )
    assert corr.status_code == 200, corr.text
    assert corr.json()["status"] in {"Completed", "Partial", "Failed"}
