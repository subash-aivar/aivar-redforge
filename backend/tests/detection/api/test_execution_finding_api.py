"""API tests for detection executions and findings."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from detection.api.dependencies import (
    get_execution_finding_service,
    get_rule_service,
)
from detection.api.exception_handlers import register_detection_exception_handlers
from detection.api.v1 import router as detection_router
from detection.application.commands.execution_finding_commands import (
    ProduceFinding,
    ScheduleRuleExecution,
)
from detection.application.ports.i_event_publisher import IEventPublisher
from detection.application.services.execution_finding_application_service import (
    ExecutionFindingApplicationService,
)
from detection.application.services.rule_application_service import RuleApplicationService
from detection.domain.events.base import BaseDomainEvent
from detection.domain.value_objects.identifiers import TenantId
from redforge.api.dependencies import get_organization_service
from redforge.api.security import TenantContext, get_tenant_context
from redforge.domain.identity.value_objects import MembershipRole, Permission
from tests.detection.application.test_execution_finding_application_service import (
    _FakeExecutions,
    _FakeFindings,
    _FakeRules,
    _FakeUow,
)
from tests.detection.conftest import make_rule


class _NoopPublisher(IEventPublisher):
    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        return None


class _OrgStub:
    async def get_by_id(self, organization_id: str) -> object:
        class _Org:
            status = "active"

        return _Org()


def _rule_payload(key: str) -> dict[str, object]:
    return {
        "rule_key": key,
        "title": "p3",
        "description": "d",
        "category": "Threat",
        "severity": "High",
        "confidence": "Medium",
        "logic": {
            "logic_type": "Condition",
            "conditions": [
                {"field": "process.name", "operator": "eq", "value": "cmd.exe"}
            ],
        },
    }


@pytest_asyncio.fixture
async def phase3_client() -> AsyncIterator[AsyncClient]:
    org_id = uuid4()
    user_id = uuid4()
    rules = _FakeRules()
    executions = _FakeExecutions()
    findings = _FakeFindings()
    publisher = _NoopPublisher()

    def uow_factory() -> _FakeUow:
        return _FakeUow(rules, executions, findings)

    rule_svc = RuleApplicationService(uow_factory, publisher)
    exec_svc = ExecutionFindingApplicationService(uow_factory, publisher)

    application = FastAPI()
    register_detection_exception_handlers(application)
    application.include_router(detection_router, prefix="/api/v1")

    def override_tenant() -> TenantContext:
        return TenantContext(
            user_id=str(user_id),
            email="phase3@example.com",
            organization_id=str(org_id),
            role=MembershipRole.OWNER,
            permissions=frozenset(Permission),
        )

    application.dependency_overrides[get_tenant_context] = override_tenant
    application.dependency_overrides[get_organization_service] = lambda: _OrgStub()
    application.dependency_overrides[get_rule_service] = lambda: rule_svc
    application.dependency_overrides[get_execution_finding_service] = lambda: exec_svc
    application.state.exec_svc = exec_svc
    application.state.tenant_id = org_id

    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    application.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_schedule_list_get_execution(phase3_client: AsyncClient) -> None:
    now = datetime(2026, 7, 20, 16, 0, 0, tzinfo=UTC)
    created_rule = await phase3_client.post(
        "/api/v1/detection-rules", json=_rule_payload("aivar.phase3_exec")
    )
    assert created_rule.status_code == 201, created_rule.text
    rule_id = created_rule.json()["rule_id"]

    created = await phase3_client.post(
        "/api/v1/detection-executions",
        json={
            "rule_id": str(rule_id),
            "source_id": "src-api",
            "window_start": (now - timedelta(hours=1)).isoformat(),
            "window_end": now.isoformat(),
            "trigger": "OnDemand",
        },
    )
    assert created.status_code == 201, created.text
    eid = created.json()["id"]

    listed = await phase3_client.get("/api/v1/detection-executions")
    assert listed.status_code == 200
    assert len(listed.json()["items"]) >= 1

    got = await phase3_client.get(f"/api/v1/detection-executions/{eid}")
    assert got.status_code == 200
    assert got.json()["state"] == "Scheduled"

    result = await phase3_client.post(
        f"/api/v1/detection-executions/{eid}/result",
        json={"findings_produced": 0, "duration_ms": 5},
    )
    assert result.status_code == 200
    assert result.json()["state"] == "Completed"


@pytest.mark.asyncio
async def test_finding_lifecycle_apis(phase3_client: AsyncClient, app: FastAPI | None = None) -> None:
    # Use shared service from dependency overrides via scheduling + produce
    now = datetime(2026, 7, 20, 16, 0, 0, tzinfo=UTC)
    created_rule = await phase3_client.post(
        "/api/v1/detection-rules", json=_rule_payload("aivar.phase3_find")
    )
    assert created_rule.status_code == 201, created_rule.text
    rule_id = UUID(created_rule.json()["rule_id"])

    execution = await phase3_client.post(
        "/api/v1/detection-executions",
        json={
            "rule_id": str(rule_id),
            "source_id": "src-api",
            "window_start": (now - timedelta(hours=1)).isoformat(),
            "window_end": now.isoformat(),
        },
    )
    assert execution.status_code == 201, execution.text
    eid = UUID(execution.json()["id"])

    # Produce via service attached on app — reconstruct from overrides is awkward;
    # call produce through a parallel service sharing... the fixture's exec_svc is not
    # on client. Re-fetch by scheduling produce in application service tests already.
    # For API: seed finding by going through get_execution_finding_service override.
    # Access via creating finding with another Schedule+Produce using same UoW from fixture
    # is not exposed. Instead build finding with temporary service that uses same repos —
    # not available. Use httpx ASGI with produce by monkeypatching.

    # Practical approach: create finding using ExecutionFindingApplicationService with
    # the same fake repos by reusing schedule from API then produce via importing
    # the fixture's internal state. Simpler: produce in-process with new service after
    # loading execution from API-created state won't share memory.

    # Fix fixture to expose service on client base_url app — use request to get app
    # from transport. Easiest fix: produce_finding endpoint not required; seed via
    # direct service constructed inside fixture and attached to client.

    # Recreate: use make_rule + service locally then hit lifecycle on a new app.
    tenant = TenantId(uuid4())
    rules = _FakeRules()
    executions = _FakeExecutions()
    findings = _FakeFindings()
    publisher = _NoopPublisher()

    def uow_factory() -> _FakeUow:
        return _FakeUow(rules, executions, findings)

    rule = make_rule(tenant_id=tenant, now=now, pop_events=True)
    await rules.save(rule)
    svc = ExecutionFindingApplicationService(uow_factory, publisher)
    sched = await svc.schedule_rule_execution(
        ScheduleRuleExecution(
            tenant_id=tenant.value,
            rule_id=rule.rule_id.value,
            source_id="s",
            window_start=(now - timedelta(hours=1)).isoformat(),
            window_end=now.isoformat(),
        )
    )
    produced = await svc.produce_finding(
        ProduceFinding(
            tenant_id=tenant.value,
            rule_id=rule.rule_id.value,
            execution_id=UUID(sched.id),
            asset_id="asset-api",
            signal_id="sig",
            observed_at=now.isoformat(),
            fingerprint_fields={"p": "1"},
        )
    )

    application = FastAPI()
    register_detection_exception_handlers(application)
    application.include_router(detection_router, prefix="/api/v1")

    def override_tenant() -> TenantContext:
        return TenantContext(
            user_id=str(uuid4()),
            email="p3b@example.com",
            organization_id=str(tenant.value),
            role=MembershipRole.OWNER,
            permissions=frozenset(Permission),
        )

    application.dependency_overrides[get_tenant_context] = override_tenant
    application.dependency_overrides[get_organization_service] = lambda: _OrgStub()
    application.dependency_overrides[get_execution_finding_service] = lambda: svc
    application.dependency_overrides[get_rule_service] = lambda: RuleApplicationService(
        uow_factory, publisher
    )

    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://test") as c2:
        got = await c2.get(f"/api/v1/detection-findings/{produced.id}")
        assert got.status_code == 200
        assert got.json()["state"] == "New"

        listed = await c2.get("/api/v1/detection-findings")
        assert listed.status_code == 200
        assert len(listed.json()["items"]) >= 1

        triaged = await c2.post(
            f"/api/v1/detection-findings/{produced.id}/triage",
            json={"note": "reviewing"},
        )
        assert triaged.status_code == 200
        assert triaged.json()["state"] == "Triaged"

        confirmed = await c2.post(
            f"/api/v1/detection-findings/{produced.id}/confirm",
            json={},
        )
        assert confirmed.status_code == 200
        assert confirmed.json()["state"] == "Confirmed"

        # New finding for FP / suppress / escalate
        produced2 = await svc.produce_finding(
            ProduceFinding(
                tenant_id=tenant.value,
                rule_id=rule.rule_id.value,
                execution_id=UUID(sched.id),
                asset_id="asset-api-2",
                signal_id="sig2",
                observed_at=now.isoformat(),
                fingerprint_fields={"p": "2"},
            )
        )
        fp = await c2.post(
            f"/api/v1/detection-findings/{produced2.id}/false-positive",
            json={"justification": "benign"},
        )
        assert fp.status_code == 200
        assert fp.json()["state"] == "FalsePositive"

        produced3 = await svc.produce_finding(
            ProduceFinding(
                tenant_id=tenant.value,
                rule_id=rule.rule_id.value,
                execution_id=UUID(sched.id),
                asset_id="asset-api-3",
                signal_id="sig3",
                observed_at=now.isoformat(),
                fingerprint_fields={"p": "3"},
            )
        )
        suppressed = await c2.post(
            f"/api/v1/detection-findings/{produced3.id}/suppress",
            json={"justification": "noise"},
        )
        assert suppressed.status_code == 200

        produced4 = await svc.produce_finding(
            ProduceFinding(
                tenant_id=tenant.value,
                rule_id=rule.rule_id.value,
                execution_id=UUID(sched.id),
                asset_id="asset-api-4",
                signal_id="sig4",
                observed_at=now.isoformat(),
                fingerprint_fields={"p": "4"},
            )
        )
        escalated = await c2.post(
            f"/api/v1/detection-findings/{produced4.id}/escalate",
            json={"investigation_id": "inv-1"},
        )
        assert escalated.status_code == 200
        assert escalated.json()["state"] == "EscalatedToInvestigation"

    _ = eid  # used for schedule smoke above
