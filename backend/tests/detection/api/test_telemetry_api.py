"""API tests for telemetry sources and rule simulation endpoints."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from types import TracebackType
from typing import Self
from uuid import UUID

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from detection.api.dependencies import get_rule_service, get_telemetry_service
from detection.api.exception_handlers import register_detection_exception_handlers
from detection.api.v1 import router as detection_router
from detection.application.ports.i_event_publisher import IEventPublisher
from detection.application.ports.i_unit_of_work import IUnitOfWork
from detection.application.services.rule_application_service import RuleApplicationService
from detection.application.services.telemetry_application_service import (
    TelemetryApplicationService,
)
from detection.domain.aggregates.detection_rule import DetectionRule
from detection.domain.aggregates.telemetry_source import TelemetrySource
from detection.domain.events.base import BaseDomainEvent
from detection.domain.providers.registry import TelemetryProviderRegistry
from detection.domain.repositories.i_detection_rule_repository import (
    IDetectionRuleRepository,
)
from detection.domain.repositories.i_telemetry_source_repository import (
    ITelemetrySourceRepository,
)
from detection.domain.value_objects.enums import RuleLifecycleState, SourceType
from detection.domain.value_objects.identifiers import (
    DetectionRuleId,
    TelemetrySourceId,
    TenantId,
)
from detection.domain.value_objects.keys import RuleKey
from redforge.api.dependencies import get_organization_service
from redforge.api.security import TenantContext, get_tenant_context
from redforge.domain.identity.value_objects import MembershipRole, Permission
from redforge.shared.identifiers import EntityId
from tests.detection.application.test_telemetry_application_service import _FakeQueryPort
from tests.detection.phase2_helpers import StubTelemetryAdapter


class _FakeRuleRepo(IDetectionRuleRepository):
    def __init__(self) -> None:
        self.by_id: dict[tuple[UUID, UUID], DetectionRule] = {}
        self.by_key: dict[tuple[str, UUID], DetectionRule] = {}

    async def save(self, rule: DetectionRule) -> None:
        self.by_id[(rule.rule_id.value, rule.tenant_id.value)] = rule
        self.by_key[(rule.rule_key.value, rule.tenant_id.value)] = rule

    async def find_by_id(
        self, rule_id: DetectionRuleId, tenant_id: TenantId
    ) -> DetectionRule | None:
        return self.by_id.get((rule_id.value, tenant_id.value))

    async def find_by_key(
        self, key: RuleKey, tenant_id: TenantId
    ) -> DetectionRule | None:
        return self.by_key.get((key.value, tenant_id.value))

    async def find_active_by_tenant(self, tenant_id: TenantId) -> list[DetectionRule]:
        return [
            r
            for (_, tid), r in self.by_id.items()
            if tid == tenant_id.value and r.lifecycle_state == RuleLifecycleState.ACTIVE
        ]

    async def find_by_lifecycle_state(
        self, tenant_id: TenantId, state: RuleLifecycleState
    ) -> list[DetectionRule]:
        return [
            r
            for (_, tid), r in self.by_id.items()
            if tid == tenant_id.value and r.lifecycle_state == state
        ]

    async def find_by_telemetry_source(
        self, tenant_id: TenantId, source_id: str
    ) -> list[DetectionRule]:
        return []

    async def find_by_attack_technique(
        self, tenant_id: TenantId, technique_id: str
    ) -> list[DetectionRule]:
        return []

    async def list_by_tenant(
        self, tenant_id: TenantId, *, limit: int = 100, offset: int = 0
    ) -> list[DetectionRule]:
        items = [r for (_, tid), r in self.by_id.items() if tid == tenant_id.value]
        return items[offset : offset + limit]


class _FakeSourceRepo(ITelemetrySourceRepository):
    def __init__(self) -> None:
        self.by_id: dict[tuple[UUID, UUID], TelemetrySource] = {}
        self.by_name: dict[tuple[str, UUID], TelemetrySource] = {}

    async def save(self, source: TelemetrySource) -> None:
        self.by_id[(source.source_id.value, source.tenant_id.value)] = source
        self.by_name[(source.name, source.tenant_id.value)] = source

    async def find_by_id(
        self, source_id: TelemetrySourceId, tenant_id: TenantId
    ) -> TelemetrySource | None:
        return self.by_id.get((source_id.value, tenant_id.value))

    async def find_by_name(
        self, name: str, tenant_id: TenantId
    ) -> TelemetrySource | None:
        return self.by_name.get((name, tenant_id.value))

    async def find_active_by_tenant(
        self, tenant_id: TenantId
    ) -> list[TelemetrySource]:
        return [
            s
            for (_, tid), s in self.by_id.items()
            if tid == tenant_id.value and s.is_active
        ]

    async def find_by_type(
        self, source_type: SourceType, tenant_id: TenantId
    ) -> list[TelemetrySource]:
        return [
            s
            for (_, tid), s in self.by_id.items()
            if tid == tenant_id.value and s.source_type == source_type
        ]

    async def list_by_tenant(
        self, tenant_id: TenantId, *, limit: int = 100, offset: int = 0
    ) -> list[TelemetrySource]:
        items = [s for (_, tid), s in self.by_id.items() if tid == tenant_id.value]
        return items[offset : offset + limit]


class _FakeUow(IUnitOfWork):
    def __init__(self, rules: _FakeRuleRepo, sources: _FakeSourceRepo) -> None:
        super().__init__()
        self.detection_rules = rules
        self.telemetry_sources = sources
        self.detection_executions = None  # type: ignore[assignment]
        self.detection_findings = None  # type: ignore[assignment]
        self.detection_packs = None  # type: ignore[assignment]
        self.detection_exceptions = None  # type: ignore[assignment]
        self.detection_evidence = None  # type: ignore[assignment]

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if not self._committed:
            await self.rollback()

    async def commit(self) -> None:
        self._committed = True

    async def rollback(self) -> None:
        self._committed = False


class _NoopPublisher(IEventPublisher):
    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        return None


class _OrgStub:
    async def get_by_id(self, organization_id: str) -> object:
        class _Org:
            status = "active"

        return _Org()


def _source_payload(name: str = "api-source") -> dict[str, object]:
    return {
        "name": name,
        "source_type": "CustomPush",
        "trust_level": "Secondary",
        "schema_version": "1.0.0",
        "fields": [
            {"path": "process.name", "data_type": "string"},
            {"path": "event.event_type", "data_type": "string"},
            {"path": "event.event_time", "data_type": "timestamp"},
            {"path": "process.command_line", "data_type": "string"},
            {"path": "actor.user_name", "data_type": "string"},
        ],
        "adapter_key": "framework.stub",
        "tenant_scope_assertion": "account=test",
        "latency_expected_seconds": 30,
        "retention_seconds": 2592000,
    }


def _rule_payload(key: str = "aivar.api_sim_rule") -> dict[str, object]:
    return {
        "rule_key": key,
        "title": "API sim rule",
        "description": "test",
        "category": "Threat",
        "severity": "High",
        "confidence": "Medium",
        "logic": {
            "logic_type": "Condition",
            "conditions": [
                {
                    "field": "process.name",
                    "operator": "eq",
                    "value": "cmd.exe",
                    "connector": None,
                    "children": [],
                }
            ],
        },
    }


@pytest_asyncio.fixture
async def phase2_client() -> AsyncIterator[AsyncClient]:
    org_id = EntityId.generate()
    user_id = EntityId.generate()
    rules = _FakeRuleRepo()
    sources = _FakeSourceRepo()
    registry = TelemetryProviderRegistry()
    registry.register(StubTelemetryAdapter())

    def uow_factory() -> _FakeUow:
        return _FakeUow(rules, sources)

    publisher = _NoopPublisher()
    rule_svc = RuleApplicationService(uow_factory, publisher)
    telemetry_svc = TelemetryApplicationService(
        uow_factory,
        publisher,
        registry,
        _FakeQueryPort(),  # type: ignore[arg-type]
    )

    application = FastAPI()
    register_detection_exception_handlers(application)
    application.include_router(detection_router, prefix="/api/v1")

    def override_tenant() -> TenantContext:
        return TenantContext(
            user_id=str(user_id),
            email="phase2@example.com",
            organization_id=str(org_id),
            role=MembershipRole.OWNER,
            permissions=frozenset(Permission),
        )

    application.dependency_overrides[get_tenant_context] = override_tenant
    application.dependency_overrides[get_organization_service] = lambda: _OrgStub()
    application.dependency_overrides[get_rule_service] = lambda: rule_svc
    application.dependency_overrides[get_telemetry_service] = lambda: telemetry_svc

    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    application.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_register_list_get_source(phase2_client: AsyncClient) -> None:
    created = await phase2_client.post(
        "/api/v1/telemetry-sources", json=_source_payload()
    )
    assert created.status_code == 201, created.text
    source_id = created.json()["id"]

    listed = await phase2_client.get("/api/v1/telemetry-sources")
    assert listed.status_code == 200
    assert len(listed.json()["items"]) >= 1

    got = await phase2_client.get(f"/api/v1/telemetry-sources/{source_id}")
    assert got.status_code == 200
    assert got.json()["name"] == "api-source"


@pytest.mark.asyncio
async def test_patch_deactivate_source(phase2_client: AsyncClient) -> None:
    created = await phase2_client.post(
        "/api/v1/telemetry-sources", json=_source_payload("to-deactivate")
    )
    source_id = created.json()["id"]
    patched = await phase2_client.patch(
        f"/api/v1/telemetry-sources/{source_id}",
        json={"deactivate_reason": "end of life"},
    )
    assert patched.status_code == 200
    assert patched.json()["lifecycle_state"] == "Deactivated"


@pytest.mark.asyncio
async def test_validate_source(phase2_client: AsyncClient) -> None:
    created = await phase2_client.post(
        "/api/v1/telemetry-sources", json=_source_payload("validate-me")
    )
    source_id = created.json()["id"]
    result = await phase2_client.post(f"/api/v1/telemetry-sources/{source_id}/validate")
    assert result.status_code == 200
    body = result.json()
    assert body["provider_registered"] is True
    assert body["schema_version_valid"] is True


@pytest.mark.asyncio
async def test_validate_schema_and_simulate(phase2_client: AsyncClient) -> None:
    source = await phase2_client.post(
        "/api/v1/telemetry-sources", json=_source_payload("sim-source")
    )
    source_id = source.json()["id"]
    rule = await phase2_client.post("/api/v1/detection-rules", json=_rule_payload())
    assert rule.status_code == 201, rule.text
    rule_id = rule.json().get("rule_id") or rule.json().get("id")

    schema = await phase2_client.post(
        f"/api/v1/detection-rules/{rule_id}/validate-schema",
        json={"source_id": source_id},
    )
    assert schema.status_code == 200
    assert schema.json()["is_valid"] is True

    now = datetime(2026, 7, 20, 15, 0, 0, tzinfo=UTC)
    sim = await phase2_client.post(
        f"/api/v1/detection-rules/{rule_id}/simulate",
        json={
            "source_id": source_id,
            "window_start": (now - timedelta(hours=1)).isoformat(),
            "window_end": now.isoformat(),
            "synthetic_events": [
                {"process.name": "cmd.exe"},
                {"process.name": "bash"},
            ],
        },
    )
    assert sim.status_code == 200, sim.text
    body = sim.json()
    assert body["match_count"] == 1
    assert body["findings_created"] == 0
    assert body["creates_findings"] is False
