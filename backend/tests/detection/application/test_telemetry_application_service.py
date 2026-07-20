"""Application service tests for TelemetrySource and simulation."""

from __future__ import annotations

from datetime import datetime, timedelta
from types import TracebackType
from typing import Self
from uuid import UUID, uuid4

import pytest

from detection.application.commands.telemetry_commands import (
    DeactivateTelemetrySource,
    RegisterTelemetrySource,
    SimulateRule,
    UpdateTelemetrySourceHealth,
    ValidateRuleAgainstSchema,
)
from detection.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from detection.application.ports.i_event_publisher import IEventPublisher
from detection.application.ports.i_unit_of_work import IUnitOfWork
from detection.application.queries.telemetry_queries import (
    GetTelemetrySource,
    ListTelemetrySources,
)
from detection.application.services.telemetry_application_service import (
    TelemetryApplicationService,
)
from detection.domain.aggregates.detection_rule import DetectionRule
from detection.domain.aggregates.telemetry_source import TelemetrySource
from detection.domain.events.base import BaseDomainEvent
from detection.domain.providers.normalized_models import NormalizedTelemetryResult
from detection.domain.providers.registry import TelemetryProviderRegistry
from detection.domain.repositories.i_detection_rule_repository import (
    IDetectionRuleRepository,
)
from detection.domain.repositories.i_telemetry_source_repository import (
    ITelemetrySourceRepository,
)
from detection.domain.value_objects.enums import (
    RuleLifecycleState,
    SourceHealthStatus,
    SourceType,
)
from detection.domain.value_objects.identifiers import (
    DetectionRuleId,
    TelemetrySourceId,
    TenantId,
)
from detection.domain.value_objects.keys import RuleKey
from tests.detection.conftest import make_rule
from tests.detection.phase2_helpers import StubTelemetryAdapter, make_schema, make_source


class _FakeRuleRepo(IDetectionRuleRepository):
    def __init__(self) -> None:
        self.by_id: dict[tuple[UUID, UUID], DetectionRule] = {}

    async def save(self, rule: DetectionRule) -> None:
        self.by_id[(rule.rule_id.value, rule.tenant_id.value)] = rule

    async def find_by_id(
        self, rule_id: DetectionRuleId, tenant_id: TenantId
    ) -> DetectionRule | None:
        return self.by_id.get((rule_id.value, tenant_id.value))

    async def find_by_key(self, key: RuleKey, tenant_id: TenantId) -> DetectionRule | None:
        return None

    async def find_active_by_tenant(self, tenant_id: TenantId) -> list[DetectionRule]:
        return []

    async def find_by_lifecycle_state(
        self, tenant_id: TenantId, state: RuleLifecycleState
    ) -> list[DetectionRule]:
        return []

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
        return []


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
    def __init__(self) -> None:
        self.batches: list[list[BaseDomainEvent]] = []

    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        self.batches.append(list(events))


class _FakeQueryPort:
    def __init__(self, result: NormalizedTelemetryResult | None = None) -> None:
        self._result = result or NormalizedTelemetryResult.empty()

    async def execute_query(self, **kwargs: object) -> NormalizedTelemetryResult:
        return self._result

    async def estimate_cost(self, **kwargs: object) -> object:
        from detection.domain.providers.normalized_models import QueryCostEstimate

        return QueryCostEstimate(estimated_events=0, estimated_duration_ms=0.0)


def _svc(
    rules: _FakeRuleRepo | None = None,
    sources: _FakeSourceRepo | None = None,
    registry: TelemetryProviderRegistry | None = None,
    query_port: _FakeQueryPort | None = None,
) -> tuple[TelemetryApplicationService, _FakeRuleRepo, _FakeSourceRepo, _NoopPublisher]:
    rule_repo = rules or _FakeRuleRepo()
    source_repo = sources or _FakeSourceRepo()
    publisher = _NoopPublisher()
    reg = registry or TelemetryProviderRegistry()

    def uow_factory() -> _FakeUow:
        return _FakeUow(rule_repo, source_repo)

    svc = TelemetryApplicationService(
        uow_factory,
        publisher,
        reg,
        query_port or _FakeQueryPort(),  # type: ignore[arg-type]
    )
    return svc, rule_repo, source_repo, publisher


@pytest.mark.asyncio
async def test_register_and_get_source(tenant_id: TenantId) -> None:
    svc, _, _sources, publisher = _svc()
    dto = await svc.register_telemetry_source(
        RegisterTelemetrySource(
            tenant_id=tenant_id.value,
            name="primary-push",
            source_type=SourceType.CUSTOM_PUSH.value,
            trust_level="Secondary",
            schema_version="1.0.0",
            fields=[
                {"path": "process.name", "data_type": "string"},
                {"path": "event.event_type", "data_type": "string"},
            ],
            adapter_key="framework.stub",
            tenant_scope_assertion="tenant=abc",
            latency_expected_seconds=10,
            retention_seconds=86400,
        )
    )
    assert dto.name == "primary-push"
    assert len(publisher.batches) == 1
    got = await svc.get_telemetry_source(
        GetTelemetrySource(tenant_id=tenant_id.value, source_id=UUID(dto.id))
    )
    assert got.id == dto.id


@pytest.mark.asyncio
async def test_deactivate_source(tenant_id: TenantId, now: datetime) -> None:
    svc, _, sources, _ = _svc()
    source = make_source(tenant_id=tenant_id, now=now, pop_events=True)
    await sources.save(source)
    dto = await svc.deactivate_telemetry_source(
        DeactivateTelemetrySource(
            tenant_id=tenant_id.value,
            source_id=source.source_id.value,
            reason="retired",
        )
    )
    assert dto.lifecycle_state == "Deactivated"


@pytest.mark.asyncio
async def test_update_health(tenant_id: TenantId, now: datetime) -> None:
    svc, _, sources, _ = _svc()
    source = make_source(tenant_id=tenant_id, now=now, pop_events=True)
    await sources.save(source)
    dto = await svc.update_telemetry_source_health(
        UpdateTelemetrySourceHealth(
            tenant_id=tenant_id.value,
            source_id=source.source_id.value,
            status=SourceHealthStatus.HEALTHY.value,
            success=True,
        )
    )
    assert dto.health_status == "Healthy"


@pytest.mark.asyncio
async def test_list_sources(tenant_id: TenantId, now: datetime) -> None:
    svc, _, sources, _ = _svc()
    await sources.save(make_source(tenant_id=tenant_id, now=now, name="a", pop_events=True))
    await sources.save(make_source(tenant_id=tenant_id, now=now, name="b", pop_events=True))
    page = await svc.list_telemetry_sources(
        ListTelemetrySources(tenant_id=tenant_id.value)
    )
    assert len(page.items) == 2


@pytest.mark.asyncio
async def test_validate_rule_against_schema(tenant_id: TenantId, now: datetime) -> None:
    svc, rules, sources, _ = _svc()
    rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
    source = make_source(tenant_id=tenant_id, now=now, pop_events=True)
    await rules.save(rule)
    await sources.save(source)
    result = await svc.validate_rule_against_schema(
        ValidateRuleAgainstSchema(
            tenant_id=tenant_id.value,
            rule_id=rule.rule_id.value,
            source_id=source.source_id.value,
        )
    )
    assert result.is_valid is True


@pytest.mark.asyncio
async def test_validate_rule_missing_field(tenant_id: TenantId, now: datetime) -> None:
    svc, rules, sources, _ = _svc()
    rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
    source = make_source(
        tenant_id=tenant_id,
        now=now,
        schema=make_schema(paths=["event.event_type"]),
        pop_events=True,
    )
    await rules.save(rule)
    await sources.save(source)
    result = await svc.validate_rule_against_schema(
        ValidateRuleAgainstSchema(
            tenant_id=tenant_id.value,
            rule_id=rule.rule_id.value,
            source_id=source.source_id.value,
        )
    )
    assert result.is_valid is False
    assert "process.name" in result.missing_fields


@pytest.mark.asyncio
async def test_simulate_with_synthetic_events(tenant_id: TenantId, now: datetime) -> None:
    svc, rules, sources, _ = _svc()
    rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
    source = make_source(tenant_id=tenant_id, now=now, pop_events=True)
    await rules.save(rule)
    await sources.save(source)
    result = await svc.simulate_rule(
        SimulateRule(
            tenant_id=tenant_id.value,
            rule_id=rule.rule_id.value,
            source_id=source.source_id.value,
            window_start=(now - timedelta(hours=1)).isoformat(),
            window_end=now.isoformat(),
            synthetic_events=[
                {"process.name": "cmd.exe", "event.event_type": "ProcessCreate"},
                {"process.name": "bash", "event.event_type": "ProcessCreate"},
            ],
        )
    )
    assert result.match_count == 1
    assert result.findings_created == 0
    assert result.creates_findings is False


@pytest.mark.asyncio
async def test_simulate_never_creates_findings(tenant_id: TenantId, now: datetime) -> None:
    svc, rules, sources, _ = _svc()
    rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
    source = make_source(tenant_id=tenant_id, now=now, pop_events=True)
    await rules.save(rule)
    await sources.save(source)
    for _ in range(5):
        result = await svc.simulate_rule(
            SimulateRule(
                tenant_id=tenant_id.value,
                rule_id=rule.rule_id.value,
                source_id=source.source_id.value,
                window_start=(now - timedelta(hours=1)).isoformat(),
                window_end=now.isoformat(),
                synthetic_events=[{"process.name": "cmd.exe"}],
            )
        )
        assert result.findings_created == 0


@pytest.mark.asyncio
async def test_validate_source_without_provider(tenant_id: TenantId, now: datetime) -> None:
    svc, _, sources, _ = _svc()
    source = make_source(tenant_id=tenant_id, now=now, pop_events=True)
    await sources.save(source)
    result = await svc.validate_telemetry_source(
        tenant_id=tenant_id.value,
        source_id=source.source_id.value,
    )
    assert result.provider_registered is False


@pytest.mark.asyncio
async def test_validate_source_with_provider(tenant_id: TenantId, now: datetime) -> None:
    registry = TelemetryProviderRegistry()
    registry.register(StubTelemetryAdapter())
    svc, _, sources, _ = _svc(registry=registry)
    source = make_source(tenant_id=tenant_id, now=now, pop_events=True)
    await sources.save(source)
    result = await svc.validate_telemetry_source(
        tenant_id=tenant_id.value,
        source_id=source.source_id.value,
    )
    assert result.provider_registered is True
    assert result.schema_version_valid is True
    assert result.health_status == "Healthy"


@pytest.mark.asyncio
async def test_get_missing_source(tenant_id: TenantId) -> None:
    svc, _, _, _ = _svc()
    with pytest.raises(ApplicationNotFoundError):
        await svc.get_telemetry_source(
            GetTelemetrySource(tenant_id=tenant_id.value, source_id=uuid4())
        )


@pytest.mark.asyncio
async def test_simulate_schema_gate(tenant_id: TenantId, now: datetime) -> None:
    svc, rules, sources, _ = _svc()
    rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
    source = make_source(
        tenant_id=tenant_id,
        now=now,
        schema=make_schema(paths=["event.event_type"]),
        pop_events=True,
    )
    await rules.save(rule)
    await sources.save(source)
    with pytest.raises(ApplicationValidationError):
        await svc.simulate_rule(
            SimulateRule(
                tenant_id=tenant_id.value,
                rule_id=rule.rule_id.value,
                source_id=source.source_id.value,
                window_start=(now - timedelta(hours=1)).isoformat(),
                window_end=now.isoformat(),
                synthetic_events=[{"process.name": "cmd.exe"}],
            )
        )
