"""Application service tests for execution + finding Phase 3."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Self
from uuid import UUID, uuid4

import pytest

from detection.application.commands.execution_finding_commands import (
    ConfirmFinding,
    EscalateFindingToInvestigation,
    MarkFindingFalsePositive,
    ProduceFinding,
    RecordExecutionResult,
    ScheduleRuleExecution,
    SuppressFinding,
    TriageFinding,
)
from detection.application.exceptions import ApplicationNotFoundError
from detection.application.ports.i_event_publisher import IEventPublisher
from detection.application.ports.i_unit_of_work import IUnitOfWork
from detection.application.queries.execution_finding_queries import (
    GetExecution,
    GetFinding,
    ListExecutions,
)
from detection.application.services.execution_finding_application_service import (
    ExecutionFindingApplicationService,
)
from detection.domain.aggregates.detection_execution import DetectionExecution
from detection.domain.aggregates.detection_finding import DetectionFinding
from detection.domain.aggregates.detection_rule import DetectionRule
from detection.domain.aggregates.telemetry_source import TelemetrySource
from detection.domain.events.base import BaseDomainEvent
from detection.domain.repositories.i_detection_execution_repository import (
    IDetectionExecutionRepository,
)
from detection.domain.repositories.i_detection_finding_repository import (
    IDetectionFindingRepository,
)
from detection.domain.repositories.i_detection_rule_repository import (
    IDetectionRuleRepository,
)
from detection.domain.repositories.i_telemetry_source_repository import (
    ITelemetrySourceRepository,
)
from detection.domain.value_objects.enums import (
    FindingState,
    RuleLifecycleState,
    SourceType,
)
from detection.domain.value_objects.execution_finding import FindingKey
from detection.domain.value_objects.identifiers import (
    DetectionExecutionId,
    DetectionFindingId,
    DetectionRuleId,
    TelemetrySourceId,
    TenantId,
)
from detection.domain.value_objects.keys import RuleKey
from tests.detection.conftest import make_rule


class _FakeRules(IDetectionRuleRepository):
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


class _FakeSources(ITelemetrySourceRepository):
    async def save(self, source: TelemetrySource) -> None:
        return None

    async def find_by_id(
        self, source_id: TelemetrySourceId, tenant_id: TenantId
    ) -> TelemetrySource | None:
        return None

    async def find_by_name(
        self, name: str, tenant_id: TenantId
    ) -> TelemetrySource | None:
        return None

    async def find_active_by_tenant(
        self, tenant_id: TenantId
    ) -> list[TelemetrySource]:
        return []

    async def find_by_type(
        self, source_type: SourceType, tenant_id: TenantId
    ) -> list[TelemetrySource]:
        return []

    async def list_by_tenant(
        self, tenant_id: TenantId, *, limit: int = 100, offset: int = 0
    ) -> list[TelemetrySource]:
        return []


class _FakeExecutions(IDetectionExecutionRepository):
    def __init__(self) -> None:
        self.by_id: dict[tuple[UUID, UUID], DetectionExecution] = {}

    async def save(self, execution: DetectionExecution) -> None:
        self.by_id[(execution.execution_id.value, execution.tenant_id.value)] = execution

    async def find_by_id(
        self, execution_id: DetectionExecutionId, tenant_id: TenantId
    ) -> DetectionExecution | None:
        return self.by_id.get((execution_id.value, tenant_id.value))

    async def find_by_rule(self, rule_id, tenant_id, window=None, *, limit=100, offset=0):
        return []

    async def find_failed_by_tenant(self, tenant_id, since):
        return []

    async def find_by_state(self, state, tenant_id):
        return [
            e
            for (_, tid), e in self.by_id.items()
            if tid == tenant_id.value and e.state == state
        ]

    async def list_by_tenant(self, tenant_id, *, limit=100, offset=0):
        items = [e for (_, tid), e in self.by_id.items() if tid == tenant_id.value]
        return items[offset : offset + limit]


class _FakeFindings(IDetectionFindingRepository):
    def __init__(self) -> None:
        self.by_id: dict[tuple[UUID, UUID], DetectionFinding] = {}

    async def save(self, finding: DetectionFinding) -> None:
        self.by_id[(finding.finding_id.value, finding.tenant_id.value)] = finding

    async def find_by_id(
        self, finding_id: DetectionFindingId, tenant_id: TenantId
    ) -> DetectionFinding | None:
        return self.by_id.get((finding_id.value, tenant_id.value))

    async def find_by_key(self, key: FindingKey, tenant_id: TenantId):
        matches = [
            f
            for (_, tid), f in self.by_id.items()
            if tid == tenant_id.value and str(f.finding_key) == str(key)
        ]
        if not matches:
            return None
        return max(matches, key=lambda f: f.last_seen_at)

    async def find_open_by_tenant(self, tenant_id, *, states=None, limit=100, offset=0):
        open_states = states or [
            FindingState.NEW,
            FindingState.TRIAGED,
            FindingState.CONFIRMED,
            FindingState.ESCALATED_TO_INVESTIGATION,
        ]
        items = [
            f
            for (_, tid), f in self.by_id.items()
            if tid == tenant_id.value and f.state in open_states
        ]
        return items[offset : offset + limit]

    async def find_by_asset(self, asset_id, tenant_id, *, limit=100, offset=0):
        items = [
            f
            for (_, tid), f in self.by_id.items()
            if tid == tenant_id.value and f.asset_ref.asset_id == asset_id
        ]
        return items[offset : offset + limit]

    async def find_by_rule(self, rule_id, tenant_id, window=None, *, limit=100, offset=0):
        return []

    async def find_by_attack_technique(
        self, technique_id, tenant_id, *, limit=100, offset=0
    ):
        return []

    async def list_by_tenant(self, tenant_id, *, limit=100, offset=0):
        items = [f for (_, tid), f in self.by_id.items() if tid == tenant_id.value]
        return items[offset : offset + limit]


class _FakeUow(IUnitOfWork):
    def __init__(
        self,
        rules: _FakeRules,
        executions: _FakeExecutions,
        findings: _FakeFindings,
    ) -> None:
        super().__init__()
        self.detection_rules = rules
        self.telemetry_sources = _FakeSources()
        self.detection_executions = executions
        self.detection_findings = findings
        self.detection_packs = None  # type: ignore[assignment]
        self.detection_exceptions = None  # type: ignore[assignment]
        self.detection_evidence = None  # type: ignore[assignment]

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
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


def _svc(
    rules: _FakeRules | None = None,
    executions: _FakeExecutions | None = None,
    findings: _FakeFindings | None = None,
) -> tuple[
    ExecutionFindingApplicationService,
    _FakeRules,
    _FakeExecutions,
    _FakeFindings,
    _NoopPublisher,
]:
    r = rules or _FakeRules()
    e = executions or _FakeExecutions()
    f = findings or _FakeFindings()
    publisher = _NoopPublisher()

    def factory() -> _FakeUow:
        return _FakeUow(r, e, f)

    return (
        ExecutionFindingApplicationService(factory, publisher),
        r,
        e,
        f,
        publisher,
    )


@pytest.mark.asyncio
async def test_schedule_and_get(tenant_id: TenantId, now: datetime) -> None:
    svc, rules, _, _, publisher = _svc()
    rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
    await rules.save(rule)
    dto = await svc.schedule_rule_execution(
        ScheduleRuleExecution(
            tenant_id=tenant_id,
            rule_id=rule.rule_id.value,
            source_id="src-1",
            window_start=(now - timedelta(hours=1)).isoformat(),
            window_end=now.isoformat(),
        )
    )
    assert dto.state == "Scheduled"
    assert len(publisher.batches) == 1
    got = await svc.get_execution(
        GetExecution(tenant_id=tenant_id, execution_id=UUID(dto.id))
    )
    assert got.id == dto.id


@pytest.mark.asyncio
async def test_record_result_and_timeout(tenant_id: TenantId, now: datetime) -> None:
    svc, rules, _, _, _ = _svc()
    rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
    await rules.save(rule)
    scheduled = await svc.schedule_rule_execution(
        ScheduleRuleExecution(
            tenant_id=tenant_id,
            rule_id=rule.rule_id.value,
            source_id="src-1",
            window_start=(now - timedelta(hours=1)).isoformat(),
            window_end=now.isoformat(),
        )
    )
    completed = await svc.record_execution_result(
        RecordExecutionResult(
            tenant_id=tenant_id,
            execution_id=UUID(scheduled.id),
            findings_produced=1,
            duration_ms=10,
        )
    )
    assert completed.state == "Completed"

    scheduled2 = await svc.schedule_rule_execution(
        ScheduleRuleExecution(
            tenant_id=tenant_id,
            rule_id=rule.rule_id.value,
            source_id="src-1",
            window_start=(now - timedelta(hours=1)).isoformat(),
            window_end=now.isoformat(),
        )
    )
    timed = await svc.record_execution_result(
        RecordExecutionResult(
            tenant_id=tenant_id,
            execution_id=UUID(scheduled2.id),
            timed_out=True,
            duration_ms=60000,
        )
    )
    assert timed.state == "Timedout"


@pytest.mark.asyncio
async def test_produce_finding_and_dedup(tenant_id: TenantId, now: datetime) -> None:
    svc, rules, _, findings, _ = _svc()
    rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
    await rules.save(rule)
    execution = await svc.schedule_rule_execution(
        ScheduleRuleExecution(
            tenant_id=tenant_id,
            rule_id=rule.rule_id.value,
            source_id="src-1",
            window_start=(now - timedelta(hours=1)).isoformat(),
            window_end=now.isoformat(),
        )
    )
    first = await svc.produce_finding(
        ProduceFinding(
            tenant_id=tenant_id,
            rule_id=rule.rule_id.value,
            execution_id=UUID(execution.id),
            asset_id="asset-1",
            signal_id="sig-1",
            observed_at=now.isoformat(),
            fingerprint_fields={"process.name": "cmd.exe"},
        )
    )
    assert first.state == "New"
    assert first.deduplicated is False

    second = await svc.produce_finding(
        ProduceFinding(
            tenant_id=tenant_id,
            rule_id=rule.rule_id.value,
            execution_id=UUID(execution.id),
            asset_id="asset-1",
            signal_id="sig-2",
            observed_at=now.isoformat(),
            fingerprint_fields={"process.name": "cmd.exe"},
        )
    )
    assert second.deduplicated is True
    assert second.id == first.id
    assert len(findings.by_id) == 1


@pytest.mark.asyncio
async def test_produce_blocked_on_timed_out(
    tenant_id: TenantId, now: datetime
) -> None:
    from detection.application.exceptions import ApplicationValidationError

    svc, rules, _, _, _ = _svc()
    rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
    await rules.save(rule)
    execution = await svc.schedule_rule_execution(
        ScheduleRuleExecution(
            tenant_id=tenant_id,
            rule_id=rule.rule_id.value,
            source_id="src-1",
            window_start=(now - timedelta(hours=1)).isoformat(),
            window_end=now.isoformat(),
        )
    )
    await svc.record_execution_result(
        RecordExecutionResult(
            tenant_id=tenant_id,
            execution_id=UUID(execution.id),
            timed_out=True,
            duration_ms=1,
        )
    )
    with pytest.raises(ApplicationValidationError):
        await svc.produce_finding(
            ProduceFinding(
                tenant_id=tenant_id,
                rule_id=rule.rule_id.value,
                execution_id=UUID(execution.id),
                asset_id="a",
                signal_id="s",
                observed_at=now.isoformat(),
                fingerprint_fields={"x": 1},
            )
        )


@pytest.mark.asyncio
async def test_finding_lifecycle_ops(tenant_id: TenantId, now: datetime) -> None:
    svc, rules, _, _, _ = _svc()
    rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
    await rules.save(rule)
    execution = await svc.schedule_rule_execution(
        ScheduleRuleExecution(
            tenant_id=tenant_id,
            rule_id=rule.rule_id.value,
            source_id="src-1",
            window_start=(now - timedelta(hours=1)).isoformat(),
            window_end=now.isoformat(),
        )
    )
    finding = await svc.produce_finding(
        ProduceFinding(
            tenant_id=tenant_id,
            rule_id=rule.rule_id.value,
            execution_id=UUID(execution.id),
            asset_id="asset-1",
            signal_id="sig-1",
            observed_at=now.isoformat(),
            fingerprint_fields={"k": "v"},
        )
    )
    fid = UUID(finding.id)
    triaged = await svc.triage_finding(
        TriageFinding(
            tenant_id=tenant_id, finding_id=fid, analyst="a", note="looks real"
        )
    )
    assert triaged.state == "Triaged"
    confirmed = await svc.confirm_finding(
        ConfirmFinding(tenant_id=tenant_id, finding_id=fid, analyst="a")
    )
    assert confirmed.state == "Confirmed"


@pytest.mark.asyncio
async def test_fp_suppress_escalate(tenant_id: TenantId, now: datetime) -> None:
    svc, rules, _, _, _ = _svc()
    rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
    await rules.save(rule)

    async def _new_finding(suffix: str) -> UUID:
        execution = await svc.schedule_rule_execution(
            ScheduleRuleExecution(
                tenant_id=tenant_id,
                rule_id=rule.rule_id.value,
                source_id="src-1",
                window_start=(now - timedelta(hours=1)).isoformat(),
                window_end=now.isoformat(),
            )
        )
        finding = await svc.produce_finding(
            ProduceFinding(
                tenant_id=tenant_id,
                rule_id=rule.rule_id.value,
                execution_id=UUID(execution.id),
                asset_id=f"asset-{suffix}",
                signal_id=f"sig-{suffix}",
                observed_at=now.isoformat(),
                fingerprint_fields={"s": suffix},
            )
        )
        return UUID(finding.id)

    fp_id = await _new_finding("fp")
    fp = await svc.mark_finding_false_positive(
        MarkFindingFalsePositive(
            tenant_id=tenant_id,
            finding_id=fp_id,
            analyst="a",
            justification="benign",
        )
    )
    assert fp.state == "FalsePositive"

    sp_id = await _new_finding("sp")
    sp = await svc.suppress_finding(
        SuppressFinding(
            tenant_id=tenant_id,
            finding_id=sp_id,
            analyst="a",
            justification="noise",
        )
    )
    assert sp.state == "Suppressed"

    esc_id = await _new_finding("esc")
    esc = await svc.escalate_finding_to_investigation(
        EscalateFindingToInvestigation(
            tenant_id=tenant_id,
            finding_id=esc_id,
            analyst="a",
            investigation_id="inv-99",
        )
    )
    assert esc.state == "EscalatedToInvestigation"
    assert esc.escalation is not None


@pytest.mark.asyncio
async def test_list_executions_and_findings(
    tenant_id: TenantId, now: datetime
) -> None:
    svc, rules, _, _, _ = _svc()
    rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
    await rules.save(rule)
    for i in range(3):
        await svc.schedule_rule_execution(
            ScheduleRuleExecution(
                tenant_id=tenant_id,
                rule_id=rule.rule_id.value,
                source_id=f"src-{i}",
                window_start=(now - timedelta(hours=1)).isoformat(),
                window_end=now.isoformat(),
            )
        )
    page = await svc.list_executions(
        ListExecutions(tenant_id=tenant_id)
    )
    assert len(page.items) == 3


@pytest.mark.asyncio
async def test_get_missing(tenant_id: TenantId) -> None:
    svc, _, _, _, _ = _svc()
    with pytest.raises(ApplicationNotFoundError):
        await svc.get_finding(
            GetFinding(tenant_id=tenant_id, finding_id=uuid4())
        )
