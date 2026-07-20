"""CorrelationCoordinator tests."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Self

import pytest

from detection.application.ports.i_event_publisher import IEventPublisher
from detection.application.ports.i_unit_of_work import IUnitOfWork
from detection.application.services.correlation_coordinator import CorrelationCoordinator
from detection.application.services.correlation_publisher import CorrelationPublisher
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
from tests.detection.application.test_execution_finding_application_service import (
    _FakeFindings,
    _FakeRules,
)
from tests.detection.phase3_helpers import make_finding
from tests.detection.phase4_helpers import make_tenant


class _FakeUow(IUnitOfWork):
    def __init__(self, findings: _FakeFindings) -> None:
        super().__init__()
        self.detection_findings = findings
        self.detection_rules = _FakeRules()
        self.telemetry_sources = None  # type: ignore[assignment]
        self.detection_executions = None  # type: ignore[assignment]
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


class _Pub(IEventPublisher):
    def __init__(self) -> None:
        self.batches: list = []

    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        self.batches.append(list(events))


@pytest.mark.asyncio
async def test_correlate_finding_enriches() -> None:
    finding = make_finding(tenant_id=make_tenant(), now=datetime.now(UTC))
    findings = _FakeFindings()
    await findings.save(finding)
    pub = _Pub()
    corr = CorrelationService(
        InventoryAdapter(),
        CloudContextAdapter(),
        VulnerabilityContextAdapter(),
        ThreatIntelAdapter(),
        ComplianceAdapter(),
        BehavioralSignalAdapter(),
    )
    coordinator = CorrelationCoordinator(
        lambda: _FakeUow(findings),
        corr,
        CorrelationPublisher(pub),
    )
    result = await coordinator.correlate_finding(
        tenant_uuid=finding.tenant_id.value,
        finding_id=finding.finding_id.value,
    )
    assert result["status"] in {"Completed", "Partial"}
    stored = await findings.find_by_id(finding.finding_id, finding.tenant_id)
    assert stored is not None
    assert stored.correlation.enriched is True


@pytest.mark.asyncio
async def test_correlate_skips_when_already_enriched() -> None:
    finding = make_finding(tenant_id=make_tenant(), now=datetime.now(UTC))
    findings = _FakeFindings()
    await findings.save(finding)
    pub = _Pub()
    corr = CorrelationService(
        InventoryAdapter(),
        CloudContextAdapter(),
        VulnerabilityContextAdapter(),
        ThreatIntelAdapter(),
        ComplianceAdapter(),
        BehavioralSignalAdapter(),
    )
    coordinator = CorrelationCoordinator(
        lambda: _FakeUow(findings),
        corr,
        CorrelationPublisher(pub),
    )
    await coordinator.correlate_finding(
        tenant_uuid=finding.tenant_id.value,
        finding_id=finding.finding_id.value,
    )
    result = await coordinator.correlate_finding(
        tenant_uuid=finding.tenant_id.value,
        finding_id=finding.finding_id.value,
    )
    assert result.get("skipped") is True


@pytest.mark.asyncio
@pytest.mark.parametrize("i", range(15))
async def test_correlate_many(i: int) -> None:
    finding = make_finding(tenant_id=make_tenant(), now=datetime.now(UTC))
    findings = _FakeFindings()
    await findings.save(finding)
    pub = _Pub()
    coordinator = CorrelationCoordinator(
        lambda: _FakeUow(findings),
        CorrelationService(
            InventoryAdapter(),
            CloudContextAdapter(),
            VulnerabilityContextAdapter(),
            ThreatIntelAdapter(),
            ComplianceAdapter(),
            BehavioralSignalAdapter(),
        ),
        CorrelationPublisher(pub),
    )
    result = await coordinator.correlate_finding(
        tenant_uuid=finding.tenant_id.value,
        finding_id=finding.finding_id.value,
        refresh=True,
    )
    assert "status" in result
