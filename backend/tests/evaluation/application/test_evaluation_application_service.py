"""Application tests for EvaluationApplicationService."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from evaluation.application.commands.evaluation_commands import (
    EvaluateCampaignCommand,
    GetMetricsTrendQuery,
)
from evaluation.domain.value_objects.enums import EvaluationState
from evaluation.domain.value_objects.evaluation_vos import (
    AttackActionRecord,
    DetectionFindingRecord,
    ObjectiveSpec,
)
from evaluation.infrastructure.acl.degraded_adapters import StubSecurityGraphWriteAdapter
from redforge.shared.identifiers import EntityId
from tests.evaluation.conftest import make_service
from tests.evaluation.fakes.repos import FakeEventPublisher, FakeUnitOfWork


@pytest.mark.asyncio
async def test_evaluate_campaign_full_pipeline() -> None:
    uow = FakeUnitOfWork()
    publisher = FakeEventPublisher()
    graph = StubSecurityGraphWriteAdapter()
    now = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
    actions = [
        AttackActionRecord(
            action_id="a1",
            operation_id="o1",
            technique_id="T1078",
            asset_ref="h1",
            started_at=now.isoformat(),
            completed_at=(now + timedelta(minutes=1)).isoformat(),
            outcome="Success",
        )
    ]
    svc = make_service(uow, publisher, actions=actions, findings=[], graph=graph)
    tenant = EntityId.generate()
    instance = uuid4()
    campaign = uuid4()
    specs = [
        ObjectiveSpec(
            objective_id="o1",
            objective_type="AccessAchieved",
            is_required=True,
            condition_type="AttackActionCompleted",
            parameters={"technique_id": "T1078"},
        )
    ]
    dto = await svc.evaluate_campaign(
        EvaluateCampaignCommand(
            tenant_id=tenant,
            campaign_instance_id=instance,
            campaign_id=campaign,
            run_number=1,
            objective_specs=specs,
            started_at=now.isoformat(),
            completed_at=(now + timedelta(hours=1)).isoformat(),
        )
    )
    assert dto.state == EvaluationState.COMPLETE.value
    assert dto.composite_outcome == "FullSuccess"
    assert dto.detection_coverage_percent == 0.0  # no findings
    assert len(graph.nodes) == 1
    assert len(graph.evaluated_by_edges) == 1
    assert len(graph.technique_edges) >= 1
    assert any(type(e).__name__ == "CampaignEvaluationCompleted" for e in publisher.events)


@pytest.mark.asyncio
async def test_detection_absent_quality_gate() -> None:
    uow = FakeUnitOfWork()
    publisher = FakeEventPublisher()
    now = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
    findings = [
        DetectionFindingRecord(
            finding_id="f1",
            rule_id="r1",
            technique_id="T1078",
            asset_ref="h1",
            detected_at=(now + timedelta(minutes=5)).isoformat(),
        )
    ]
    svc = make_service(uow, publisher, actions=[], findings=findings)
    dto = await svc.evaluate_campaign(
        EvaluateCampaignCommand(
            tenant_id=EntityId.generate(),
            campaign_instance_id=uuid4(),
            campaign_id=uuid4(),
            run_number=1,
            objective_specs=[
                ObjectiveSpec(
                    objective_id="o1",
                    objective_type="DetectionEvaded",
                    is_required=True,
                    condition_type="DetectionAbsent",
                    parameters={"technique_id": "T1078"},
                )
            ],
        )
    )
    assert dto.assessments[0].outcome == "Failed"


@pytest.mark.asyncio
async def test_metrics_trend_direction() -> None:
    uow = FakeUnitOfWork()
    publisher = FakeEventPublisher()
    now = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
    tenant = EntityId.generate()
    campaign = uuid4()

    # Three runs with increasing coverage
    for run, tech in enumerate(["T1", "T1", "T1"], start=1):
        findings = []
        if run >= 2:
            findings = [
                DetectionFindingRecord(
                    finding_id=f"f{run}",
                    rule_id="r1",
                    technique_id=tech,
                    asset_ref="h1",
                    detected_at=(now + timedelta(minutes=5)).isoformat(),
                )
            ]
        actions = [
            AttackActionRecord(
                action_id=f"a{run}",
                operation_id=f"o{run}",
                technique_id=tech,
                asset_ref="h1",
                started_at=now.isoformat(),
                completed_at=(now + timedelta(minutes=1)).isoformat(),
                outcome="Success",
            )
        ]
        svc = make_service(uow, publisher, actions=actions, findings=findings)
        await svc.evaluate_campaign(
            EvaluateCampaignCommand(
                tenant_id=tenant,
                campaign_instance_id=uuid4(),
                campaign_id=campaign,
                run_number=run,
                objective_specs=[
                    ObjectiveSpec(
                        objective_id=f"o{run}",
                        objective_type="AccessAchieved",
                        is_required=True,
                        condition_type="AttackActionCompleted",
                        parameters={"technique_id": tech},
                    )
                ],
            )
        )

    trend = await svc.get_metrics_trend(
        GetMetricsTrendQuery(tenant_id=tenant, campaign_id=campaign, limit=5)
    )
    assert trend.run_count == 3
    assert trend.coverage_values[0] == 0.0
    assert trend.coverage_values[-1] == 100.0
    assert trend.trend_direction == "better"
