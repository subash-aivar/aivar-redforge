"""Projection rebuild from evaluation domain events via bridging publisher."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from evaluation.application.commands.evaluation_commands import EvaluateCampaignCommand
from evaluation.application.projections.evaluation_read_models import (
    KillChainProgressionProjection,
)
from evaluation.domain.value_objects.evaluation_vos import (
    AttackActionRecord,
    KillChainPhaseOutcome,
    ObjectiveSpec,
)
from evaluation.infrastructure.events.projection_bridging_publisher import (
    ProjectionBridgingEventPublisher,
)
from tests.evaluation.conftest import make_service
from tests.evaluation.fakes.repos import FakeUnitOfWork


@pytest.mark.asyncio
async def test_kill_chain_projection_rebuilds_with_per_phase_coverage() -> None:
    uow = FakeUnitOfWork()
    bridging = ProjectionBridgingEventPublisher()
    projection = KillChainProgressionProjection()
    bridging.register_projection(projection)

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
            kill_chain_phase="Initial Access",
        ),
        AttackActionRecord(
            action_id="a2",
            operation_id="o1",
            technique_id="T1021",
            asset_ref="h1",
            started_at=now.isoformat(),
            completed_at=(now + timedelta(minutes=2)).isoformat(),
            outcome="Success",
            kill_chain_phase="Lateral Movement",
        ),
    ]
    svc = make_service(uow, bridging, actions=actions, findings=[])
    tenant = uuid4()
    instance = uuid4()
    dto = await svc.evaluate_campaign(
        EvaluateCampaignCommand(
            tenant_id=tenant,
            campaign_instance_id=instance,
            campaign_id=uuid4(),
            run_number=1,
            objective_specs=[
                ObjectiveSpec(
                    objective_id="o1",
                    objective_type="AccessAchieved",
                    is_required=True,
                    condition_type="AttackActionCompleted",
                    parameters={"technique_id": "T1078"},
                )
            ],
            kill_chain_phases=[
                KillChainPhaseOutcome(
                    phase_name="Initial Access",
                    tasks_planned=1,
                    tasks_completed=1,
                    tasks_failed=0,
                ),
                KillChainPhaseOutcome(
                    phase_name="Lateral Movement",
                    tasks_planned=1,
                    tasks_completed=1,
                    tasks_failed=0,
                ),
            ],
            started_at=now.isoformat(),
            completed_at=(now + timedelta(hours=1)).isoformat(),
        )
    )
    assert dto.state == "Complete"
    completed = [e for e in bridging.published if e.event_type == "CampaignEvaluationCompleted"]
    assert completed
    payload = completed[0].payload
    assert isinstance(payload, dict)
    assert payload.get("per_phase_coverage")
    key = f"killchain:{tenant}:{instance}"
    doc = projection._store.get(key)
    assert doc is not None
    assert doc["per_phase_coverage"]
    assert doc["kill_chain_phases"]
