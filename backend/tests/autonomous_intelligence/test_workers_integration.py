from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from autonomous_intelligence.application.commands.intelligence_commands import (
    ApproveSuggestion,
    CreateIntelligenceSuggestion,
    DeployOptimizationModel,
    TrainOptimizationModel,
)
from autonomous_intelligence.domain.aggregates.suggestion_outcome import SuggestionOutcome
from autonomous_intelligence.domain.value_objects.enums import SuggestionTargetType
from autonomous_intelligence.domain.value_objects.identifiers import TenantId
from autonomous_intelligence.infrastructure.container import AutonomousIntelligenceContainer


@pytest.mark.asyncio
@pytest.mark.parametrize("conf", [0.75, 0.8, 0.85, 0.9, 0.95])
async def test_generation_worker(conf: float) -> None:
    c = AutonomousIntelligenceContainer()
    dto = await c.generation_worker.handle_signal(
        uuid4(), "detection_rule_tuning", "detection", conf
    )
    assert dto.status == "pending_review"


@pytest.mark.asyncio
async def test_expiry_worker() -> None:
    c = AutonomousIntelligenceContainer()
    tenant = uuid4()
    created = await c.app.create_suggestion(
        CreateIntelligenceSuggestion(
            tenant,
            "detection",
            None,
            "detection_rule_tuning",
            {},
            "m",
            1,
            0.9,
            (),
            "r",
            ("system",),
        )
    )
    s = await c.suggestions.find_by_id(UUID(created.suggestion_id), TenantId(tenant))
    assert s is not None
    s.review_deadline_at = datetime.now(UTC) - timedelta(hours=1)
    await c.suggestions.save(s, TenantId(tenant))
    n = await c.expiry_worker.tick()
    assert n >= 1


@pytest.mark.asyncio
async def test_application_worker() -> None:
    c = AutonomousIntelligenceContainer()
    tenant = uuid4()
    created = await c.app.create_suggestion(
        CreateIntelligenceSuggestion(
            tenant,
            "detection",
            None,
            "detection_rule_tuning",
            {},
            "m",
            1,
            0.9,
            (),
            "r",
            ("system",),
        )
    )
    sid = UUID(created.suggestion_id)
    await c.app.approve(ApproveSuggestion(tenant, sid, "eng", ("soc:detection_engineer",)))
    dto = await c.application_worker.confirm(tenant, sid, "detection:rule:1")
    assert dto.status == "applied"


@pytest.mark.asyncio
@pytest.mark.parametrize("baseline", [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8])
async def test_outcome_measurement_worker(baseline: float) -> None:
    c = AutonomousIntelligenceContainer()
    tenant = uuid4()
    await c.app.train_model(
        TrainOptimizationModel(tenant, "detection_rule_tuning", "m-o", 1, ("ai:ml_engineer",))
    )
    await c.app.deploy_model(
        DeployOptimizationModel(
            tenant, "m-o", "eu", {"precision": 0.8, "recall": 0.75}, ("ai:ml_engineer",)
        )
    )
    outcome = SuggestionOutcome.create_pending(
        uuid4(), TenantId(tenant), SuggestionTargetType.DETECTION_RULE_TUNING, 30, baseline
    )
    await c.outcomes.append(outcome)
    n = await c.outcome_worker.tick(tenant)
    assert n >= 1


@pytest.mark.asyncio
async def test_retrain_worker_trigger() -> None:
    c = AutonomousIntelligenceContainer()
    tenant = uuid4()
    await c.app.train_model(
        TrainOptimizationModel(tenant, "detection_rule_tuning", "m-r", 1, ("ai:ml_engineer",))
    )
    await c.app.deploy_model(
        DeployOptimizationModel(
            tenant, "m-r", "eu", {"precision": 0.8, "recall": 0.75}, ("ai:ml_engineer",)
        )
    )
    model = await c.models.find_by_id("m-r", TenantId(tenant))
    assert model is not None
    model.feedback_sample_count = model.retraining_threshold
    await c.models.save(model, TenantId(tenant))
    n = await c.retrain_worker.tick(tenant)
    assert n >= 1


@pytest.mark.asyncio
@pytest.mark.parametrize("i", range(10))
async def test_scheduler_tick(i: int) -> None:
    c = AutonomousIntelligenceContainer()
    result = await c.scheduler.tick_all(uuid4())
    assert "expired" in result
    assert "measured" in result
