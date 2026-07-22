from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from autonomous_intelligence.application.commands.intelligence_commands import (
    ApproveSuggestion,
    CreateIntelligenceSuggestion,
    DeployOptimizationModel,
    MarkSuggestionApplied,
    RejectSuggestion,
    TrainOptimizationModel,
)
from autonomous_intelligence.domain.exceptions.domain_exceptions import (
    AccuracyThresholdNotMet,
    ConfidenceThresholdNotMet,
    InvalidSuggestionTransition,
)
from autonomous_intelligence.infrastructure.container import AutonomousIntelligenceContainer


@pytest.mark.asyncio
async def test_suggestion_lifecycle_approve_apply() -> None:
    c = AutonomousIntelligenceContainer()
    tenant = uuid4()
    roles_sys = ("system",)
    created = await c.app.create_suggestion(
        CreateIntelligenceSuggestion(
            tenant,
            "detection",
            None,
            "detection_rule_tuning",
            {"threshold": 0.9},
            "m1",
            1,
            0.85,
            ("sig1",),
            "Tune rule threshold",
            roles_sys,
        )
    )
    assert created.status == "pending_review"
    sid = UUID(created.suggestion_id)
    approved = await c.app.approve(
        ApproveSuggestion(tenant, sid, "eng1", ("soc:detection_engineer",))
    )
    assert approved.status == "approved"
    applied = await c.app.mark_applied(
        MarkSuggestionApplied(tenant, sid, "detection:rule:1", ("system",))
    )
    assert applied.status == "applied"


@pytest.mark.asyncio
async def test_confidence_gate() -> None:
    c = AutonomousIntelligenceContainer()
    with pytest.raises(ConfidenceThresholdNotMet):
        await c.app.create_suggestion(
            CreateIntelligenceSuggestion(
                uuid4(),
                "detection",
                None,
                "detection_rule_tuning",
                {},
                "m1",
                1,
                0.50,
                (),
                "too low",
                ("system",),
            )
        )


@pytest.mark.asyncio
async def test_reject_and_invalid_transition() -> None:
    c = AutonomousIntelligenceContainer()
    tenant = uuid4()
    created = await c.app.create_suggestion(
        CreateIntelligenceSuggestion(
            tenant,
            "campaign",
            None,
            "campaign_scenario",
            {},
            "m1",
            1,
            0.70,
            (),
            "scenario",
            ("system",),
        )
    )
    sid = UUID(created.suggestion_id)
    await c.app.reject(RejectSuggestion(tenant, sid, "arch", "not useful", ("red_team:architect",)))
    with pytest.raises(InvalidSuggestionTransition):
        await c.app.approve(ApproveSuggestion(tenant, sid, "arch", ("red_team:architect",)))


@pytest.mark.asyncio
async def test_model_deploy_threshold() -> None:
    c = AutonomousIntelligenceContainer()
    tenant = uuid4()
    roles = ("ai:ml_engineer",)
    await c.app.train_model(
        TrainOptimizationModel(tenant, "detection_rule_tuning", "m-det", 1, roles)
    )
    with pytest.raises(AccuracyThresholdNotMet):
        await c.app.deploy_model(
            DeployOptimizationModel(
                tenant, "m-det", "eu-ref-1", {"precision": 0.5, "recall": 0.5}, roles
            )
        )
    deployed = await c.app.deploy_model(
        DeployOptimizationModel(
            tenant, "m-det", "eu-ref-1", {"precision": 0.8, "recall": 0.75}, roles
        )
    )
    assert deployed.status == "deployed"
