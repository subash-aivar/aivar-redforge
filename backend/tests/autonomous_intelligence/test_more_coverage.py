from __future__ import annotations

from datetime import UTC, datetime

import pytest

from autonomous_intelligence.application.commands.intelligence_commands import (
    CreateIntelligenceSuggestion,
)
from autonomous_intelligence.domain.aggregates.autonomous_operations_policy import (
    AutonomousOperationsPolicy,
)
from autonomous_intelligence.domain.aggregates.intelligence_suggestion import IntelligenceSuggestion
from autonomous_intelligence.domain.exceptions.domain_exceptions import DomainInvariantViolation
from autonomous_intelligence.domain.value_objects.enums import SuggestionTargetType
from autonomous_intelligence.domain.value_objects.evidence import (
    SuggestionEvidence,
    SuggestionTargetRef,
)
from autonomous_intelligence.domain.value_objects.identifiers import TenantId
from autonomous_intelligence.infrastructure.acl.m28_performance_translator import (
    DetectionRulePerformanceReportedPayload,
    M28PerformanceTranslator,
)
from autonomous_intelligence.infrastructure.container import AutonomousIntelligenceContainer
from redforge.shared.identifiers import EntityId


@pytest.mark.parametrize("tt", list(SuggestionTargetType))
@pytest.mark.asyncio
async def test_create_all_target_types(tt: SuggestionTargetType) -> None:
    c = AutonomousIntelligenceContainer()
    # ensure confidence meets default
    conf = {
        SuggestionTargetType.DETECTION_RULE_TUNING: 0.80,
        SuggestionTargetType.CAMPAIGN_SCENARIO: 0.70,
        SuggestionTargetType.PLAYBOOK_SYNTHESIS: 0.75,
        SuggestionTargetType.VULNERABILITY_PRIORITY_ADJUSTMENT: 0.65,
    }[tt]
    dto = await c.app.create_suggestion(
        CreateIntelligenceSuggestion(
            EntityId.generate(),
            tt.value.split("_")[0],
            None,
            tt.value,
            {},
            "m",
            1,
            conf,
            ("s",),
            "rationale",
            ("system",),
        )
    )
    assert dto.target_type == tt.value


@pytest.mark.asyncio
async def test_kill_switch_blocks_generation() -> None:
    c = AutonomousIntelligenceContainer()
    tenant = EntityId.generate()
    policy = await c.policies.get_or_create_default(TenantId(tenant))
    policy.activate_kill_switch()
    await c.policies.save(policy, TenantId(tenant))
    with pytest.raises(DomainInvariantViolation):
        await c.app.create_suggestion(
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
                "x",
                ("system",),
            )
        )


def test_withdraw() -> None:
    tenant = TenantId.generate()
    s = IntelligenceSuggestion.create(
        tenant,
        SuggestionTargetRef(
            target_context="detection",
            target_id=None,
            target_type=SuggestionTargetType.DETECTION_RULE_TUNING,
            proposed_change_payload={},
        ),
        SuggestionEvidence(
            model_id="m",
            model_version=1,
            confidence_score=0.9,
            supporting_signal_refs=(),
            rationale_summary="r",
            generated_at=datetime.now(UTC),
        ),
    )
    s.withdraw(tenant, "retrain")
    assert s.status.value == "withdrawn"


def test_acl_translators() -> None:
    sig = M28PerformanceTranslator().translate(
        DetectionRulePerformanceReportedPayload("t", "r1", "HIGH", {"fp": 0.2})
    )
    assert sig is not None


def test_policy_default() -> None:
    p = AutonomousOperationsPolicy.default(TenantId.generate())
    assert p.allows(SuggestionTargetType.PLAYBOOK_SYNTHESIS)
