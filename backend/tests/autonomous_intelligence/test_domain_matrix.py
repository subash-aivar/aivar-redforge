from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from autonomous_intelligence.domain.aggregates.autonomous_operations_policy import (
    AutonomousOperationsPolicy,
)
from autonomous_intelligence.domain.aggregates.intelligence_suggestion import IntelligenceSuggestion
from autonomous_intelligence.domain.aggregates.optimization_model import OptimizationModel
from autonomous_intelligence.domain.aggregates.suggestion_outcome import SuggestionOutcome
from autonomous_intelligence.domain.exceptions.domain_exceptions import (
    AccuracyThresholdNotMet,
    AutonBoundaryViolation,
    ConfidenceThresholdNotMet,
    DomainInvariantViolation,
    InvalidSuggestionTransition,
    TenantIsolationViolation,
)
from autonomous_intelligence.domain.services.autonomy_boundary_service import (
    AutonomyBoundaryService,
)
from autonomous_intelligence.domain.services.feedback_ingestion_service import (
    FeedbackIngestionService,
)
from autonomous_intelligence.domain.services.model_governance_service import ModelGovernanceService
from autonomous_intelligence.domain.services.suggestion_generation_service import (
    SuggestionGenerationService,
)
from autonomous_intelligence.domain.services.suggestion_review_service import (
    SuggestionReviewService,
)
from autonomous_intelligence.domain.value_objects.enums import (
    ModelStatus,
    OutcomeType,
    SuggestionPriority,
    SuggestionStatus,
    SuggestionTargetType,
)
from autonomous_intelligence.domain.value_objects.evidence import (
    DEFAULT_MIN_CONFIDENCE,
    REVIEW_ROLES,
    LLMPrompt,
    SuggestionConfidence,
    SuggestionEvidence,
    SuggestionTargetRef,
    TenantScopedDocument,
)
from autonomous_intelligence.domain.value_objects.identifiers import TenantId


def _evidence(score: float = 0.9) -> SuggestionEvidence:
    return SuggestionEvidence(
        model_id="m",
        model_version=1,
        confidence_score=score,
        supporting_signal_refs=("s1",),
        rationale_summary="rationale",
        generated_at=datetime.now(UTC),
    )


def _target(tt: SuggestionTargetType) -> SuggestionTargetRef:
    return SuggestionTargetRef(
        target_context=tt.value.split("_")[0],
        target_id=None,
        target_type=tt,
        proposed_change_payload={"k": "v"},
    )


@pytest.mark.parametrize("tt", list(SuggestionTargetType))
def test_suggestion_create_status_pending(tt: SuggestionTargetType) -> None:
    s = IntelligenceSuggestion.create(TenantId.generate(), _target(tt), _evidence(0.95))
    assert s.status is SuggestionStatus.PENDING_REVIEW


@pytest.mark.parametrize("tt", list(SuggestionTargetType))
def test_approve_roles_matrix(tt: SuggestionTargetType) -> None:
    tenant = TenantId.generate()
    s = IntelligenceSuggestion.create(tenant, _target(tt), _evidence(0.95))
    SuggestionReviewService().approve(s, tenant, "reviewer", (REVIEW_ROLES[tt],))
    assert s.status is SuggestionStatus.APPROVED


@pytest.mark.parametrize(
    "bad",
    [
        SuggestionStatus.APPROVED,
        SuggestionStatus.REJECTED,
        SuggestionStatus.APPLIED,
        SuggestionStatus.EXPIRED,
        SuggestionStatus.WITHDRAWN,
    ],
)
def test_invalid_approve_from_terminal(bad: SuggestionStatus) -> None:
    tenant = TenantId.generate()
    s = IntelligenceSuggestion.create(
        tenant, _target(SuggestionTargetType.DETECTION_RULE_TUNING), _evidence()
    )
    s.status = bad
    with pytest.raises(InvalidSuggestionTransition):
        s.approve(tenant, "r", ("soc:detection_engineer",))


@pytest.mark.parametrize("tt", list(SuggestionTargetType))
def test_confidence_defaults(tt: SuggestionTargetType) -> None:
    assert 0.5 <= DEFAULT_MIN_CONFIDENCE[tt] <= 0.9


@pytest.mark.parametrize("tt", list(SuggestionTargetType))
def test_generation_service_threshold(tt: SuggestionTargetType) -> None:
    tenant = TenantId.generate()
    policy = AutonomousOperationsPolicy.default(tenant)
    low = DEFAULT_MIN_CONFIDENCE[tt] - 0.05
    with pytest.raises(ConfidenceThresholdNotMet):
        SuggestionGenerationService().create_if_eligible(
            tenant,
            _target(tt),
            SuggestionEvidence(
                model_id="m",
                model_version=1,
                confidence_score=low,
                supporting_signal_refs=(),
                rationale_summary="x",
                generated_at=datetime.now(UTC),
            ),
            min_confidence=policy.min_confidence(tt),
            kill_switch_active=False,
            enabled=True,
        )


@pytest.mark.parametrize(
    "metrics,ok",
    [
        ({"precision": 0.8, "recall": 0.75}, True),
        ({"precision": 0.5, "recall": 0.75}, False),
        ({"precision": 0.8, "recall": 0.5}, False),
    ],
)
def test_detection_accuracy_gate(metrics: dict[str, float], ok: bool) -> None:
    tenant = TenantId.generate()
    model = OptimizationModel.start_training(
        tenant, SuggestionTargetType.DETECTION_RULE_TUNING, "m", 1
    )
    model.mark_validating(metrics)
    gov = ModelGovernanceService()
    if ok:
        gov.deploy(model, tenant, "eu-ref")
        assert model.status is ModelStatus.DEPLOYED
    else:
        with pytest.raises(AccuracyThresholdNotMet):
            gov.deploy(model, tenant, "eu-ref")


@pytest.mark.parametrize(
    "tt,metrics",
    [
        (SuggestionTargetType.CAMPAIGN_SCENARIO, {"relevance_score": 0.7}),
        (SuggestionTargetType.PLAYBOOK_SYNTHESIS, {"structure_score": 0.75}),
        (SuggestionTargetType.VULNERABILITY_PRIORITY_ADJUSTMENT, {"rank_correlation": 0.65}),
    ],
)
def test_other_accuracy_gates(tt: SuggestionTargetType, metrics: dict[str, float]) -> None:
    tenant = TenantId.generate()
    model = OptimizationModel.start_training(tenant, tt, f"m-{tt.value}", 1)
    model.mark_validating(metrics)
    ModelGovernanceService().deploy(model, tenant, "eu")
    assert model.status is ModelStatus.DEPLOYED


@pytest.mark.parametrize("pri", list(SuggestionPriority))
def test_priorities(pri: SuggestionPriority) -> None:
    assert isinstance(pri.value, str)


@pytest.mark.parametrize("st", list(SuggestionStatus))
def test_statuses(st: SuggestionStatus) -> None:
    assert st.value == st.name.lower()


@pytest.mark.parametrize("ms", list(ModelStatus))
def test_model_statuses(ms: ModelStatus) -> None:
    assert isinstance(ms.value, str)


@pytest.mark.parametrize("ot", list(OutcomeType))
def test_outcomes(ot: OutcomeType) -> None:
    assert isinstance(ot.value, str)


@pytest.mark.parametrize(
    "score,threshold,ok", [(0.9, 0.8, True), (0.7, 0.8, False), (0.8, 0.8, True)]
)
def test_suggestion_confidence(score: float, threshold: float, ok: bool) -> None:
    assert SuggestionConfidence(score=score, threshold=threshold).meets_threshold is ok


def test_llm_prompt_ok() -> None:
    t = TenantId.generate()
    LLMPrompt(
        tenant_id=t,
        system_instruction="sys",
        context_documents=(TenantScopedDocument(tenant_id=t, content="c", source_ref="s"),),
        task_instruction="task",
        max_tokens=100,
    )


def test_llm_prompt_mismatch() -> None:
    t1, t2 = TenantId.generate(), TenantId.generate()
    with pytest.raises(TenantIsolationViolation):
        LLMPrompt(
            tenant_id=t1,
            system_instruction="sys",
            context_documents=(TenantScopedDocument(tenant_id=t2, content="c", source_ref="s"),),
            task_instruction="task",
            max_tokens=100,
        )


def test_policy_kill_switch_and_types() -> None:
    p = AutonomousOperationsPolicy.default(TenantId.generate())
    assert p.allows(SuggestionTargetType.DETECTION_RULE_TUNING)
    p.activate_kill_switch()
    assert p.kill_switch_active
    assert not p.allows(SuggestionTargetType.DETECTION_RULE_TUNING)


def test_expire_and_withdraw() -> None:
    tenant = TenantId.generate()
    s = IntelligenceSuggestion.create(
        tenant, _target(SuggestionTargetType.PLAYBOOK_SYNTHESIS), _evidence()
    )
    s.expire(tenant)
    assert s.status is SuggestionStatus.EXPIRED
    s2 = IntelligenceSuggestion.create(
        tenant, _target(SuggestionTargetType.PLAYBOOK_SYNTHESIS), _evidence()
    )
    s2.withdraw(tenant, "retrain")
    assert s2.status is SuggestionStatus.WITHDRAWN


def test_feedback_ingestion() -> None:
    tenant = TenantId.generate()
    model = OptimizationModel.start_training(
        tenant, SuggestionTargetType.DETECTION_RULE_TUNING, "m", 1
    )
    model.mark_validating({"precision": 0.8, "recall": 0.75})
    ModelGovernanceService().deploy(model, tenant, "eu")
    outcome = SuggestionOutcome.create_pending(
        uuid4(), tenant, SuggestionTargetType.DETECTION_RULE_TUNING, 30, 0.5
    )
    outcome.record_measurement(0.4, datetime.now(UTC))
    FeedbackIngestionService().ingest(model, outcome)
    assert model.feedback_sample_count == 1


@pytest.mark.parametrize(
    "name",
    ["DetectionRule", "RuleVersion", "ScenarioTemplate", "PlaybookVersion", "Vulnerability"],
)
def test_autonomy_boundary_all_targets(name: str) -> None:
    with pytest.raises(AutonBoundaryViolation):
        AutonomyBoundaryService().assert_no_direct_mutation(name)


def test_evidence_bounds() -> None:
    with pytest.raises(DomainInvariantViolation):
        SuggestionEvidence(
            model_id="m",
            model_version=1,
            confidence_score=1.5,
            supporting_signal_refs=(),
            rationale_summary="x",
            generated_at=datetime.now(UTC),
        )


def test_review_deadline_present() -> None:
    s = IntelligenceSuggestion.create(
        TenantId.generate(),
        _target(SuggestionTargetType.CAMPAIGN_SCENARIO),
        _evidence(),
    )
    assert s.review_deadline_at > datetime.now(UTC) - timedelta(seconds=1)
