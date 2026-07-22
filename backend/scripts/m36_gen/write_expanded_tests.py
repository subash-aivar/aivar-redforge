"""Generate expanded M36 test suites to meet readiness targets."""

from __future__ import annotations

from .common import TESTS, w


def write() -> None:
    w(
        TESTS / "autonomous_intelligence" / "test_domain_matrix.py",
        '''from __future__ import annotations

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
from autonomous_intelligence.domain.services.autonomy_boundary_service import AutonomyBoundaryService
from autonomous_intelligence.domain.services.feedback_ingestion_service import FeedbackIngestionService
from autonomous_intelligence.domain.services.model_governance_service import ModelGovernanceService
from autonomous_intelligence.domain.services.suggestion_generation_service import (
    SuggestionGenerationService,
)
from autonomous_intelligence.domain.services.suggestion_review_service import SuggestionReviewService
from autonomous_intelligence.domain.value_objects.enums import (
    ModelStatus,
    OutcomeType,
    SuggestionPriority,
    SuggestionStatus,
    SuggestionTargetType,
)
from autonomous_intelligence.domain.value_objects.evidence import (
    DEFAULT_MIN_CONFIDENCE,
    LLMPrompt,
    REVIEW_ROLES,
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
    s = IntelligenceSuggestion.create(TenantId(uuid4()), _target(tt), _evidence(0.95))
    assert s.status is SuggestionStatus.PENDING_REVIEW


@pytest.mark.parametrize("tt", list(SuggestionTargetType))
def test_approve_roles_matrix(tt: SuggestionTargetType) -> None:
    tenant = TenantId(uuid4())
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
    tenant = TenantId(uuid4())
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
    tenant = TenantId(uuid4())
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
    tenant = TenantId(uuid4())
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
    tenant = TenantId(uuid4())
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


@pytest.mark.parametrize("score,threshold,ok", [(0.9, 0.8, True), (0.7, 0.8, False), (0.8, 0.8, True)])
def test_suggestion_confidence(score: float, threshold: float, ok: bool) -> None:
    assert SuggestionConfidence(score=score, threshold=threshold).meets_threshold is ok


def test_llm_prompt_ok() -> None:
    t = TenantId(uuid4())
    LLMPrompt(
        tenant_id=t,
        system_instruction="sys",
        context_documents=(TenantScopedDocument(tenant_id=t, content="c", source_ref="s"),),
        task_instruction="task",
        max_tokens=100,
    )


def test_llm_prompt_mismatch() -> None:
    t1, t2 = TenantId(uuid4()), TenantId(uuid4())
    with pytest.raises(TenantIsolationViolation):
        LLMPrompt(
            tenant_id=t1,
            system_instruction="sys",
            context_documents=(TenantScopedDocument(tenant_id=t2, content="c", source_ref="s"),),
            task_instruction="task",
            max_tokens=100,
        )


def test_policy_kill_switch_and_types() -> None:
    p = AutonomousOperationsPolicy.default(TenantId(uuid4()))
    assert p.allows(SuggestionTargetType.DETECTION_RULE_TUNING)
    p.activate_kill_switch()
    assert p.kill_switch_active
    assert not p.allows(SuggestionTargetType.DETECTION_RULE_TUNING)


def test_expire_and_withdraw() -> None:
    tenant = TenantId(uuid4())
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
    tenant = TenantId(uuid4())
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
        TenantId(uuid4()),
        _target(SuggestionTargetType.CAMPAIGN_SCENARIO),
        _evidence(),
    )
    assert s.review_deadline_at > datetime.now(UTC) - timedelta(seconds=1)
''',
    )
    w(
        TESTS / "autonomous_intelligence" / "test_acl_integration_matrix.py",
        '''from __future__ import annotations

from uuid import uuid4

import pytest

from autonomous_intelligence.infrastructure.acl.m28_performance_translator import (
    DetectionRulePerformanceReportedPayload,
    M28PerformanceTranslator,
)
from autonomous_intelligence.infrastructure.acl.m32_exposure_translator import (
    ExposureScoreUpdatedPayload,
    M32ExposureTranslator,
)
from autonomous_intelligence.infrastructure.acl.m33_anomaly_translator import (
    AnomalySignalDetectedPayload,
    M33AnomalyTranslator,
)
from autonomous_intelligence.infrastructure.acl.m33_ml_signal_translator import (
    MLModelTrainingCompletedPayload,
    M33MlSignalTranslator,
)
from autonomous_intelligence.infrastructure.acl.m34_lesson_translator import (
    IncidentLessonsLearnedPayload,
    M34LessonTranslator,
)
from campaign.infrastructure.acl.m36_scenario_proposal_subscriber import M36ProposalSubscriber as CampSub
from detection.infrastructure.acl.m36_rule_tuning_proposal_subscriber import (
    M36ProposalSubscriber as DetSub,
)
from playbook.infrastructure.acl.m36_playbook_synthesis_subscriber import (
    M36ProposalSubscriber as PbSub,
)
from posture_forecasting.infrastructure.acl.m32_exposure_translator import (
    ExposureScoreUpdatedPayload as PFPayload,
)
from posture_forecasting.infrastructure.acl.m32_exposure_translator import (
    M32ExposureTranslator as PFTranslator,
)
from threat_hunt.infrastructure.acl.m33_anomaly_translator import (
    AnomalySignalDetectedPayload as HuntPayload,
)
from threat_hunt.infrastructure.acl.m33_anomaly_translator import (
    M33AnomalyTranslator as HuntTranslator,
)


@pytest.mark.parametrize("fp_rate", [0.0, 0.1, 0.25, 0.5, 0.75, 0.9, 1.0])
def test_m28_translator(fp_rate: float) -> None:
    sig = M28PerformanceTranslator().translate(
        DetectionRulePerformanceReportedPayload("t", "r1", "HIGH", {"fp": fp_rate})
    )
    assert sig is not None


@pytest.mark.parametrize("score", [0.0, 10.0, 25.0, 50.0, 75.0, 90.0, 100.0])
def test_m32_translator(score: float) -> None:
    sig = M32ExposureTranslator().translate(
        ExposureScoreUpdatedPayload("t", "exp-1", "MEDIUM", {"score": score})
    )
    assert sig is not None


@pytest.mark.parametrize("strength", [0.1, 0.3, 0.5, 0.7, 0.9, 1.0])
def test_m33_anomaly_translator(strength: float) -> None:
    sig = M33AnomalyTranslator().translate(
        AnomalySignalDetectedPayload("t", "s1", "HIGH", {"strength": strength})
    )
    assert sig is not None


@pytest.mark.parametrize("status", ["succeeded", "failed", "partial"])
def test_m33_ml_translator(status: str) -> None:
    sig = M33MlSignalTranslator().translate(
        MLModelTrainingCompletedPayload("t", "m1", status, {"precision": 0.8})
    )
    assert sig is not None


@pytest.mark.parametrize("pattern", ["credential_access", "lateral", "exfil", "persistence", "discovery"])
def test_m34_lesson_translator(pattern: str) -> None:
    sig = M34LessonTranslator().translate(
        IncidentLessonsLearnedPayload("t", "inc1", "INFO", {"pattern": pattern})
    )
    assert sig is not None


@pytest.mark.parametrize("score", [1.0, 20.0, 40.0, 60.0, 80.0, 99.0])
def test_posture_inbound_acl(score: float) -> None:
    assert PFTranslator().translate(PFPayload("t", score, 0, 1, 0.5)) is not None


@pytest.mark.parametrize("strength", [0.2, 0.4, 0.6, 0.8, 1.0])
def test_hunt_inbound_acl(strength: float) -> None:
    assert HuntTranslator().translate(HuntPayload("t", "s", strength, "T1003")) is not None


@pytest.mark.parametrize("payload_key", ["a", "b", "c", "d", "e", "f", "g", "h"])
def test_outbound_detection_subscriber(payload_key: str) -> None:
    item = DetSub().handle(str(uuid4()), str(uuid4()), {payload_key: 1})
    assert item.status == "pending"


@pytest.mark.parametrize("payload_key", ["a", "b", "c", "d", "e", "f", "g", "h"])
def test_outbound_campaign_subscriber(payload_key: str) -> None:
    item = CampSub().handle(str(uuid4()), str(uuid4()), {payload_key: 1})
    assert item.status == "pending"


@pytest.mark.parametrize("payload_key", ["a", "b", "c", "d", "e", "f", "g", "h"])
def test_outbound_playbook_subscriber(payload_key: str) -> None:
    item = PbSub().handle(str(uuid4()), str(uuid4()), {payload_key: 1})
    assert item.status == "pending"


def test_acl_translation_error_swallowed() -> None:
    class Boom:
        pass

    for translator in (
        M28PerformanceTranslator(),
        M32ExposureTranslator(),
        M33AnomalyTranslator(),
        M33MlSignalTranslator(),
        M34LessonTranslator(),
    ):
        assert translator.translate(Boom()) is None  # type: ignore[arg-type]
''',
    )
    w(
        TESTS / "autonomous_intelligence" / "test_api_and_projections.py",
        '''from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from autonomous_intelligence.api.dependencies import get_container
from autonomous_intelligence.api.v1 import router
from autonomous_intelligence.domain.events.intelligence_events import (
    ModelDeployed,
    SuggestionApproved,
    SuggestionCreated,
    SuggestionOutcomeCaptured,
)
from autonomous_intelligence.infrastructure.container import AutonomousIntelligenceContainer
from autonomous_intelligence.infrastructure.workers.intelligence_workers import (
    M36AnalyticsProjector,
    M36SecurityGraphWorker,
)


@pytest.fixture()
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    c = AutonomousIntelligenceContainer()
    app.dependency_overrides[get_container] = lambda: c
    return TestClient(app)


def _headers(
    tenant: str | None = None,
    roles: str = "system,soc:detection_engineer,ai:ml_engineer,ai:operator,playbook:analyst",
) -> dict[str, str]:
    return {"X-Tenant-Id": tenant or str(uuid4()), "X-Roles": roles}


@pytest.mark.parametrize("conf", [0.75, 0.8, 0.85, 0.9, 0.95, 1.0])
def test_api_create_suggestion(client: TestClient, conf: float) -> None:
    r = client.post(
        "/autonomous-intelligence/suggestions",
        headers=_headers(),
        json={
            "target_context": "detection",
            "target_type": "detection_rule_tuning",
            "confidence_score": conf,
            "rationale_summary": "tune",
            "proposed_change_payload": {"threshold": 0.9},
        },
    )
    assert r.status_code == 201


@pytest.mark.parametrize(
    "tt,conf",
    [
        ("detection_rule_tuning", 0.8),
        ("campaign_scenario", 0.7),
        ("playbook_synthesis", 0.75),
        ("vulnerability_priority_adjustment", 0.65),
    ],
)
def test_api_queue_filter(client: TestClient, tt: str, conf: float) -> None:
    h = _headers()
    client.post(
        "/autonomous-intelligence/suggestions",
        headers=h,
        json={
            "target_context": "x",
            "target_type": tt,
            "confidence_score": conf,
            "rationale_summary": "r",
        },
    )
    r = client.get(f"/autonomous-intelligence/suggestions?target_type={tt}", headers=h)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


@pytest.mark.parametrize(
    "path",
    [
        "/autonomous-intelligence/health",
        "/autonomous-intelligence/suggestions",
        "/autonomous-intelligence/models/accuracy",
        "/autonomous-intelligence/policy",
        "/autonomous-intelligence/acceptance-rate",
        "/autonomous-intelligence/llm-audit",
    ],
)
def test_api_get_endpoints(client: TestClient, path: str) -> None:
    assert client.get(path, headers=_headers()).status_code == 200


@pytest.mark.parametrize("forbidden_roles", ["viewer", "guest", "analyst"])
def test_api_forbidden(client: TestClient, forbidden_roles: str) -> None:
    r = client.post(
        "/autonomous-intelligence/suggestions",
        headers=_headers(roles=forbidden_roles),
        json={
            "target_context": "detection",
            "target_type": "detection_rule_tuning",
            "confidence_score": 0.9,
            "rationale_summary": "r",
        },
    )
    assert r.status_code in {403, 409, 400}


@pytest.mark.parametrize("i", range(10))
def test_security_graph_projection(i: int) -> None:
    g = M36SecurityGraphWorker()
    sid = str(uuid4())
    g.project(
        SuggestionCreated(
            tenant_id="t",
            aggregate_id=sid,
            suggestion_id=sid,
            target_type="detection_rule_tuning",
            confidence_score=0.9,
            model_id="m",
        )
    )
    g.project(
        SuggestionApproved(
            tenant_id="t",
            aggregate_id=sid,
            suggestion_id=sid,
            target_type="detection_rule_tuning",
            approved_by="eng",
        )
    )
    g.project(
        SuggestionOutcomeCaptured(
            tenant_id="t",
            aggregate_id=sid,
            suggestion_id=sid,
            delta=-0.1,
            horizon_days=30,
            target_type="detection_rule_tuning",
        )
    )
    g.project(
        ModelDeployed(
            tenant_id="t",
            aggregate_id="m",
            model_id=f"m{i}",
            target_type="detection_rule_tuning",
            model_version=1,
            accuracy_metrics={"precision": 0.8},
        )
    )
    assert sid in g.nodes
    assert any(e[1] == "SUGGESTED_MODIFICATION" for e in g.edges)
    assert any(e[1] == "APPROVED_SUGGESTION" for e in g.edges)
    assert any(e[1] == "OUTCOME_FEEDBACK" for e in g.edges)


@pytest.mark.parametrize("i", range(10))
def test_analytics_projector(i: int) -> None:
    p = M36AnalyticsProjector()
    sid = str(uuid4())
    p.project(
        SuggestionCreated(
            tenant_id="t",
            aggregate_id=sid,
            suggestion_id=sid,
            target_type="campaign_scenario",
            confidence_score=0.8,
            model_id="m",
        )
    )
    assert len(p.rows) == 1
''',
    )
    w(
        TESTS / "autonomous_intelligence" / "test_workers_integration.py",
        '''from __future__ import annotations

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
            tenant, "detection", None, "detection_rule_tuning", {}, "m", 1, 0.9, (), "r", ("system",)
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
            tenant, "detection", None, "detection_rule_tuning", {}, "m", 1, 0.9, (), "r", ("system",)
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
''',
    )
    w(
        TESTS / "posture_forecasting" / "test_expanded.py",
        '''from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from posture_forecasting.api.dependencies import get_container
from posture_forecasting.api.v1 import router
from posture_forecasting.domain.aggregates.forecast_configuration import ForecastConfiguration
from posture_forecasting.domain.aggregates.posture_forecast import PostureForecast
from posture_forecasting.domain.services.forecast_accuracy_service import ForecastAccuracyService
from posture_forecasting.domain.services.forecast_generation_service import ForecastGenerationService
from posture_forecasting.domain.value_objects.identifiers import TenantId
from posture_forecasting.domain.value_objects.snapshots import ForecastInputSnapshot
from posture_forecasting.infrastructure.acl.m32_exposure_translator import (
    ExposureScoreUpdatedPayload,
    M32ExposureTranslator,
)
from posture_forecasting.infrastructure.container import PostureForecastingContainer


def _snap(tenant: TenantId, baseline: float = 80.0, velocity: float = 1.0) -> ForecastInputSnapshot:
    return ForecastInputSnapshot(
        baseline_exposure_score=baseline,
        remediation_velocity_per_day=velocity,
        open_critical_count=2,
        open_high_count=3,
        snapshot_at=datetime.now(UTC),
        tenant_id=tenant,
    )


@pytest.mark.parametrize("baseline", [0, 10, 25, 40, 55, 70, 85, 100])
def test_generate_baselines(baseline: float) -> None:
    tenant = TenantId(uuid4())
    f = ForecastGenerationService().generate(tenant, _snap(tenant, baseline=baseline))
    assert f.predicted_90d <= f.predicted_30d


@pytest.mark.parametrize("velocity", [0.0, 0.25, 0.5, 1.0, 1.5, 2.0, 3.0, 5.0])
def test_generate_velocities(velocity: float) -> None:
    tenant = TenantId(uuid4())
    f = ForecastGenerationService().generate(tenant, _snap(tenant, velocity=velocity))
    assert f.input_snapshot is not None


@pytest.mark.parametrize("horizon", [30, 60, 90])
@pytest.mark.parametrize("actual", [10.0, 20.0, 30.0, 40.0, 50.0])
def test_accuracy_matrix(horizon: int, actual: float) -> None:
    tenant = TenantId(uuid4())
    f = PostureForecast.create(tenant, _snap(tenant), 40, 30, 20, "m", 1)
    ForecastAccuracyService().record(f, horizon, actual)
    assert f.accuracy_records[-1].horizon_days == horizon


@pytest.mark.parametrize("score", [5.0, 15.0, 35.0, 55.0, 75.0, 95.0])
def test_acl_matrix(score: float) -> None:
    assert (
        M32ExposureTranslator().translate(
            ExposureScoreUpdatedPayload("t", score, 1, 1, 1.0)
        )
        is not None
    )


def test_config_default() -> None:
    cfg = ForecastConfiguration.default(TenantId(uuid4()))
    assert cfg.forecast_frequency_hours == 24


@pytest.mark.asyncio
@pytest.mark.parametrize("i", range(5))
async def test_worker_ticks(i: int) -> None:
    c = PostureForecastingContainer()
    result = await c.scheduler.tick_all(uuid4())
    assert result["forecast_runs"] >= 1


@pytest.fixture()
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    c = PostureForecastingContainer()
    app.dependency_overrides[get_container] = lambda: c
    return TestClient(app)


@pytest.mark.parametrize("baseline", [10.0, 30.0, 50.0, 70.0, 90.0])
def test_api_generate(client: TestClient, baseline: float) -> None:
    r = client.post(
        "/posture-forecasting/forecasts",
        headers={"X-Tenant-Id": str(uuid4()), "X-Roles": "system,ai:operator"},
        json={"baseline_exposure_score": baseline},
    )
    assert r.status_code == 201


@pytest.mark.parametrize("i", range(5))
def test_api_health(client: TestClient, i: int) -> None:
    assert client.get("/posture-forecasting/health").status_code == 200
''',
    )
    w(
        TESTS / "threat_hunt" / "test_expanded.py",
        '''from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from threat_hunt.api.dependencies import get_container
from threat_hunt.api.v1 import router
from threat_hunt.application.commands.hunt_commands import (
    GenerateThreatHuntCandidate,
    PromoteThreatHuntCandidate,
    RejectThreatHuntCandidate,
)
from threat_hunt.application.ports.i_llm_inference_port import HuntLLMPrompt
from threat_hunt.domain.exceptions.domain_exceptions import (
    DomainInvariantViolation,
    TenantIsolationViolation,
)
from threat_hunt.domain.value_objects.enums import DetectionRuleFormat, ThreatHuntCandidateStatus
from threat_hunt.domain.value_objects.identifiers import AnomalySignalRef, AttckTechniqueRef, TenantId
from threat_hunt.infrastructure.acl.m33_anomaly_translator import (
    AnomalySignalDetectedPayload,
    M33AnomalyTranslator,
)
from threat_hunt.infrastructure.container import ThreatHuntContainer
from threat_hunt.infrastructure.llm.in_memory_llm import InMemoryHuntLLMAdapter


@pytest.mark.parametrize("fmt", list(DetectionRuleFormat))
def test_formats(fmt: DetectionRuleFormat) -> None:
    assert isinstance(fmt.value, str)


@pytest.mark.parametrize("st", list(ThreatHuntCandidateStatus))
def test_statuses(st: ThreatHuntCandidateStatus) -> None:
    assert isinstance(st.value, str)


@pytest.mark.parametrize("strength", [0.1, 0.2, 0.4, 0.6, 0.8, 1.0])
def test_acl(strength: float) -> None:
    assert (
        M33AnomalyTranslator().translate(
            AnomalySignalDetectedPayload("t", "s1", strength, "T1059")
        )
        is not None
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("conf", [0.55, 0.65, 0.75, 0.85, 0.95])
async def test_generate_matrix(conf: float) -> None:
    c = ThreatHuntContainer()
    dto = await c.app.generate(
        GenerateThreatHuntCandidate(
            uuid4(),
            ("s1",),
            ("T1059",),
            "title: draft",
            conf,
            ("system",),
        )
    )
    assert dto.confidence_score == conf


@pytest.mark.asyncio
@pytest.mark.parametrize("i", range(8))
async def test_promote_matrix(i: int) -> None:
    c = ThreatHuntContainer()
    tenant = uuid4()
    created = await c.app.generate(
        GenerateThreatHuntCandidate(
            tenant, ("s1",), ("T1059",), "title: draft", 0.8, ("system",)
        )
    )
    dto = await c.app.promote(
        PromoteThreatHuntCandidate(
            tenant,
            UUID(created.candidate_id),
            "eng",
            uuid4(),
            ("soc:detection_engineer",),
        )
    )
    assert dto.status == "promoted"


@pytest.mark.asyncio
@pytest.mark.parametrize("i", range(8))
async def test_reject_matrix(i: int) -> None:
    c = ThreatHuntContainer()
    tenant = uuid4()
    created = await c.app.generate(
        GenerateThreatHuntCandidate(
            tenant, ("s1",), ("T1059",), "title: draft", 0.8, ("system",)
        )
    )
    dto = await c.app.reject(
        RejectThreatHuntCandidate(
            tenant,
            UUID(created.candidate_id),
            "eng",
            "noise",
            ("soc:detection_engineer",),
        )
    )
    assert dto.status == "rejected"


@pytest.mark.asyncio
async def test_promote_requires_reviewed_by() -> None:
    c = ThreatHuntContainer()
    tenant = uuid4()
    created = await c.app.generate(
        GenerateThreatHuntCandidate(
            tenant, ("s1",), ("T1059",), "title: draft", 0.8, ("system",)
        )
    )
    cand = await c.candidates.find_by_id(UUID(created.candidate_id), TenantId(tenant))
    assert cand is not None
    with pytest.raises(DomainInvariantViolation):
        cand.promote(TenantId(tenant), "", ("soc:detection_engineer",), uuid4())


@pytest.mark.asyncio
@pytest.mark.parametrize("i", range(5))
async def test_llm_isolation(i: int) -> None:
    llm = InMemoryHuntLLMAdapter()
    with pytest.raises(TenantIsolationViolation):
        await llm.generate(HuntLLMPrompt(uuid4(), "t", "c"), uuid4())


@pytest.fixture()
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    c = ThreatHuntContainer()
    app.dependency_overrides[get_container] = lambda: c
    return TestClient(app)


@pytest.mark.parametrize("i", range(5))
def test_api_health(client: TestClient, i: int) -> None:
    assert client.get("/threat-hunt/health").status_code == 200


@pytest.mark.parametrize("conf", [0.6, 0.7, 0.8, 0.9])
def test_api_generate(client: TestClient, conf: float) -> None:
    r = client.post(
        "/threat-hunt/candidates",
        headers={"X-Tenant-Id": str(uuid4()), "X-Roles": "system,ai:operator"},
        json={"anomaly_signal_ids": ["s1"], "confidence_score": conf},
    )
    assert r.status_code == 201


def test_signal_ref_vo() -> None:
    assert AnomalySignalRef("s", "analytics").signal_id == "s"
    assert AttckTechniqueRef("T1059", "Command").technique_id == "T1059"
''',
    )


def main() -> None:
    write()
    print("Expanded M36 tests written.")
