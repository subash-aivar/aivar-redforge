"""Sprint 40 Remediation — 26 integration tests.

OBJECTIVE 1: Production composition root (RedTeamOrchestratorFactory wired in
             RuntimeContainer).
OBJECTIVE 2: Real runtime reachability — the full evaluation control loop is
             accessible from the same composition path as the real application.

Principal Engineering Reviews:
  PE-1: RuntimeContainer owns RedTeamOrchestratorFactory singleton
  PE-2: Factory builds fully-wired RedTeamOrchestrator per campaign
  PE-3: EvaluationPipeline has ConsensusEngine + EvaluationPolicyEnforcer
  PE-4: ValidationService has with_evaluation_adapter wired
  PE-5: organization_id comes exclusively from RedTeamRequest (not body/query)
  PE-6: No duplicate EvaluationPipeline; no empty evaluator list

These tests use NO external network calls. They verify composition structure,
not execution results. The RedTeamOrchestrator.execute() is NOT called in
these tests — those would require a live LLM endpoint.
"""

from __future__ import annotations

from redforge.application.platform.runtime_container import (
    RuntimeContainer,
    build_runtime_container,
)
from redforge.application.red_team.campaign_intelligence import (
    RuleBasedCampaignIntelligenceService,
)
from redforge.application.red_team.evaluation_intelligence import (
    EvaluationDrivenIntelligenceAdapter,
)
from redforge.application.red_team.factory import (
    RedTeamOrchestratorFactory,
    _build_red_team_factory,
    _default_evaluators,
)
from redforge.application.red_team.orchestrator import RedTeamOrchestrator
from redforge.application.runtime.evaluation.consensus import ConsensusEngine
from redforge.application.runtime.evaluation.pipeline import EvaluationPipeline
from redforge.application.runtime.evaluation.policy import EvaluationPolicyEnforcer
from redforge.application.validation_service import ValidationService
from redforge.core.config import get_settings
from redforge.domain.red_team.eval_signals import (
    EVAL_KEY_CONSENSUS_STATE,
    EVAL_KEY_EVALUATION_QUALITY,
    EVAL_KEY_RECOMMENDED_ACTION,
    EVAL_KEY_REQUIRES_MORE_EVIDENCE,
    EvalQuality,
    EvalSignals,
    parse_eval_signals,
)

# ─── Helpers ──────────────────────────────────────────────────────────────────


def _make_container() -> RuntimeContainer:
    """Build a real RuntimeContainer via the production path."""
    return build_runtime_container(get_settings())


def _make_factory() -> RedTeamOrchestratorFactory:
    return _build_red_team_factory()


class _MinimalProviderAdapter:
    """Minimal concrete provider adapter for composition tests.

    Does NOT make network calls. Only satisfies the type contract so
    factory.build() can construct the object graph.
    """

    async def chat_completion(
        self, messages: list[dict[str, str]], model: str | None = None
    ) -> dict[str, object]:
        return {"content": "test", "model": model or "test", "usage": {}}


# ─── OBJECTIVE 1 — PE-1: RuntimeContainer owns RedTeamOrchestratorFactory ────


class TestRuntimeContainerOwnsFactory:
    def test_container_has_red_team_factory_field(self) -> None:
        """PE-1a: red_team_factory attribute exists on RuntimeContainer."""
        container = _make_container()
        assert hasattr(container, "red_team_factory")

    def test_red_team_factory_is_not_none(self) -> None:
        """PE-1b: factory is set (not left as None default) by build_runtime_container."""
        container = _make_container()
        assert container.red_team_factory is not None

    def test_red_team_factory_is_correct_type(self) -> None:
        """PE-1c: factory is a RedTeamOrchestratorFactory, not Any/object."""
        container = _make_container()
        assert isinstance(container.red_team_factory, RedTeamOrchestratorFactory)

    def test_build_runtime_container_is_deterministic(self) -> None:
        """PE-1d: two calls to build_runtime_container produce independent containers."""
        c1 = _make_container()
        c2 = _make_container()
        assert c1 is not c2
        assert c1.red_team_factory is not c2.red_team_factory

    def test_factory_singleton_stays_on_container(self) -> None:
        """PE-1e: retrieving red_team_factory twice from same container returns same object."""
        container = _make_container()
        f1 = container.red_team_factory
        f2 = container.red_team_factory
        assert f1 is f2


# ─── PE-2: Factory builds fully-wired RedTeamOrchestrator per campaign ────────


class TestFactoryBuildsOrchestrator:
    def test_build_returns_orchestrator(self) -> None:
        """PE-2a: factory.build() returns a RedTeamOrchestrator."""
        factory = _make_factory()
        orch = factory.build(
            provider_adapter=_MinimalProviderAdapter(),
            uow_factory=None,
        )
        assert isinstance(orch, RedTeamOrchestrator)

    def test_each_build_call_returns_new_orchestrator(self) -> None:
        """PE-2b: two build() calls produce independent orchestrators."""
        factory = _make_factory()
        adapter = _MinimalProviderAdapter()
        orch1 = factory.build(provider_adapter=adapter, uow_factory=None)
        orch2 = factory.build(provider_adapter=adapter, uow_factory=None)
        assert orch1 is not orch2

    def test_build_without_kg_does_not_raise(self) -> None:
        """PE-2c: knowledge_graph=None is a valid production configuration."""
        factory = _make_factory()
        orch = factory.build(
            provider_adapter=_MinimalProviderAdapter(),
            uow_factory=None,
            knowledge_graph=None,
        )
        assert orch is not None

    def test_orchestrator_has_validation_service(self) -> None:
        """PE-2d: orchestrator._validation_service is a real ValidationService."""
        factory = _make_factory()
        orch = factory.build(
            provider_adapter=_MinimalProviderAdapter(),
            uow_factory=None,
        )
        assert isinstance(orch._validation_service, ValidationService)

    def test_orchestrator_has_campaign_intelligence(self) -> None:
        """PE-2e: orchestrator._campaign_intelligence is RuleBasedCampaignIntelligenceService."""
        factory = _make_factory()
        orch = factory.build(
            provider_adapter=_MinimalProviderAdapter(),
            uow_factory=None,
        )
        assert isinstance(orch._campaign_intelligence, RuleBasedCampaignIntelligenceService)


# ─── PE-3: EvaluationPipeline has ConsensusEngine + EvaluationPolicyEnforcer ─


class TestEvaluationPipelineComposition:
    def test_factory_has_evaluation_pipeline(self) -> None:
        """PE-3a: factory.evaluation_pipeline returns the singleton EvaluationPipeline."""
        factory = _make_factory()
        assert isinstance(factory.evaluation_pipeline, EvaluationPipeline)

    def test_pipeline_has_consensus_engine(self) -> None:
        """PE-3b: EvaluationPipeline._consensus_engine is a ConsensusEngine."""
        factory = _make_factory()
        pipeline = factory.evaluation_pipeline
        assert isinstance(pipeline._consensus_engine, ConsensusEngine)

    def test_pipeline_has_policy_enforcer(self) -> None:
        """PE-3c: EvaluationPipeline._policy_enforcer is EvaluationPolicyEnforcer."""
        factory = _make_factory()
        pipeline = factory.evaluation_pipeline
        assert isinstance(pipeline._policy_enforcer, EvaluationPolicyEnforcer)

    def test_pipeline_has_at_least_one_evaluator(self) -> None:
        """PE-3d: evaluator list is non-empty (empty list → only ERROR outcomes)."""
        factory = _make_factory()
        assert len(factory.evaluation_pipeline._evaluators) >= 1

    def test_default_evaluators_non_empty(self) -> None:
        """PE-3e: _default_evaluators() returns at least one evaluator."""
        evaluators = _default_evaluators()
        assert len(evaluators) >= 1

    def test_pipeline_singleton_is_shared_across_builds(self) -> None:
        """PE-3f: two orchestrators built by the same factory share the same pipeline."""
        factory = _make_factory()
        orch1 = factory.build(provider_adapter=_MinimalProviderAdapter(), uow_factory=None)
        orch2 = factory.build(provider_adapter=_MinimalProviderAdapter(), uow_factory=None)
        # Same pipeline object — singletons are shared, per-campaign objects are not.
        assert (
            orch1._validation_service._classifier
            is orch2._validation_service._classifier
        )


# ─── PE-4: ValidationService has with_evaluation_adapter wired ───────────────


class TestEvaluationAdapterWiring:
    def test_validation_service_has_evaluation_adapter(self) -> None:
        """PE-4a: ValidationService._evaluation_adapter is set (not None)."""
        factory = _make_factory()
        orch = factory.build(
            provider_adapter=_MinimalProviderAdapter(),
            uow_factory=None,
        )
        assert orch._validation_service._evaluation_adapter is not None

    def test_evaluation_adapter_is_correct_type(self) -> None:
        """PE-4b: _evaluation_adapter is EvaluationDrivenIntelligenceAdapter."""
        factory = _make_factory()
        orch = factory.build(
            provider_adapter=_MinimalProviderAdapter(),
            uow_factory=None,
        )
        assert isinstance(
            orch._validation_service._evaluation_adapter,
            EvaluationDrivenIntelligenceAdapter,
        )

    def test_intelligence_adapter_singleton_shared(self) -> None:
        """PE-4c: both orchestrators share the same intelligence adapter singleton."""
        factory = _make_factory()
        orch1 = factory.build(provider_adapter=_MinimalProviderAdapter(), uow_factory=None)
        orch2 = factory.build(provider_adapter=_MinimalProviderAdapter(), uow_factory=None)
        assert (
            orch1._validation_service._evaluation_adapter
            is orch2._validation_service._evaluation_adapter
        )

    def test_factory_exposes_intelligence_adapter_property(self) -> None:
        """PE-4d: factory.intelligence_adapter property returns the singleton."""
        factory = _make_factory()
        assert isinstance(factory.intelligence_adapter, EvaluationDrivenIntelligenceAdapter)

    def test_factory_exposes_campaign_intelligence_property(self) -> None:
        """PE-4e: factory.campaign_intelligence property returns the singleton."""
        factory = _make_factory()
        assert isinstance(factory.campaign_intelligence, RuleBasedCampaignIntelligenceService)


# ─── PE-5: organization_id enforcement at API layer ──────────────────────────


class TestOrganizationIdEnforcement:
    def test_red_team_request_has_organization_id_field(self) -> None:
        """PE-5a: RedTeamRequest has an organization_id field."""
        from redforge.application.red_team.orchestrator import RedTeamRequest
        from redforge.domain.red_team.value_objects import (
            AttackObjective,
            BudgetConstraint,
            CampaignGoal,
        )
        req = RedTeamRequest(
            organization_id="org-test-123",
            target_id="tgt-1",
            target_endpoint="https://api.example.com",
            target_provider="openai",
            target_name="Test Target",
            model="gpt-4o-mini",
            target_system_prompt="You are a helpful assistant.",
            goal=CampaignGoal(
                objective=AttackObjective(
                    name="jailbreak",
                    description="test",
                    target_categories=frozenset({"jailbreak"}),
                ),
                budget=BudgetConstraint(),
            ),
            correlation_id="corr-1",
        )
        assert req.organization_id == "org-test-123"

    def test_launch_campaign_request_has_no_organization_id_field(self) -> None:
        """PE-5b: LaunchCampaignRequest (HTTP body model) has NO organization_id field.

        This structural test proves the endpoint cannot accept organization_id
        from the HTTP body — it is not a defined field.
        """
        from redforge.api.v1.red_team import LaunchCampaignRequest
        field_names = set(LaunchCampaignRequest.model_fields.keys())
        assert "organization_id" not in field_names

    def test_make_campaign_goal_uses_known_categories(self) -> None:
        """PE-5c: _make_campaign_goal produces valid CampaignGoal for all defined goals."""
        from redforge.api.v1.red_team import _GOAL_CATEGORIES, _make_campaign_goal
        for goal_name in _GOAL_CATEGORIES:
            goal = _make_campaign_goal(goal_name)
            assert goal.objective.name == goal_name
            assert len(goal.objective.target_categories) >= 1


# ─── PE-6: No duplicate EvaluationPipeline; no empty evaluator list ──────────


class TestNoDuplicatePipeline:
    def test_validation_service_classifier_is_factory_pipeline(self) -> None:
        """PE-6a: ValidationService.classifier IS the factory's singleton pipeline."""
        factory = _make_factory()
        orch = factory.build(provider_adapter=_MinimalProviderAdapter(), uow_factory=None)
        assert orch._validation_service._classifier is factory.evaluation_pipeline

    def test_no_second_pipeline_constructed_per_build(self) -> None:
        """PE-6b: build() does not create a second EvaluationPipeline internally."""
        factory = _make_factory()
        pipeline_before = factory.evaluation_pipeline
        orch = factory.build(provider_adapter=_MinimalProviderAdapter(), uow_factory=None)
        pipeline_after = factory.evaluation_pipeline
        # Pipeline is singleton — unchanged by build()
        assert pipeline_before is pipeline_after
        assert orch._validation_service._classifier is pipeline_before

    def test_evaluator_list_is_not_empty_after_build(self) -> None:
        """PE-6c: After build(), the shared pipeline still has evaluators."""
        factory = _make_factory()
        factory.build(provider_adapter=_MinimalProviderAdapter(), uow_factory=None)
        assert len(factory.evaluation_pipeline._evaluators) >= 1

    def test_eval_signal_keys_are_canonical_constants(self) -> None:
        """PE-6d: Eval signal key constants match the expected string values."""
        assert EVAL_KEY_RECOMMENDED_ACTION == "eval_recommended_action"
        assert EVAL_KEY_EVALUATION_QUALITY == "eval_evaluation_quality"
        assert EVAL_KEY_REQUIRES_MORE_EVIDENCE == "eval_requires_more_evidence"
        assert EVAL_KEY_CONSENSUS_STATE == "eval_consensus_state"

    def test_parse_eval_signals_returns_typed_object(self) -> None:
        """PE-6e: parse_eval_signals() returns EvalSignals value object."""
        signals = parse_eval_signals({
            EVAL_KEY_EVALUATION_QUALITY: "high",
            EVAL_KEY_REQUIRES_MORE_EVIDENCE: "true",
        })
        assert isinstance(signals, EvalSignals)
        assert signals.evaluation_quality == EvalQuality.HIGH
        assert signals.requires_more_evidence is True

    def test_parse_eval_signals_fail_closed_on_unknown_quality(self) -> None:
        """PE-6f: parse_eval_signals is fail-closed: unknown quality → None."""
        signals = parse_eval_signals({EVAL_KEY_EVALUATION_QUALITY: "unknown_value"})
        assert signals.evaluation_quality is None

    def test_factory_build_accepts_none_uow_factory(self) -> None:
        """PE-6g: uow_factory=None is accepted for test/minimal setups."""
        factory = _make_factory()
        orch = factory.build(
            provider_adapter=_MinimalProviderAdapter(),
            uow_factory=None,
        )
        assert orch._validation_service._uow_factory is None
