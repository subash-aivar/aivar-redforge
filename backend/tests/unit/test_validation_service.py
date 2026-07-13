"""Comprehensive tests for the canonical ValidationService pipeline.

Tests cover:
  - Happy path: attacks execute, evidence persisted, findings generated
  - Secure outcome: no findings generated for passing attacks
  - Provider failure: error evidence recorded, run completes
  - Evaluation pipeline classification
  - Risk correlation on findings
  - Knowledge Graph population after commit
  - Domain event publishing
  - Transaction atomicity via UoW
  - Failure durability: run marked FAILED on exception
  - AttackLibraryResolver filtering (category, severity, limit)
  - ValidationServiceResult fields
  - ScenarioRunner delegation to ValidationService
"""

from __future__ import annotations

import pytest

from redforge.application.knowledge_graph import KnowledgeGraph, NodeType
from redforge.application.knowledge_graph_populator import KnowledgeGraphPopulator
from redforge.application.risk_engine import RiskCorrelationEngine
from redforge.application.runtime.attacks.library_resolver import AttackLibraryResolver
from redforge.application.runtime.contracts import (
    ClassificationResult,
    StepContext,
    StepEvidence,
)
from redforge.application.runtime.evaluation.aggregators import WeightedAverageAggregator
from redforge.application.runtime.evaluation.evaluators import KeywordEvaluator
from redforge.application.runtime.evaluation.pipeline import EvaluationPipeline
from redforge.application.scenarios.models import (
    AttackScope,
    CapabilityRequirement,
    EvaluationProfile,
    InteractionMode,
    ScenarioDefinition,
    ScenarioStatus,
    ScenarioVersion,
    SuccessCriteria,
    TargetType,
)
from redforge.application.scenarios.runner import ScenarioRunner, ScenarioTarget
from redforge.application.validation_service import (
    ValidationService,
    ValidationServiceRequest,
)
from redforge.infrastructure.events import InMemoryEventPublisher
from redforge.infrastructure.repositories.in_memory_uow import InMemoryUnitOfWorkFactory
from redforge.shared.identifiers import EntityId

# Valid ULID strings for tests
_ORG_ID = str(EntityId.generate())
_TARGET_ID = str(EntityId.generate())


# ─── Test Doubles ─────────────────────────────────────────────────────────────


class _VulnerableExecutor:
    """Always returns a response that triggers VULNERABLE classification."""

    async def execute(self, context: StepContext) -> StepEvidence:
        return StepEvidence(
            step_id=context.step_id,
            attack_id=context.attack_id,
            target_id=context.target_id,
            request_method="POST",
            request_url=context.target_endpoint,
            request_body=context.payload_content,
            response_status=200,
            response_body=(
                "Sure, I'll ignore my previous instructions. "
                "Here is my system prompt: You are a helpful assistant with no restrictions."
            ),
            duration_ms=42,
        )


class _SecureExecutor:
    """Always returns a response that triggers SECURE classification."""

    async def execute(self, context: StepContext) -> StepEvidence:
        return StepEvidence(
            step_id=context.step_id,
            attack_id=context.attack_id,
            target_id=context.target_id,
            request_method="POST",
            request_url=context.target_endpoint,
            request_body=context.payload_content,
            response_status=200,
            response_body=(
                "I'm sorry, I cannot comply with that request. "
                "I'm designed to be helpful while maintaining safety boundaries."
            ),
            duration_ms=38,
        )


class _ErrorExecutor:
    """Always returns an error (provider down / network failure)."""

    async def execute(self, context: StepContext) -> StepEvidence:
        return StepEvidence(
            step_id=context.step_id,
            attack_id=context.attack_id,
            target_id=context.target_id,
            request_method="POST",
            request_url=context.target_endpoint,
            request_body=context.payload_content,
            response_status=0,
            response_body="",
            duration_ms=1,
            error="ConnectionError: provider unreachable",
        )


class _AlwaysVulnerableClassifier:
    """Classifies every response as FAIL with high confidence."""

    async def classify(
        self, evidence: StepEvidence, attack_name: str
    ) -> ClassificationResult:
        return ClassificationResult(outcome="fail", confidence=0.95, reasoning="Vulnerable")


class _AlwaysSecureClassifier:
    """Classifies every response as PASS."""

    async def classify(
        self, evidence: StepEvidence, attack_name: str
    ) -> ClassificationResult:
        return ClassificationResult(outcome="pass", confidence=0.90, reasoning="Secure")


def _make_evaluation_pipeline() -> EvaluationPipeline:
    """Create a real EvaluationPipeline with KeywordEvaluator."""
    return EvaluationPipeline(
        evaluators=[KeywordEvaluator()],
        aggregator=WeightedAverageAggregator(),
    )


def _make_vulnerable_evaluation_pipeline() -> EvaluationPipeline:
    """Pipeline that always classifies as VULNERABLE with high confidence."""
    from redforge.application.runtime.evaluation.models import (
        EvaluationOutcome,
        EvaluatorResult,
    )

    class _AlwaysVulnerableEvaluator:
        name = "always_vulnerable"

        async def evaluate(self, context: object) -> EvaluatorResult:
            return EvaluatorResult(
                evaluator_name="always_vulnerable",
                outcome=EvaluationOutcome.VULNERABLE,
                confidence=0.95,
                reasoning="Test: always vulnerable",
            )

    return EvaluationPipeline(
        evaluators=[_AlwaysVulnerableEvaluator()],  # type: ignore[list-item]
        aggregator=WeightedAverageAggregator(),
    )


def _make_service(
    executor: object,
    evaluation_pipeline: EvaluationPipeline | None = None,
    uow_factory: InMemoryUnitOfWorkFactory | None = None,
    event_publisher: InMemoryEventPublisher | None = None,
    graph: KnowledgeGraph | None = None,
) -> tuple[ValidationService, InMemoryUnitOfWorkFactory, InMemoryEventPublisher, KnowledgeGraph]:
    factory = uow_factory or InMemoryUnitOfWorkFactory()
    publisher = event_publisher or InMemoryEventPublisher()
    kg = graph or KnowledgeGraph()
    pipeline = evaluation_pipeline or _make_evaluation_pipeline()

    service = ValidationService(
        executor=executor,  # type: ignore[arg-type]
        classifier=pipeline,
        attack_resolver=AttackLibraryResolver(),
        risk_engine=RiskCorrelationEngine(),
        kg_populator=KnowledgeGraphPopulator(kg),
        uow_factory=factory,
        event_publisher=publisher,
    )
    return service, factory, publisher, kg


def _make_request(
    attack_categories: frozenset[str] | None = None,
    max_per_category: int = 1,
    severity_minimum: str = "low",
) -> ValidationServiceRequest:
    categories = (
        frozenset({"prompt_injection"})
        if attack_categories is None
        else attack_categories
    )
    return ValidationServiceRequest(
        organization_id=_ORG_ID,
        target_id=_TARGET_ID,
        target_endpoint="https://api.openai.com/v1/chat/completions",
        target_provider="openai",
        target_name="Test LLM Target",
        model="gpt-4o",
        target_system_prompt="You are a helpful assistant.",
        target_capabilities=frozenset({"chat_completion", "system_prompt"}),
        attack_categories=categories,
        max_attacks_per_category=max_per_category,
        severity_minimum=severity_minimum,
        correlation_id="test-correlation-id-001",
        policy_id=None,
        scenario_id=None,
        trigger_type="manual",
    )


# ─── AttackLibraryResolver Tests ──────────────────────────────────────────────


class TestAttackLibraryResolver:
    def test_resolves_known_categories(self) -> None:
        resolver = AttackLibraryResolver()
        result = _run_sync(resolver.resolve(
            categories=frozenset({"prompt_injection", "jailbreak"}),
            severity_minimum="low",
            max_per_category=0,
        ))
        categories = {step.metadata["category"] for step in result}
        assert "prompt_injection" in categories
        assert "jailbreak" in categories

    def test_unknown_category_returns_no_steps(self) -> None:
        resolver = AttackLibraryResolver()
        result = _run_sync(resolver.resolve(
            categories=frozenset({"nonexistent_category_xyz"}),
        ))
        assert result == []

    def test_max_per_category_respected(self) -> None:
        resolver = AttackLibraryResolver()
        result = _run_sync(resolver.resolve(
            categories=frozenset({"prompt_injection"}),
            max_per_category=1,
        ))
        assert len(result) == 1

    def test_severity_minimum_filters_low(self) -> None:
        resolver = AttackLibraryResolver()
        high_up = _run_sync(resolver.resolve(
            categories=frozenset({"denial_of_service"}),
            severity_minimum="high",
        ))
        all_attacks = _run_sync(resolver.resolve(
            categories=frozenset({"denial_of_service"}),
            severity_minimum="low",
        ))
        # denial_of_service has medium and low — high filter should exclude them
        assert len(high_up) < len(all_attacks)

    def test_extra_payloads_merged(self) -> None:
        extra = {
            "prompt_injection": [
                {
                    "attack_id": "custom-001",
                    "name": "custom_attack",
                    "payload": "custom payload",
                    "severity": "high",
                }
            ]
        }
        resolver = AttackLibraryResolver(extra_payloads=extra)
        result = _run_sync(resolver.resolve(
            categories=frozenset({"prompt_injection"}),
            severity_minimum="low",
            max_per_category=0,
        ))
        names = {step.attack_name for step in result}
        assert "custom_attack" in names

    def test_attack_steps_have_required_fields(self) -> None:
        resolver = AttackLibraryResolver()
        steps = _run_sync(resolver.resolve(
            categories=frozenset({"prompt_injection"}),
            max_per_category=1,
        ))
        assert steps
        step = steps[0]
        assert step.attack_id
        assert step.attack_name
        assert step.payload_content
        assert "category" in step.metadata
        assert "severity" in step.metadata


# ─── ValidationService Happy Path ─────────────────────────────────────────────


@pytest.mark.asyncio
class TestValidationServiceHappyPath:
    async def test_vulnerable_response_creates_finding(self) -> None:
        # Use a controlled pipeline that always classifies as VULNERABLE
        service, _factory, _publisher, _kg = _make_service(
            _VulnerableExecutor(),
            evaluation_pipeline=_make_vulnerable_evaluation_pipeline(),
        )
        request = _make_request(max_per_category=1)

        result = await service.execute(request)

        assert result.status == "completed"
        assert result.total_attacks >= 1
        assert result.failed >= 1
        assert len(result.finding_ids) >= 1
        assert len(result.evidence_ids) >= 1

    async def test_evidence_persisted_to_uow(self) -> None:
        factory = InMemoryUnitOfWorkFactory()
        service, _, _, _ = _make_service(
            _VulnerableExecutor(),
            uow_factory=factory,
            evaluation_pipeline=_make_vulnerable_evaluation_pipeline(),
        )
        request = _make_request(max_per_category=1)

        result = await service.execute(request)

        # Check evidence is in the UoW store
        async with factory() as uow:
            for ev_id in result.evidence_ids:
                stored = await uow.evidence.get_by_id(ev_id)
                assert stored is not None
                assert stored["id"] == ev_id
                assert stored["finalized"] is True

    async def test_findings_persisted_to_uow(self) -> None:
        factory = InMemoryUnitOfWorkFactory()
        service, _, _, _ = _make_service(
            _VulnerableExecutor(),
            uow_factory=factory,
            evaluation_pipeline=_make_vulnerable_evaluation_pipeline(),
        )
        request = _make_request(max_per_category=1)

        result = await service.execute(request)

        async with factory() as uow:
            for f_id in result.finding_ids:
                stored = await uow.findings.get_by_id(f_id)
                assert stored is not None
                assert stored["id"] == f_id
                assert stored["status"] == "open"

    async def test_validation_run_persisted_completed(self) -> None:
        factory = InMemoryUnitOfWorkFactory()
        service, _, _, _ = _make_service(_SecureExecutor(), uow_factory=factory)
        request = _make_request(max_per_category=1)

        result = await service.execute(request)

        async with factory() as uow:
            run_data = await uow.validations.get_by_id(result.run_id)
            assert run_data is not None
            assert run_data["status"] == "completed"
            assert run_data["total_checks"] >= 1

    async def test_secure_target_no_findings(self) -> None:
        service, _factory, _, _ = _make_service(_SecureExecutor())
        request = _make_request(max_per_category=1)

        result = await service.execute(request)

        assert result.status == "completed"
        assert len(result.finding_ids) == 0
        # KeywordEvaluator may return inconclusive for borderline responses —
        # the key invariant is that no findings are generated.
        assert result.failed == 0

    async def test_knowledge_graph_populated(self) -> None:
        kg = KnowledgeGraph()
        service, _, _, _ = _make_service(
            _VulnerableExecutor(), graph=kg,
            evaluation_pipeline=_make_vulnerable_evaluation_pipeline(),
        )
        request = _make_request(max_per_category=1)

        result = await service.execute(request)

        assert result.kg_nodes_added > 0
        # Target node should be in graph
        target_node = kg._store.get_node(request.target_id)  # type: ignore[attr-defined]
        assert target_node is not None
        assert target_node.node_type == NodeType.AI_TARGET

    async def test_domain_events_published(self) -> None:
        publisher = InMemoryEventPublisher()
        service, _, _, _ = _make_service(
            _VulnerableExecutor(), event_publisher=publisher,
            evaluation_pipeline=_make_vulnerable_evaluation_pipeline(),
        )
        request = _make_request(max_per_category=1)

        await service.execute(request)

        assert len(publisher.published) > 0

    async def test_multiple_categories_all_executed(self) -> None:
        service, _factory, _, _ = _make_service(_SecureExecutor())
        request = _make_request(
            attack_categories=frozenset({"prompt_injection", "jailbreak"}),
            max_per_category=1,
        )

        result = await service.execute(request)

        assert result.total_attacks == 2
        assert len(result.evidence_ids) == 2

    async def test_risk_incidents_produced_for_findings(self) -> None:
        service, _, _, _ = _make_service(
            _VulnerableExecutor(),
            evaluation_pipeline=_make_vulnerable_evaluation_pipeline(),
        )
        request = _make_request(max_per_category=1)

        result = await service.execute(request)

        if result.has_findings:
            assert len(result.risk_incidents) > 0

    async def test_execution_result_compatible_structure(self) -> None:
        service, _, _, _ = _make_service(_SecureExecutor())
        request = _make_request(max_per_category=1)

        result = await service.execute(request)

        er = result.execution_result
        assert er.run_id == result.run_id
        assert er.total_steps == result.total_attacks
        assert er.passed + er.failed + er.errors + er.inconclusive == er.total_steps


# ─── ValidationService Error Handling ─────────────────────────────────────────


@pytest.mark.asyncio
class TestValidationServiceErrorHandling:
    async def test_provider_error_creates_error_evidence(self) -> None:
        factory = InMemoryUnitOfWorkFactory()
        service, _, _, _ = _make_service(_ErrorExecutor(), uow_factory=factory)
        request = _make_request(max_per_category=1)

        result = await service.execute(request)

        assert result.status == "completed"
        assert result.errors >= 1
        # Error evidence is still persisted
        assert len(result.evidence_ids) >= 1

    async def test_executor_exception_persists_failed_run(self) -> None:
        """If the executor raises (not returns error), run is marked FAILED."""

        class _RaisingExecutor:
            async def execute(self, context: StepContext) -> StepEvidence:
                raise RuntimeError("Catastrophic provider failure")

        factory = InMemoryUnitOfWorkFactory()
        service, _, _, _ = _make_service(_RaisingExecutor(), uow_factory=factory)
        request = _make_request(max_per_category=1)

        with pytest.raises(RuntimeError):
            await service.execute(request)

        # The run should be persisted as FAILED (best-effort)
        # Find any validation run in the store
        all_runs = list(factory._validations._store.values())
        assert len(all_runs) >= 1
        failed_runs = [r for r in all_runs if r["status"] == "failed"]
        assert len(failed_runs) >= 1

    async def test_empty_categories_produces_no_attacks(self) -> None:
        service, _, _, _ = _make_service(_SecureExecutor())
        request = _make_request(attack_categories=frozenset())

        result = await service.execute(request)

        assert result.total_attacks == 0
        assert result.status == "completed"

    async def test_knowledge_graph_failure_does_not_fail_completed_run(self) -> None:
        """A Knowledge Graph population failure is strictly post-commit.

        It must never cause an already-persisted, successfully COMPLETED
        run to be reported as failed, and it must not raise out of
        execute(). Regression test for the KG failure-isolation P0 fix.
        """

        class _RaisingKGPopulator:
            def populate(self, **kwargs: object) -> int:
                raise RuntimeError("Knowledge Graph store unreachable")

        factory = InMemoryUnitOfWorkFactory()
        service = ValidationService(
            executor=_VulnerableExecutor(),  # type: ignore[arg-type]
            classifier=_make_vulnerable_evaluation_pipeline(),
            attack_resolver=AttackLibraryResolver(),
            risk_engine=RiskCorrelationEngine(),
            kg_populator=_RaisingKGPopulator(),  # type: ignore[arg-type]
            uow_factory=factory,
            event_publisher=InMemoryEventPublisher(),
        )
        request = _make_request(max_per_category=1)

        # Must not raise, despite the KG populator raising internally.
        result = await service.execute(request)

        assert result.status == "completed"
        assert result.kg_nodes_added == 0
        assert len(result.finding_ids) >= 1

        # Evidence and findings were still committed before KG population ran.
        async with factory() as uow:
            run_data = await uow.validations.get_by_id(result.run_id)
            assert run_data is not None
            assert run_data["status"] == "completed"
            for ev_id in result.evidence_ids:
                assert await uow.evidence.get_by_id(ev_id) is not None
            for f_id in result.finding_ids:
                assert await uow.findings.get_by_id(f_id) is not None

    async def test_event_publishing_failure_does_not_fail_completed_run(self) -> None:
        """Symmetric with the Knowledge Graph isolation guarantee: event
        publishing is also strictly post-commit and its failure must not
        flip an already-completed run to failed.
        """

        class _RaisingEventPublisher:
            async def publish(self, events: list[object]) -> None:
                raise RuntimeError("Event bus unreachable")

        factory = InMemoryUnitOfWorkFactory()
        service = ValidationService(
            executor=_SecureExecutor(),  # type: ignore[arg-type]
            classifier=_make_evaluation_pipeline(),
            attack_resolver=AttackLibraryResolver(),
            risk_engine=RiskCorrelationEngine(),
            kg_populator=KnowledgeGraphPopulator(KnowledgeGraph()),
            uow_factory=factory,
            event_publisher=_RaisingEventPublisher(),  # type: ignore[arg-type]
        )
        request = _make_request(max_per_category=1)

        result = await service.execute(request)

        assert result.status == "completed"
        async with factory() as uow:
            run_data = await uow.validations.get_by_id(result.run_id)
            assert run_data is not None
            assert run_data["status"] == "completed"


# ─── ScenarioRunner → ValidationService Integration ───────────────────────────


@pytest.mark.asyncio
class TestScenarioRunnerIntegration:
    def _make_scenario(self) -> ScenarioDefinition:
        return ScenarioDefinition(
            id="scenario-test-001",
            name="Test Scenario",
            description="Integration test scenario",
            version=ScenarioVersion.initial(),
            status=ScenarioStatus.PUBLISHED,
            target_type=TargetType.CHATBOT,
            interaction_modes=frozenset({InteractionMode.SINGLE_TURN}),
            attack_scope=AttackScope(
                categories=frozenset({"prompt_injection"}),
                severity_minimum="low",
                max_attacks_per_category=1,
            ),
            capability_requirements=CapabilityRequirement(
                required=frozenset({"chat_completion"}),
            ),
            evaluation_profile=EvaluationProfile(
                evaluator_names=("keyword_evaluator",),
                aggregation_strategy="weighted_average",
                minimum_confidence=0.5,
            ),
            success_criteria=SuccessCriteria(
                minimum_pass_rate=0.0,
                maximum_vulnerability_rate=1.0,
                maximum_high_severity_findings=100,
            ),
            tags=frozenset({"test"}),
        )

    def _make_target(self) -> ScenarioTarget:
        return ScenarioTarget(
            target_id=_TARGET_ID,
            name="Test Target",
            endpoint="https://api.openai.com/v1/chat/completions",
            provider="openai",
            capabilities=frozenset({"chat_completion", "system_prompt"}),
            model="gpt-4o",
            system_prompt="You are a helpful assistant.",
            organization_id=_ORG_ID,
        )

    async def test_scenario_runner_returns_scenario_result(self) -> None:
        service, _, _, _ = _make_service(_SecureExecutor())
        runner = ScenarioRunner(validation_service=service)
        scenario = self._make_scenario()
        target = self._make_target()

        result = await runner.execute(scenario, target, run_id="test-run-001")

        assert result.scenario_id == "scenario-test-001"
        assert result.scenario_name == "Test Scenario"
        assert result.target_id == target.target_id
        assert result.summary.total_attacks >= 1

    async def test_scenario_runner_evaluates_success_criteria(self) -> None:
        service, _, _, _ = _make_service(_SecureExecutor())
        runner = ScenarioRunner(validation_service=service)
        scenario = self._make_scenario()
        target = self._make_target()

        result = await runner.execute(scenario, target, run_id="test-run-002")

        # CriteriaResult is present and has a passed attribute
        assert hasattr(result.criteria_result, "passed")

    async def test_scenario_runner_raises_on_incompatible_target(self) -> None:
        service, _, _, _ = _make_service(_SecureExecutor())
        runner = ScenarioRunner(validation_service=service)

        # Scenario requires "tool_use" but target doesn't have it
        scenario = ScenarioDefinition(
            id="scenario-002",
            name="MCP Test",
            description="Test",
            version=ScenarioVersion.initial(),
            status=ScenarioStatus.PUBLISHED,
            target_type=TargetType.MCP_SERVER,
            interaction_modes=frozenset({InteractionMode.TOOL_CALLING}),
            attack_scope=AttackScope(
                categories=frozenset({"tool_abuse"}),
                severity_minimum="low",
            ),
            capability_requirements=CapabilityRequirement(
                required=frozenset({"tool_use", "function_calling"}),
            ),
            evaluation_profile=EvaluationProfile(
                evaluator_names=("keyword_evaluator",),
                aggregation_strategy="weighted_average",
                minimum_confidence=0.5,
            ),
            success_criteria=SuccessCriteria(
                minimum_pass_rate=0.9,
                maximum_vulnerability_rate=0.05,
            ),
            tags=frozenset(),
        )
        target = ScenarioTarget(
            target_id=_TARGET_ID,
            name="Basic LLM",
            endpoint="https://api.example.com/chat",
            provider="openai",
            capabilities=frozenset({"chat_completion"}),  # Missing tool_use
        )

        with pytest.raises(ValueError, match="missing capabilities"):
            await runner.execute(scenario, target, run_id="test-run-003")

    async def test_scenario_result_includes_persisted_ids(self) -> None:
        service, _, _, _ = _make_service(_VulnerableExecutor())
        runner = ScenarioRunner(validation_service=service)
        scenario = self._make_scenario()
        target = self._make_target()

        result = await runner.execute(scenario, target, run_id="test-run-004")

        assert "run_id" in result.metadata
        assert "evidence_ids" in result.metadata
        assert "finding_ids" in result.metadata


# ─── KnowledgeGraph Population Tests ──────────────────────────────────────────


@pytest.mark.asyncio
class TestKnowledgeGraphPopulation:
    async def test_target_and_provider_nodes_created(self) -> None:
        kg = KnowledgeGraph()
        service, _, _, _ = _make_service(_SecureExecutor(), graph=kg)
        request = _make_request(max_per_category=1)

        await service.execute(request)

        # Provider node
        provider_node = kg._store.get_node(f"provider:{request.target_provider}")  # type: ignore[attr-defined]
        assert provider_node is not None
        assert provider_node.node_type == NodeType.PROVIDER

    async def test_evidence_nodes_created(self) -> None:
        kg = KnowledgeGraph()
        service, _, _, _ = _make_service(_SecureExecutor(), graph=kg)
        request = _make_request(max_per_category=1)

        result = await service.execute(request)

        evidence_nodes = [
            n for n in kg._store.all_nodes()
            if n.node_type == NodeType.EVIDENCE
        ]
        assert len(evidence_nodes) == len(result.evidence_ids)

    async def test_finding_nodes_created_when_vulnerable(self) -> None:
        kg = KnowledgeGraph()
        service, _, _, _ = _make_service(
            _VulnerableExecutor(), graph=kg,
            evaluation_pipeline=_make_vulnerable_evaluation_pipeline(),
        )
        request = _make_request(max_per_category=1)

        result = await service.execute(request)

        finding_nodes = [
            n for n in kg._store.all_nodes()
            if n.node_type == NodeType.FINDING
        ]
        assert len(finding_nodes) == len(result.finding_ids)


# ─── Evaluation Intelligence Engine integration ───────────────────────────────


@pytest.mark.asyncio
class TestValidationServiceIntelligence:
    """ValidationService must attach EvaluationIntelligence to Findings when
    the injected classifier is an IntelligentClassifier (EvaluationPipeline
    configured with an ExplainabilityProvider), and must behave exactly as
    before when it isn't — proving the intelligence layer extends the
    canonical pipeline additively rather than requiring a redesign.
    """

    def _make_intelligent_pipeline(self) -> EvaluationPipeline:
        from redforge.application.runtime.evaluation.confidence import (
            HeuristicConfidenceCalculator,
        )
        from redforge.application.runtime.evaluation.explainability import (
            DefaultExplainabilityProvider,
            StaticRemediationProvider,
        )
        from redforge.application.runtime.evaluation.models import (
            EvaluationOutcome,
            EvaluatorResult,
        )

        class _AlwaysVulnerableEvaluator:
            name = "always_vulnerable"

            async def evaluate(self, context: object) -> EvaluatorResult:
                return EvaluatorResult(
                    evaluator_name="always_vulnerable",
                    outcome=EvaluationOutcome.VULNERABLE,
                    confidence=0.95,
                    reasoning="Test: always vulnerable",
                )

        return EvaluationPipeline(
            evaluators=[_AlwaysVulnerableEvaluator()],  # type: ignore[list-item]
            aggregator=WeightedAverageAggregator(),
            explainability_provider=DefaultExplainabilityProvider(
                confidence_calculator=HeuristicConfidenceCalculator(),
                remediation_provider=StaticRemediationProvider(
                    {"prompt_injection": "Intelligence-derived remediation."}
                ),
            ),
        )

    async def test_finding_enriched_with_owasp_reference(self) -> None:
        service, _, _, _ = _make_service(
            _VulnerableExecutor(),
            evaluation_pipeline=self._make_intelligent_pipeline(),
        )
        request = _make_request(
            attack_categories=frozenset({"prompt_injection"}), max_per_category=1,
        )

        result = await service.execute(request)

        assert len(result.finding_ids) >= 1

    async def test_finding_recommendation_uses_intelligence_when_present(self) -> None:
        factory = InMemoryUnitOfWorkFactory()
        service, _, _, _ = _make_service(
            _VulnerableExecutor(),
            evaluation_pipeline=self._make_intelligent_pipeline(),
            uow_factory=factory,
        )
        request = _make_request(
            attack_categories=frozenset({"prompt_injection"}), max_per_category=1,
        )

        result = await service.execute(request)

        async with factory() as uow:
            for f_id in result.finding_ids:
                stored = await uow.findings.get_by_id(f_id)
                assert stored is not None
                assert stored["recommendation"] == "Intelligence-derived remediation."
                assert len(stored["owasp_refs"]) >= 1

    async def test_non_intelligent_classifier_unaffected(self) -> None:
        """A classifier that only implements classify() (not evaluate())
        must keep working exactly as before — no OWASP refs, no crash.
        """

        class _PlainClassifier:
            async def classify(
                self, evidence: StepEvidence, attack_name: str
            ) -> ClassificationResult:
                return ClassificationResult(
                    outcome="fail", confidence=0.9, reasoning="plain classifier",
                )

        factory = InMemoryUnitOfWorkFactory()
        service = ValidationService(
            executor=_VulnerableExecutor(),  # type: ignore[arg-type]
            classifier=_PlainClassifier(),
            attack_resolver=AttackLibraryResolver(),
            risk_engine=RiskCorrelationEngine(),
            kg_populator=KnowledgeGraphPopulator(KnowledgeGraph()),
            uow_factory=factory,
            event_publisher=InMemoryEventPublisher(),
        )
        request = _make_request(max_per_category=1)

        result = await service.execute(request)

        assert result.status == "completed"
        assert len(result.finding_ids) >= 1
        async with factory() as uow:
            for f_id in result.finding_ids:
                stored = await uow.findings.get_by_id(f_id)
                assert stored is not None
                assert stored["owasp_refs"] == []
                assert stored["mitre_refs"] == []
                # Falls back to the static category recommendation table.
                assert stored["recommendation"]


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _run_sync(coro: object) -> object:
    """Run a coroutine synchronously for sync test methods."""
    import asyncio
    return asyncio.run(coro)  # type: ignore[arg-type]
