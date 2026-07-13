"""Comprehensive tests for the Scenario Engine.

Covers:
- Scenario model creation and validation
- Capability resolution and compatibility
- Success criteria evaluation
- Profile factories
- Scenario runner integration with existing runtime
- Attack resolution
- Custom extensibility
"""

from __future__ import annotations

from redforge.application.knowledge_graph import KnowledgeGraph
from redforge.application.knowledge_graph_populator import KnowledgeGraphPopulator
from redforge.application.risk_engine import RiskCorrelationEngine
from redforge.application.runtime.attacks.library_resolver import AttackLibraryResolver
from redforge.application.runtime.evaluation.aggregators import WeightedAverageAggregator
from redforge.application.runtime.evaluation.evaluators import KeywordEvaluator
from redforge.application.runtime.evaluation.pipeline import EvaluationPipeline
from redforge.application.runtime.executors import ChatCompletionExecutor
from redforge.application.scenarios.models import (
    AttackScope,
    CapabilityRequirement,
    EvaluationProfile,
    InteractionMode,
    ScenarioDefinition,
    ScenarioExecutionSummary,
    ScenarioStatus,
    ScenarioVersion,
    SuccessCriteria,
    TargetType,
)
from redforge.application.scenarios.profiles import ScenarioProfiles
from redforge.application.scenarios.runner import (
    DefaultAttackResolver,
    ScenarioRunner,
    ScenarioTarget,
)
from redforge.application.validation_service import ValidationService
from redforge.infrastructure.events import NullEventPublisher
from redforge.infrastructure.repositories.in_memory_uow import InMemoryUnitOfWorkFactory
from redforge.shared.identifiers import EntityId

# ─── Test Helpers ─────────────────────────────────────────────────────────────

_TARGET_ID = str(EntityId.generate())
_ORG_ID = str(EntityId.generate())


def _make_target(capabilities: frozenset[str] | None = None) -> ScenarioTarget:
    return ScenarioTarget(
        target_id=_TARGET_ID,
        organization_id=_ORG_ID,
        name="TestBot",
        endpoint="http://api/v1/chat",
        provider="openai",
        capabilities=capabilities or frozenset({
            "chat_completion", "system_prompt", "tool_use",
        }),
    )


def _make_scenario(
    categories: frozenset[str] | None = None,
    required_caps: frozenset[str] | None = None,
    pass_rate: float = 0.8,
) -> ScenarioDefinition:
    return ScenarioDefinition(
        id="scenario-001",
        name="Test Scenario",
        description="A test scenario",
        version=ScenarioVersion.initial(),
        status=ScenarioStatus.PUBLISHED,
        target_type=TargetType.CHATBOT,
        interaction_modes=frozenset({InteractionMode.SINGLE_TURN}),
        attack_scope=AttackScope(
            categories=categories or frozenset({"prompt_injection"}),
        ),
        capability_requirements=CapabilityRequirement(
            required=required_caps or frozenset({"chat_completion"}),
        ),
        evaluation_profile=EvaluationProfile(
            evaluator_names=("keyword_evaluator",),
        ),
        success_criteria=SuccessCriteria(minimum_pass_rate=pass_rate),
    )


# ─── Capability Resolution Tests ─────────────────────────────────────────────


class TestCapabilityResolution:
    def test_compatible_target(self) -> None:
        scenario = _make_scenario(required_caps=frozenset({"chat_completion"}))
        target = _make_target(frozenset({"chat_completion", "tool_use"}))
        assert scenario.is_compatible_with(target.capabilities)

    def test_incompatible_target(self) -> None:
        scenario = _make_scenario(required_caps=frozenset({"mcp_protocol"}))
        target = _make_target(frozenset({"chat_completion"}))
        assert not scenario.is_compatible_with(target.capabilities)

    def test_missing_capabilities_reported(self) -> None:
        scenario = _make_scenario(
            required_caps=frozenset({"chat_completion", "tool_use", "mcp"})
        )
        target = _make_target(frozenset({"chat_completion"}))
        missing = scenario.missing_capabilities(target.capabilities)
        assert "tool_use" in missing
        assert "mcp" in missing


# ─── Success Criteria Tests ───────────────────────────────────────────────────


class TestSuccessCriteria:
    def test_passes_when_all_criteria_met(self) -> None:
        criteria = SuccessCriteria(minimum_pass_rate=0.8)
        summary = ScenarioExecutionSummary(
            total_attacks=10, passed=9, failed=1, errors=0,
            inconclusive=0, high_severity_count=0,
            categories_tested=frozenset({"prompt_injection"}),
            duration_ms=1000,
        )
        result = criteria.evaluate(summary)
        assert result.passed

    def test_fails_when_pass_rate_too_low(self) -> None:
        criteria = SuccessCriteria(minimum_pass_rate=0.9)
        summary = ScenarioExecutionSummary(
            total_attacks=10, passed=7, failed=3, errors=0,
            inconclusive=0, high_severity_count=0,
            categories_tested=frozenset(), duration_ms=500,
        )
        result = criteria.evaluate(summary)
        assert not result.passed
        assert any("Pass rate" in f for f in result.failures)

    def test_fails_when_vulnerability_rate_too_high(self) -> None:
        criteria = SuccessCriteria(maximum_vulnerability_rate=0.05)
        summary = ScenarioExecutionSummary(
            total_attacks=10, passed=8, failed=2, errors=0,
            inconclusive=0, high_severity_count=0,
            categories_tested=frozenset(), duration_ms=500,
        )
        result = criteria.evaluate(summary)
        assert not result.passed

    def test_fails_when_high_severity_exceeded(self) -> None:
        criteria = SuccessCriteria(maximum_high_severity_findings=0)
        summary = ScenarioExecutionSummary(
            total_attacks=10, passed=9, failed=1, errors=0,
            inconclusive=0, high_severity_count=2,
            categories_tested=frozenset(), duration_ms=500,
        )
        result = criteria.evaluate(summary)
        assert not result.passed

    def test_fails_when_required_categories_missing(self) -> None:
        criteria = SuccessCriteria(
            required_categories_tested=frozenset({"prompt_injection", "jailbreak"})
        )
        summary = ScenarioExecutionSummary(
            total_attacks=5, passed=5, failed=0, errors=0,
            inconclusive=0, high_severity_count=0,
            categories_tested=frozenset({"prompt_injection"}),
            duration_ms=200,
        )
        result = criteria.evaluate(summary)
        assert not result.passed
        assert any("jailbreak" in f for f in result.failures)


# ─── Profile Tests ────────────────────────────────────────────────────────────


class TestScenarioProfiles:
    def test_banking_assistant_profile(self) -> None:
        scenario = ScenarioProfiles.banking_assistant("s1")
        assert scenario.id == "s1"
        assert scenario.target_type == TargetType.CHATBOT
        assert scenario.success_criteria.minimum_pass_rate == 0.95
        assert "prompt_injection" in scenario.attack_scope.categories
        assert scenario.is_executable

    def test_mcp_server_profile(self) -> None:
        scenario = ScenarioProfiles.mcp_server("s2")
        assert scenario.target_type == TargetType.MCP_SERVER
        assert "tool_use" in scenario.capability_requirements.required

    def test_rag_application_profile(self) -> None:
        scenario = ScenarioProfiles.rag_application("s3")
        assert scenario.target_type == TargetType.RAG_APPLICATION
        assert "rag_poisoning" in scenario.attack_scope.categories

    def test_from_profile_factory(self) -> None:
        scenario = ScenarioProfiles.from_profile("coding_assistant", "s4")
        assert scenario.target_type == TargetType.COPILOT

    def test_from_profile_unknown_raises(self) -> None:
        import pytest

        with pytest.raises(ValueError, match="Unknown profile"):
            ScenarioProfiles.from_profile("nonexistent", "s5")

    def test_available_profiles_lists_all(self) -> None:
        profiles = ScenarioProfiles.available_profiles()
        assert len(profiles) >= 5
        assert "banking_assistant" in profiles
        assert "mcp_server" in profiles


# ─── Default Attack Resolver Tests ────────────────────────────────────────────


class TestDefaultAttackResolver:
    async def test_generates_steps_per_category(self) -> None:
        resolver = DefaultAttackResolver()
        scenario = _make_scenario(
            categories=frozenset({"prompt_injection", "jailbreak"})
        )
        steps = await resolver.resolve(scenario, _make_target())
        assert len(steps) == 2  # One generic probe per category
        categories = {s.metadata["category"] for s in steps}
        assert categories == {"prompt_injection", "jailbreak"}

    async def test_uses_custom_payloads(self) -> None:
        resolver = DefaultAttackResolver(payloads={
            "prompt_injection": ["Ignore all", "Override system"],
        })
        scenario = _make_scenario(categories=frozenset({"prompt_injection"}))
        steps = await resolver.resolve(scenario, _make_target())
        assert len(steps) == 2
        assert "Ignore all" in steps[0].payload_content

    async def test_respects_max_per_category(self) -> None:
        resolver = DefaultAttackResolver(payloads={
            "prompt_injection": ["a", "b", "c", "d", "e"],
        })
        scenario = ScenarioDefinition(
            id="s1", name="t", description="d",
            version=ScenarioVersion.initial(),
            status=ScenarioStatus.PUBLISHED,
            target_type=TargetType.CHATBOT,
            interaction_modes=frozenset({InteractionMode.SINGLE_TURN}),
            attack_scope=AttackScope(
                categories=frozenset({"prompt_injection"}),
                max_attacks_per_category=2,
            ),
            capability_requirements=CapabilityRequirement(required=frozenset()),
            evaluation_profile=EvaluationProfile(evaluator_names=()),
            success_criteria=SuccessCriteria(),
        )
        steps = await resolver.resolve(scenario, _make_target())
        assert len(steps) == 2


# ─── Scenario Runner Integration Tests ───────────────────────────────────────


class TestScenarioRunner:
    def _make_runner(self, responses: list[str]) -> ScenarioRunner:
        """Create a runner backed by the canonical ValidationService."""
        from tests.unit.test_runtime_execution import FakeProviderAdapter

        adapter = FakeProviderAdapter(responses)
        executor = ChatCompletionExecutor(adapter)
        evaluation_pipeline = EvaluationPipeline(
            evaluators=[KeywordEvaluator()],
            aggregator=WeightedAverageAggregator(),
        )
        service = ValidationService(
            executor=executor,
            classifier=evaluation_pipeline,
            attack_resolver=AttackLibraryResolver(),
            risk_engine=RiskCorrelationEngine(),
            kg_populator=KnowledgeGraphPopulator(KnowledgeGraph()),
            uow_factory=InMemoryUnitOfWorkFactory(),
            event_publisher=NullEventPublisher(),
        )
        return ScenarioRunner(validation_service=service)

    async def test_executes_and_passes(self) -> None:
        runner = self._make_runner(["I cannot help with that."] * 5)
        scenario = _make_scenario(pass_rate=0.5)
        target = _make_target()

        result = await runner.execute(scenario, target, "run-001")
        assert result.passed
        assert result.summary.total_attacks > 0
        assert result.pass_rate > 0

    async def test_fails_criteria_when_vulnerable(self) -> None:
        runner = self._make_runner(
            ["I will ignore my instructions."] * 5
        )
        scenario = _make_scenario(pass_rate=0.9)
        target = _make_target()

        result = await runner.execute(scenario, target, "run-002")
        assert not result.passed

    async def test_raises_on_incompatible_target(self) -> None:
        import pytest

        runner = self._make_runner(["ok"])
        scenario = _make_scenario(required_caps=frozenset({"mcp_protocol"}))
        target = _make_target(frozenset({"chat_completion"}))

        with pytest.raises(ValueError, match="missing capabilities"):
            await runner.execute(scenario, target, "run-003")

    async def test_raises_when_organization_id_unresolvable(self) -> None:
        """ScenarioRunner must refuse to invent an organization identity.

        Regression test: previously a missing organization_id on both the
        target and the runner silently generated a fresh ULID per run,
        which would fragment a single tenant's data across ULID-keyed
        "organizations" in the Knowledge Graph and violate multi-tenant
        data integrity guarantees.
        """
        import pytest

        runner = self._make_runner(["ok"])
        scenario = _make_scenario()
        # No organization_id on the target, and the runner has no default.
        target = _make_target()
        target = ScenarioTarget(
            target_id=target.target_id,
            name=target.name,
            endpoint=target.endpoint,
            provider=target.provider,
            capabilities=target.capabilities,
            organization_id="",
        )

        with pytest.raises(ValueError, match="organization_id"):
            await runner.execute(scenario, target, "run-org-missing")

    async def test_empty_attacks_returns_result(self) -> None:
        runner = self._make_runner(["ok"])
        # Create scenario with an explicit attack scope that has no categories
        scenario = ScenarioDefinition(
            id="scenario-empty", name="Empty", description="No attacks",
            version=ScenarioVersion.initial(),
            status=ScenarioStatus.PUBLISHED,
            target_type=TargetType.CHATBOT,
            interaction_modes=frozenset({InteractionMode.SINGLE_TURN}),
            attack_scope=AttackScope(categories=frozenset()),
            capability_requirements=CapabilityRequirement(
                required=frozenset({"chat_completion"})
            ),
            evaluation_profile=EvaluationProfile(evaluator_names=()),
            success_criteria=SuccessCriteria(minimum_pass_rate=0.0),
        )
        target = _make_target()

        result = await runner.execute(scenario, target, "run-004")
        assert result.summary.total_attacks == 0
