"""Integration tests for the AI Security Validation Pipeline."""

from redforge.application.pipeline import PipelineInput, ValidationPipeline
from redforge.domain.attack_library.entity import AttackDefinition
from redforge.domain.attack_library.value_objects import (
    AttackCategory,
    AttackSeverity,
    AttackTechnique,
)
from redforge.domain.execution.value_objects import FailureStrategy, StepResult, StepStatus
from redforge.domain.payloads.entity import PayloadTemplate
from redforge.domain.payloads.value_objects import TemplateType, TemplateVariable
from redforge.domain.validations.value_objects import TriggerType
from redforge.shared.identifiers import EntityId

# ─── Mock Provider ────────────────────────────────────────────────────────────


class SuccessProvider:
    """Mock provider that always succeeds."""

    @property
    def provider_name(self) -> str:
        return "mock-success"

    async def execute_step(
        self, step_id: str, attack_id: str, target_id: str, context: dict[str, str]
    ) -> StepResult:
        return StepResult(
            status=StepStatus.COMPLETED, evidence_id=str(EntityId.generate()), duration_ms=50
        )

    async def health_check(self) -> bool:
        return True


class FailureProvider:
    """Mock provider that always fails."""

    @property
    def provider_name(self) -> str:
        return "mock-failure"

    async def execute_step(
        self, step_id: str, attack_id: str, target_id: str, context: dict[str, str]
    ) -> StepResult:
        return StepResult(
            status=StepStatus.FAILED, error_message="Vulnerability detected", duration_ms=30
        )

    async def health_check(self) -> bool:
        return True


class MixedProvider:
    """Mock provider: first call succeeds, second fails."""

    def __init__(self) -> None:
        self._count = 0

    @property
    def provider_name(self) -> str:
        return "mock-mixed"

    async def execute_step(
        self, step_id: str, attack_id: str, target_id: str, context: dict[str, str]
    ) -> StepResult:
        self._count += 1
        if self._count % 2 == 0:
            return StepResult(status=StepStatus.FAILED, error_message="Vuln found", duration_ms=25)
        return StepResult(
            status=StepStatus.COMPLETED, evidence_id=str(EntityId.generate()), duration_ms=40
        )

    async def health_check(self) -> bool:
        return True


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _create_attack(
    name: str = "injection-basic", severity: AttackSeverity = AttackSeverity.HIGH
) -> AttackDefinition:
    a = AttackDefinition.create(
        name=name,
        display_name=f"Attack: {name}",
        description="Test attack",
        category=AttackCategory.PROMPT_INJECTION,
        technique=AttackTechnique(technique="Injection"),
        severity=severity,
    )
    a.publish()
    a.collect_events()
    return a


def _create_template(attack_id: str | None = None) -> PayloadTemplate:
    t = PayloadTemplate.create(
        name="Test Template",
        template_type=TemplateType.PROMPT,
        body="Execute: {{ payload }}",
        variables=[TemplateVariable(name="payload", required=True)],
        attack_id=attack_id,
    )
    t.publish()
    t.collect_events()
    return t


def _pipeline_input(
    attacks: list[AttackDefinition] | None = None,
    templates: list[PayloadTemplate] | None = None,
    provider: object | None = None,
    failure_strategy: FailureStrategy = FailureStrategy.CONTINUE,
) -> PipelineInput:
    attack_list = attacks if attacks is not None else [_create_attack()]
    template_list = templates if templates is not None else [_create_template()]
    return PipelineInput(
        organization_id=EntityId.generate(),
        target_id=EntityId.generate(),
        attacks=attack_list,
        templates=template_list,
        provider_adapter=provider or SuccessProvider(),  # type: ignore[arg-type]
        trigger_type=TriggerType.MANUAL,
        failure_strategy=failure_strategy,
        target_context={"model": "gpt-4"},
    )


class TestPipelineSuccess:
    async def test_single_attack_passes(self) -> None:
        pipeline = ValidationPipeline()
        result = await pipeline.execute(_pipeline_input())

        assert result.attack_count == 1
        assert result.evidence_count == 1
        assert result.finding_count == 0
        assert result.passed == 1
        assert result.failed == 0
        assert result.provider_used == "mock-success"
        assert not result.has_findings
        assert result.duration_ms >= 0

    async def test_multiple_attacks_all_pass(self) -> None:
        attacks = [_create_attack(f"atk-{i}") for i in range(5)]
        pipeline = ValidationPipeline()
        result = await pipeline.execute(_pipeline_input(attacks=attacks))

        assert result.attack_count == 5
        assert result.evidence_count == 5
        assert result.finding_count == 0
        assert result.passed == 5

    async def test_returns_validation_and_plan_ids(self) -> None:
        pipeline = ValidationPipeline()
        result = await pipeline.execute(_pipeline_input())

        assert result.validation_id
        assert result.execution_plan_id
        assert len(result.evidence_ids) == 1


class TestPipelineFailure:
    async def test_all_attacks_fail_generates_findings(self) -> None:
        pipeline = ValidationPipeline()
        result = await pipeline.execute(_pipeline_input(provider=FailureProvider()))

        assert result.attack_count == 1
        assert result.finding_count == 1
        assert result.failed == 1
        assert result.has_findings
        assert "1 findings" in result.risk_summary

    async def test_mixed_results(self) -> None:
        attacks = [_create_attack(f"atk-{i}") for i in range(4)]
        pipeline = ValidationPipeline()
        result = await pipeline.execute(_pipeline_input(attacks=attacks, provider=MixedProvider()))

        assert result.attack_count == 4
        assert result.passed == 2
        assert result.failed == 2
        assert result.finding_count == 2
        assert result.evidence_count == 4

    async def test_high_severity_in_risk_summary(self) -> None:
        attack = _create_attack("critical-vuln", AttackSeverity.CRITICAL)
        pipeline = ValidationPipeline()
        result = await pipeline.execute(
            _pipeline_input(attacks=[attack], provider=FailureProvider())
        )

        assert "1 critical" in result.risk_summary


class TestPipelineEdgeCases:
    async def test_no_template_skips_attack(self) -> None:
        pipeline = ValidationPipeline()
        result = await pipeline.execute(
            _pipeline_input(templates=[])  # No templates available
        )
        # Attack is skipped (no template), no evidence generated
        assert result.evidence_count == 0
        assert result.finding_count == 0
        assert result.attack_count == 1

    async def test_fail_fast_stops_on_first_failure(self) -> None:
        attacks = [_create_attack(f"atk-{i}") for i in range(3)]
        pipeline = ValidationPipeline()
        result = await pipeline.execute(
            _pipeline_input(
                attacks=attacks,
                provider=FailureProvider(),
                failure_strategy=FailureStrategy.FAIL_FAST,
            )
        )
        # Fail fast: plan fails after first step failure, remaining skipped
        assert result.evidence_count == 1  # Only first attack executed
        assert result.finding_count == 1

    async def test_template_matched_by_attack_id(self) -> None:
        attack = _create_attack("specific-attack")
        template = _create_template(attack_id=str(attack.id))
        pipeline = ValidationPipeline()
        result = await pipeline.execute(_pipeline_input(attacks=[attack], templates=[template]))
        assert result.evidence_count == 1


class TestPipelineMetrics:
    async def test_duration_tracked(self) -> None:
        pipeline = ValidationPipeline()
        result = await pipeline.execute(_pipeline_input())
        assert result.duration_ms >= 0

    async def test_provider_name_tracked(self) -> None:
        pipeline = ValidationPipeline()
        result = await pipeline.execute(_pipeline_input(provider=FailureProvider()))
        assert result.provider_used == "mock-failure"
