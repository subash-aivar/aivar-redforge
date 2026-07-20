"""OperationRiskAssessor — impact ceiling union → risk."""

from __future__ import annotations

from operation.domain.entities.operation_entities import ExecutionStep
from operation.domain.services.operation_risk_assessor import OperationRiskAssessor
from operation.domain.value_objects.enums import ImpactCeiling, OperationRisk, StepState, StepType
from operation.domain.value_objects.identifiers import ExecutionStepId
from operation.domain.value_objects.plan_vos import StepConstraints


def _step(impact: ImpactCeiling | None) -> ExecutionStep:
    return ExecutionStep(
        step_id=ExecutionStepId.generate(),
        name="s",
        step_type=StepType.ATTACK_STEP,
        state=StepState.PENDING,
        constraints=StepConstraints(
            max_duration_seconds=60,
            rollback_on_failure=True,
            continue_on_failure=False,
        ),
        technique_ref=None,
        target_ref=None,
        impact_ceiling=impact,
        modifies_persistent_state=False,
        mitre_ref=None,
        rate_limit=None,
        window=None,
        output_ref=None,
        description="",
    )


class TestRiskAssessor:
    def test_empty_is_low(self) -> None:
        assert OperationRiskAssessor.assess([]) == OperationRisk.LOW

    def test_observe_is_low(self) -> None:
        assert OperationRiskAssessor.assess([_step(ImpactCeiling.OBSERVE)]) == OperationRisk.LOW

    def test_probe_is_medium(self) -> None:
        assert OperationRiskAssessor.assess([_step(ImpactCeiling.PROBE)]) == OperationRisk.MEDIUM

    def test_exploit_is_high(self) -> None:
        assert OperationRiskAssessor.assess([_step(ImpactCeiling.EXPLOIT)]) == OperationRisk.HIGH

    def test_destruct_is_critical(self) -> None:
        assert (
            OperationRiskAssessor.assess([_step(ImpactCeiling.DESTRUCT)])
            == OperationRisk.CRITICAL
        )

    def test_union_takes_highest(self) -> None:
        steps = [
            _step(ImpactCeiling.OBSERVE),
            _step(ImpactCeiling.EXPLOIT),
            _step(ImpactCeiling.PROBE),
        ]
        assert OperationRiskAssessor.assess(steps) == OperationRisk.HIGH
        steps.append(_step(ImpactCeiling.DESTRUCT))
        assert OperationRiskAssessor.assess(steps) == OperationRisk.CRITICAL
