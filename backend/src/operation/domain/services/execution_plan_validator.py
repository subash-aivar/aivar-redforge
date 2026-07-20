"""ExecutionPlanValidator — validates plan against engagement constraints."""

from __future__ import annotations

from typing import TYPE_CHECKING

from operation.domain.exceptions.domain_exceptions import PlanValidationError
from operation.domain.value_objects.enums import ImpactCeiling, StepType

if TYPE_CHECKING:
    from uuid import UUID

    from operation.domain.aggregates.operation import Operation


class ExecutionPlanValidator:
    """Validates a complete ExecutionPlan before signing."""

    @staticmethod
    def validate(
        operation: Operation,
        *,
        authorized_targets: set[UUID],
        allowed_techniques: set[str],
    ) -> None:
        errors: list[str] = []
        errors.extend(ExecutionPlanValidator._check_targets(operation, authorized_targets))
        errors.extend(ExecutionPlanValidator._check_techniques(operation, allowed_techniques))
        errors.extend(ExecutionPlanValidator._check_acyclic(operation))
        errors.extend(ExecutionPlanValidator._check_exploit_gates(operation))
        errors.extend(ExecutionPlanValidator._check_verification_after_mutate(operation))
        errors.extend(ExecutionPlanValidator._check_rate_limits(operation))
        if errors:
            raise PlanValidationError("; ".join(errors))

    @staticmethod
    def _check_targets(operation: Operation, authorized_targets: set[UUID]) -> list[str]:
        errors: list[str] = []
        for step in operation.steps.values():
            if step.target_ref is None:
                continue
            if step.target_ref.asset_id not in authorized_targets:
                errors.append(
                    f"step {step.step_id} target {step.target_ref.asset_id} out of scope"
                )
        return errors

    @staticmethod
    def _check_techniques(operation: Operation, allowed_techniques: set[str]) -> list[str]:
        errors: list[str] = []
        for step in operation.steps.values():
            if step.technique_ref is None:
                continue
            tid = step.technique_ref.technique_id
            if tid not in allowed_techniques:
                errors.append(f"step {step.step_id} technique {tid} not authorized by RoE")
        return errors

    @staticmethod
    def _check_acyclic(operation: Operation) -> list[str]:
        adjacency: dict[str, list[str]] = {}
        for dep in operation.dependencies:
            adjacency.setdefault(str(dep.from_step_id), []).append(str(dep.to_step_id))

        visited: set[str] = set()
        in_stack: set[str] = set()

        def dfs(node: str) -> bool:
            visited.add(node)
            in_stack.add(node)
            for nxt in adjacency.get(node, []):
                if nxt not in visited:
                    if dfs(nxt):
                        return True
                elif nxt in in_stack:
                    return True
            in_stack.discard(node)
            return False

        for step_id in operation.steps:
            if step_id not in visited and dfs(step_id):
                return ["execution plan DAG contains a cycle"]
        return []

    @staticmethod
    def _predecessors(operation: Operation, step_id: str) -> set[str]:
        """All steps that must complete before step_id (reverse edges from→to)."""
        reverse: dict[str, list[str]] = {}
        for dep in operation.dependencies:
            reverse.setdefault(str(dep.to_step_id), []).append(str(dep.from_step_id))
        result: set[str] = set()
        stack = list(reverse.get(step_id, []))
        while stack:
            current = stack.pop()
            if current in result:
                continue
            result.add(current)
            stack.extend(reverse.get(current, []))
        return result

    @staticmethod
    def _successors(operation: Operation, step_id: str) -> set[str]:
        forward: dict[str, list[str]] = {}
        for dep in operation.dependencies:
            forward.setdefault(str(dep.from_step_id), []).append(str(dep.to_step_id))
        result: set[str] = set()
        stack = list(forward.get(step_id, []))
        while stack:
            current = stack.pop()
            if current in result:
                continue
            result.add(current)
            stack.extend(forward.get(current, []))
        return result

    @staticmethod
    def _check_exploit_gates(operation: Operation) -> list[str]:
        errors: list[str] = []
        for step in operation.steps.values():
            if step.step_type != StepType.ATTACK_STEP:
                continue
            if step.impact_ceiling != ImpactCeiling.EXPLOIT:
                continue
            preds = ExecutionPlanValidator._predecessors(operation, str(step.step_id))
            has_gate = any(
                operation.steps[p].step_type == StepType.HUMAN_APPROVAL_GATE
                for p in preds
                if p in operation.steps
            )
            if not has_gate:
                errors.append(
                    f"AttackStep {step.step_id} with impact_ceiling=Exploit "
                    "requires a preceding HumanApprovalGate"
                )
        return errors

    @staticmethod
    def _check_verification_after_mutate(operation: Operation) -> list[str]:
        errors: list[str] = []
        for step in operation.steps.values():
            if step.step_type != StepType.ATTACK_STEP:
                continue
            if not step.modifies_persistent_state:
                continue
            successors = ExecutionPlanValidator._successors(operation, str(step.step_id))
            has_verification = any(
                operation.steps[s].step_type == StepType.VERIFICATION_STEP
                for s in successors
                if s in operation.steps
            )
            if not has_verification:
                errors.append(
                    f"AttackStep {step.step_id} modifies persistent state and "
                    "requires a following VerificationStep"
                )
        return errors

    @staticmethod
    def _check_rate_limits(operation: Operation) -> list[str]:
        """Basic check: rate limit window must fit within execution window hours."""
        errors: list[str] = []
        for step in operation.steps.values():
            if step.rate_limit is None or step.window is None:
                continue
            available_seconds = step.window.window_hours() * 3600
            if step.rate_limit.window_seconds > available_seconds:
                errors.append(
                    f"step {step.step_id} rate limit window exceeds execution window"
                )
            # At least one execution must fit in the available window.
            if step.rate_limit.max_executions < 1:
                errors.append(f"step {step.step_id} rate limit max_executions < 1")
        return errors
