"""Reuse CSPM PolicyEvaluationEngine via CloudRuntimeEvent.cspm_snapshot()."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from redforge.domain.cloud_security.policy_engine.evaluator import (
    ConditionOutcome,
    PolicyEvaluationEngine,
)
from redforge.domain.cloud_security.runtime.event import CloudRuntimeEvent


@dataclass(frozen=True, slots=True)
class RuntimePolicyEvaluationResult:
    event_id: str
    policy_id: str
    matched: bool
    path: str
    expected: str
    actual: str
    message: str
    snapshot: dict[str, Any]


class RuntimePolicySnapshotPort(Protocol):
    def evaluate_runtime_event(
        self, event: CloudRuntimeEvent, policies: list[Any]
    ) -> list[RuntimePolicyEvaluationResult]: ...


class CspmRuntimePolicyInterface:
    """Thin adapter — no second policy engine."""

    def __init__(self, engine: PolicyEvaluationEngine | None = None) -> None:
        self._engine = engine or PolicyEvaluationEngine()

    def evaluate_runtime_event(
        self, event: CloudRuntimeEvent, policies: list[Any]
    ) -> list[RuntimePolicyEvaluationResult]:
        snapshot = event.cspm_snapshot()
        results: list[RuntimePolicyEvaluationResult] = []
        for policy in policies:
            rule = getattr(policy, "rule", None)
            if rule is None and isinstance(policy, dict):
                rule = policy.get("rule")
            if not isinstance(rule, dict):
                continue
            policy_id = str(
                getattr(policy, "id", None)
                or (policy.get("id") if isinstance(policy, dict) else "")
                or "unknown"
            )
            outcome: ConditionOutcome = self._engine.evaluate(rule, snapshot)
            results.append(
                RuntimePolicyEvaluationResult(
                    event_id=str(event.id),
                    policy_id=policy_id,
                    matched=outcome.matched,
                    path=outcome.path,
                    expected=outcome.expected,
                    actual=outcome.actual,
                    message=outcome.message,
                    snapshot=snapshot,
                )
            )
        return results


def evaluate_runtime_event(
    event: CloudRuntimeEvent,
    policies: list[Any],
    *,
    engine: PolicyEvaluationEngine | None = None,
) -> list[RuntimePolicyEvaluationResult]:
    return CspmRuntimePolicyInterface(engine).evaluate_runtime_event(event, policies)
