"""DetectionApplicationService — the Detection Engine's single
application-layer entrypoint (M42 Phase 6 / M44A).

Orchestrates, in order: authorization, tenant validation, loading the
tenant's `DetectionRule`s (`IDetectionRuleProvider`), rule-lifecycle/
enabled-state filtering, evaluator selection
(`IDetectionEvaluatorRegistry`), execution, and `DetectionMatch`
construction for anything that matched. Each event is evaluated
independently — no correlation, no windowing, no cross-event state —
and this service never creates an `Alert`, never opens an
investigation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.shared.timestamps import utc_now
from siem_detection.application import _auth
from siem_detection.application.dtos.detection_match import DetectionMatch
from siem_detection.application.dtos.detection_result import (
    BatchDetectionResult,
    DetectionFailure,
    DetectionStatus,
    EventDetectionResult,
    RuleEvaluationOutcome,
)
from siem_detection.application.exceptions import (
    EmptyBatchEvaluationError,
    EvaluatorSelectionError,
    TenantContextMismatchError,
    UnsupportedEvaluatorError,
)
from siem_detection.domain.value_objects.enums import DetectionRole, DetectionRuleStatus

if TYPE_CHECKING:
    from redforge.shared.identifiers import EntityId
    from siem_detection.application.commands.detection_commands import (
        EvaluateBatchCommand,
        EvaluateCanonicalEventCommand,
    )
    from siem_detection.application.ports.i_detection_evaluator_registry import (
        IDetectionEvaluatorRegistry,
    )
    from siem_detection.application.ports.i_detection_rule_provider import IDetectionRuleProvider
    from siem_detection.domain.aggregates.detection_rule import DetectionRule
    from siem_shared.domain.value_objects.canonical_event import CanonicalEvent


def _to_failure(stage: str, exc: Exception) -> DetectionFailure:
    return DetectionFailure(stage=stage, error_type=type(exc).__name__, message=str(exc))


class DetectionApplicationService:
    def __init__(
        self,
        rule_provider: IDetectionRuleProvider,
        evaluator_registry: IDetectionEvaluatorRegistry,
    ) -> None:
        self._rule_provider = rule_provider
        self._registry = evaluator_registry

    def evaluate_event(self, cmd: EvaluateCanonicalEventCommand) -> EventDetectionResult:
        _auth.require_at_least(cmd.actor_roles, DetectionRole.EXECUTOR)
        return self._evaluate(cmd.tenant_id, cmd.canonical_event)

    def evaluate_batch(self, cmd: EvaluateBatchCommand) -> BatchDetectionResult:
        _auth.require_at_least(cmd.actor_roles, DetectionRole.EXECUTOR)
        if not cmd.events:
            raise EmptyBatchEvaluationError()

        results = tuple(self._evaluate(cmd.tenant_id, event) for event in cmd.events)
        succeeded = sum(1 for r in results if r.status == DetectionStatus.SUCCEEDED)

        if succeeded == len(results):
            overall = DetectionStatus.SUCCEEDED
        elif succeeded == 0:
            overall = DetectionStatus.FAILED
        else:
            overall = DetectionStatus.PARTIALLY_SUCCEEDED

        return BatchDetectionResult(status=overall, results=results)

    def _evaluate(self, tenant_id: EntityId, event: CanonicalEvent) -> EventDetectionResult:
        event_id = str(event.identity.event_id)

        if event.tenant.tenant_id != tenant_id:
            failure = _to_failure(
                "tenant_validation", TenantContextMismatchError(tenant_id, event.tenant.tenant_id)
            )
            return EventDetectionResult(
                status=DetectionStatus.EVALUATION_REJECTED, event_id=event_id, failures=(failure,)
            )

        rules = self._rule_provider.get_rules(tenant_id)
        outcomes = tuple(self._evaluate_rule(rule, event) for rule in rules)

        failed = sum(1 for o in outcomes if o.status == DetectionStatus.FAILED)
        if not failed:
            overall = DetectionStatus.SUCCEEDED
        elif failed == len(outcomes):
            overall = DetectionStatus.FAILED
        else:
            overall = DetectionStatus.PARTIALLY_SUCCEEDED

        return EventDetectionResult(status=overall, event_id=event_id, outcomes=outcomes)

    def _evaluate_rule(self, rule: DetectionRule, event: CanonicalEvent) -> RuleEvaluationOutcome:
        rule_id = str(rule.rule_id)

        if rule.status != DetectionRuleStatus.ACTIVE:
            return RuleEvaluationOutcome(rule_id=rule_id, status=DetectionStatus.RULE_DISABLED)

        try:
            evaluator = self._registry.resolve(rule_id, event.metadata.schema_version)
        except EvaluatorSelectionError as exc:
            stage = (
                "unsupported_evaluator"
                if isinstance(exc, UnsupportedEvaluatorError)
                else "evaluator_selection"
            )
            return RuleEvaluationOutcome(
                rule_id=rule_id,
                status=DetectionStatus.RULE_SKIPPED,
                failures=(_to_failure(stage, exc),),
            )

        try:
            evaluation = evaluator.evaluate(event)
        except Exception as exc:
            # An untrusted evaluator's execution failure must never
            # crash the pipeline (same discipline as M43D's normalizer
            # mapping-failure handling) — caught broadly and deliberately.
            return RuleEvaluationOutcome(
                rule_id=rule_id,
                status=DetectionStatus.FAILED,
                failures=(_to_failure("execution", exc),),
            )

        match = None
        if evaluation.matched:
            match = DetectionMatch(
                rule_id=rule_id,
                event_id=str(event.identity.event_id),
                matched_at=utc_now(),
                severity=evaluation.severity,
                confidence=evaluation.confidence,
                reason=evaluation.reason,
            )
        return RuleEvaluationOutcome(rule_id=rule_id, status=DetectionStatus.SUCCEEDED, match=match)
