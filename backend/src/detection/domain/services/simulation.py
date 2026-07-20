"""Rule simulation — isolated evaluation without findings or execution engine."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from uuid import uuid7

from detection.domain.exceptions.domain_exceptions import (
    InvalidArgument,
    SimulationBlocked,
)
from detection.domain.providers.normalized_models import (
    NormalizedCondition,
    NormalizedQuery,
    NormalizedTelemetryEvent,
    NormalizedTelemetryResult,
)
from detection.domain.value_objects.enums import ConditionOperator, RuleLogicType
from detection.domain.value_objects.identifiers import SimulationId
from detection.domain.value_objects.rule_logic import NormalizedFieldRef, RuleCondition

if TYPE_CHECKING:
    from datetime import datetime

    from detection.domain.aggregates.detection_rule import DetectionRule
    from detection.domain.aggregates.telemetry_source import TelemetrySource
    from detection.domain.value_objects.identifiers import DetectionRuleId, TenantId
    from detection.domain.value_objects.rule_logic import RuleLogic
    from detection.domain.value_objects.telemetry import TimeWindow


@dataclass(frozen=True, slots=True)
class SimulationMatchSample:
    """Sample match — normalized field refs only (no vendor fields)."""

    fields: dict[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "fields", dict(self.fields))


@dataclass(frozen=True, slots=True)
class SimulationStatistics:
    events_evaluated: int
    match_count: int
    duration_ms: float
    truncated: bool = False
    source_unavailable: bool = False


@dataclass(frozen=True, slots=True)
class SimulationEvidenceModel:
    """
    In-memory simulation evidence lineage model.

    Phase 2 does not persist DetectionEvidence aggregates; this captures
    the evidence shape for auditability without creating findings.
    """

    evidence_type: str = "SimulationResult"
    rule_id: str = ""
    rule_version: str | None = None
    source_id: str = ""
    window_start: str = ""
    window_end: str = ""
    match_count: int = 0
    simulated_at: str = ""
    payload_summary: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.evidence_type != "SimulationResult":
            raise InvalidArgument(
                "SimulationEvidenceModel.evidence_type",
                "must be SimulationResult",
            )
        object.__setattr__(self, "payload_summary", dict(self.payload_summary))


@dataclass(frozen=True, slots=True)
class SimulationResult:
    """Isolated simulation output — never a DetectionFinding."""

    simulation_id: SimulationId
    tenant_id: TenantId
    rule_id: DetectionRuleId
    rule_version: str | None
    source_id: str
    statistics: SimulationStatistics
    sample_matches: tuple[SimulationMatchSample, ...]
    evidence: SimulationEvidenceModel
    simulated_at: datetime
    creates_findings: bool = False  # always False — invariant

    def __post_init__(self) -> None:
        if self.creates_findings:
            raise InvalidArgument(
                "SimulationResult.creates_findings",
                "simulation must never create findings",
            )


class SimulationValidator:
    """Pre-flight checks before simulation runs."""

    def validate(
        self,
        *,
        rule: DetectionRule,
        source: TelemetrySource,
        window: TimeWindow,
    ) -> None:
        if not source.is_active:
            raise SimulationBlocked("telemetry source is not Active")
        if source.tenant_id != rule.tenant_id:
            raise SimulationBlocked("rule and source tenant mismatch")
        if window.end <= window.start:
            raise SimulationBlocked("invalid time window")
        if window.duration > source.retention.retention:
            raise SimulationBlocked(
                "requested window exceeds source retention window"
            )


class RuleSimulationService:
    """
    Evaluates RuleLogic against NormalizedTelemetryResult.

    Completely isolated from DetectionFinding creation and execution engine.
    """

    def __init__(self, *, max_samples: int = 25) -> None:
        self._max_samples = max_samples
        self._validator = SimulationValidator()

    def build_query(
        self,
        logic: RuleLogic,
        window: TimeWindow,
        *,
        limit: int = 1000,
    ) -> NormalizedQuery:
        flat: list[NormalizedCondition] = []
        for cond in logic.conditions:
            flat.extend(self._condition_to_normalized(cond))
        if not flat:
            raise InvalidArgument("NormalizedQuery", "at least one condition required")
        fields = tuple(logic.normalized_field_refs) or tuple(
            NormalizedFieldRef(p) for p in {c.field.path for c in flat}
        )
        return NormalizedQuery(
            conditions=tuple(flat),
            logic_type=logic.logic_type,
            window=window,
            limit=limit,
            normalized_fields_requested=fields,
        )

    def _condition_to_normalized(
        self, cond: RuleCondition
    ) -> list[NormalizedCondition]:
        items = [
            NormalizedCondition(
                field=cond.field,
                operator=cond.operator,
                value=cond.value,
            )
        ]
        for child in cond.children:
            items.extend(self._condition_to_normalized(child))
        return items

    def evaluate_event(
        self,
        logic: RuleLogic,
        event: NormalizedTelemetryEvent,
    ) -> bool:
        if not logic.conditions:
            return False
        # Top-level conditions are AND-combined for Condition/Threshold types
        results = [self._eval_condition(c, event) for c in logic.conditions]
        if logic.logic_type == RuleLogicType.CORRELATION:
            # Correlation needs sibling findings — not available in simulation
            return all(results)
        return all(results)

    def _eval_condition(
        self,
        cond: RuleCondition,
        event: NormalizedTelemetryEvent,
    ) -> bool:
        if cond.children:
            child_results = [self._eval_condition(c, event) for c in cond.children]
            if cond.connector is None:
                return all(child_results)
            from detection.domain.value_objects.enums import LogicConnector

            if cond.connector == LogicConnector.AND:
                return all(child_results)
            if cond.connector == LogicConnector.OR:
                return any(child_results)
            if cond.connector == LogicConnector.NOT:
                return not child_results[0]

        value = event.get(cond.field.path)
        return self._apply_operator(cond.operator, value, cond.value)

    def _apply_operator(
        self,
        operator: ConditionOperator,
        actual: Any,
        expected: Any,
    ) -> bool:
        if operator == ConditionOperator.EXISTS:
            return actual is not None
        if operator == ConditionOperator.NOT_EXISTS:
            return actual is None
        if actual is None:
            return False
        if operator == ConditionOperator.EQUALS:
            return bool(actual == expected)
        if operator == ConditionOperator.NOT_EQUALS:
            return bool(actual != expected)
        if operator == ConditionOperator.CONTAINS:
            return bool(expected in str(actual))
        if operator == ConditionOperator.NOT_CONTAINS:
            return bool(expected not in str(actual))
        if operator == ConditionOperator.STARTS_WITH:
            return bool(str(actual).startswith(str(expected)))
        if operator == ConditionOperator.ENDS_WITH:
            return bool(str(actual).endswith(str(expected)))
        if operator == ConditionOperator.GREATER_THAN:
            return bool(actual > expected)
        if operator == ConditionOperator.GREATER_OR_EQUAL:
            return bool(actual >= expected)
        if operator == ConditionOperator.LESS_THAN:
            return bool(actual < expected)
        if operator == ConditionOperator.LESS_OR_EQUAL:
            return bool(actual <= expected)
        if operator == ConditionOperator.IN:
            return bool(actual in (expected or []))
        if operator == ConditionOperator.NOT_IN:
            return bool(actual not in (expected or []))
        if operator == ConditionOperator.REGEX:
            import re

            return re.search(str(expected), str(actual)) is not None
        return False

    def evaluate_threshold(
        self,
        logic: RuleLogic,
        events: tuple[NormalizedTelemetryEvent, ...],
    ) -> list[NormalizedTelemetryEvent]:
        """Group by aggregation_field and apply threshold_count."""
        if logic.logic_type != RuleLogicType.THRESHOLD:
            return [e for e in events if self.evaluate_event(logic, e)]
        matching = [e for e in events if self.evaluate_event(logic, e)]
        if not logic.aggregation_field or not logic.threshold_count:
            return matching
        groups: dict[Any, list[NormalizedTelemetryEvent]] = {}
        for event in matching:
            key = event.get(logic.aggregation_field)
            groups.setdefault(key, []).append(event)
        result: list[NormalizedTelemetryEvent] = []
        for group in groups.values():
            if len(group) >= logic.threshold_count:
                result.extend(group)
        return result

    def simulate(
        self,
        *,
        rule: DetectionRule,
        source: TelemetrySource,
        window: TimeWindow,
        telemetry: NormalizedTelemetryResult,
        now: datetime,
        rule_version: str | None = None,
    ) -> SimulationResult:
        self._validator.validate(rule=rule, source=source, window=window)
        started = time.perf_counter()

        if telemetry.source_unavailable:
            duration_ms = (time.perf_counter() - started) * 1000.0
            stats = SimulationStatistics(
                events_evaluated=0,
                match_count=0,
                duration_ms=duration_ms,
                source_unavailable=True,
            )
            evidence = SimulationEvidenceModel(
                rule_id=str(rule.rule_id),
                rule_version=rule_version,
                source_id=str(source.source_id),
                window_start=window.start.isoformat(),
                window_end=window.end.isoformat(),
                match_count=0,
                simulated_at=now.isoformat(),
                payload_summary={"unavailable": telemetry.unavailable_reason},
            )
            return SimulationResult(
                simulation_id=SimulationId.generate(),
                tenant_id=rule.tenant_id,
                rule_id=rule.rule_id,
                rule_version=rule_version,
                source_id=str(source.source_id),
                statistics=stats,
                sample_matches=(),
                evidence=evidence,
                simulated_at=now,
                creates_findings=False,
            )

        logic = rule.current_logic
        if rule_version:
            version_entity = next(
                (v for v in rule.versions if str(v.semver) == rule_version),
                None,
            )
            if version_entity is not None:
                logic = version_entity.logic

        if logic.logic_type == RuleLogicType.THRESHOLD:
            matches = self.evaluate_threshold(logic, telemetry.events)
        else:
            matches = [e for e in telemetry.events if self.evaluate_event(logic, e)]

        duration_ms = (time.perf_counter() - started) * 1000.0
        samples = tuple(
            SimulationMatchSample(fields=dict(e.fields))
            for e in matches[: self._max_samples]
        )
        stats = SimulationStatistics(
            events_evaluated=len(telemetry.events),
            match_count=len(matches),
            duration_ms=duration_ms + telemetry.query_duration_ms,
            truncated=telemetry.truncated,
        )
        evidence = SimulationEvidenceModel(
            rule_id=str(rule.rule_id),
            rule_version=rule_version,
            source_id=str(source.source_id),
            window_start=window.start.isoformat(),
            window_end=window.end.isoformat(),
            match_count=len(matches),
            simulated_at=now.isoformat(),
            payload_summary={
                "events_evaluated": len(telemetry.events),
                "sample_count": len(samples),
                "evidence_id": str(uuid7()),
            },
        )
        return SimulationResult(
            simulation_id=SimulationId.generate(),
            tenant_id=rule.tenant_id,
            rule_id=rule.rule_id,
            rule_version=rule_version,
            source_id=str(source.source_id),
            statistics=stats,
            sample_matches=samples,
            evidence=evidence,
            simulated_at=now,
            creates_findings=False,
        )
