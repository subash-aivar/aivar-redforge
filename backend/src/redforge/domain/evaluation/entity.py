"""EvaluationResult aggregate root.

The canonical, immutable answer to "did this executed attack actually
succeed" — the decision-making intelligence output of the evaluation
pipeline (see pipeline.py's EvaluationEngine). Gives the existing
evaluation engine's output (previously a fresh, identity-less bundle of
dataclasses on every run — see value_objects.py's module docstring)
identity, immutability, and a place other aggregates (Findings, Risk,
the Knowledge Graph) can reference.

Immutability: the same pattern as domain.planning.AttackPlan and
domain.payloads.PayloadBundle — a complete artifact built in one shot
via create(), with the single allowed mutation being supersede() (a
re-evaluation retiring the old result, never editing it in place).
"""

from __future__ import annotations

from typing import Self

from redforge.domain.evaluation.events import (
    EvaluationEvent,
    EvaluationResultCreated,
    EvaluationResultSuperseded,
    _now,
)
from redforge.domain.evaluation.exceptions import (
    EmptyEvaluationTrailError,
    EvaluationAlreadySupersededError,
)
from redforge.domain.evaluation.value_objects import (
    AttackOutcome,
    Confidence,
    EvaluationEvidence,
    EvaluationStatus,
    RecommendedFinding,
    RecommendedRemediation,
    RecommendedSeverity,
    RiskContribution,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps


class EvaluationResult:
    """EvaluationResult aggregate root.

    Invariants:
    - Always has at least one EvaluationEvidence entry (EmptyEvaluationTrailError
      otherwise) — an evaluation with no evaluator opinion is not a valid
      result.
    - recommended_finding/recommended_severity/recommended_remediation
      are only meaningful (non-None) when outcome indicates the attack
      succeeded, at least partially — enforced at construction, not left
      to callers to get right (see create()'s validation).
    - Immutable except for the single supersede() transition.
    """

    __slots__ = (
        "_attack_id",
        "_attack_plan_id",
        "_confidence",
        "_evaluation_trail",
        "_events",
        "_evidence_ids",
        "_id",
        "_metadata",
        "_organization_id",
        "_outcome",
        "_recommended_finding",
        "_recommended_remediation",
        "_recommended_severity",
        "_risk_contribution",
        "_status",
        "_superseded_by",
        "_target_id",
        "_timestamps",
    )

    def __init__(
        self,
        id: EntityId,
        organization_id: EntityId,
        target_id: EntityId,
        attack_id: EntityId,
        attack_plan_id: EntityId | None,
        evidence_ids: tuple[EntityId, ...],
        outcome: AttackOutcome,
        confidence: Confidence,
        evaluation_trail: tuple[EvaluationEvidence, ...],
        risk_contribution: RiskContribution,
        recommended_finding: RecommendedFinding | None,
        recommended_severity: RecommendedSeverity | None,
        recommended_remediation: RecommendedRemediation | None,
        status: EvaluationStatus,
        superseded_by: EntityId | None,
        metadata: dict[str, str],
        timestamps: AuditTimestamps,
    ) -> None:
        self._id = id
        self._organization_id = organization_id
        self._target_id = target_id
        self._attack_id = attack_id
        self._attack_plan_id = attack_plan_id
        self._evidence_ids = evidence_ids
        self._outcome = outcome
        self._confidence = confidence
        self._evaluation_trail = evaluation_trail
        self._risk_contribution = risk_contribution
        self._recommended_finding = recommended_finding
        self._recommended_severity = recommended_severity
        self._recommended_remediation = recommended_remediation
        self._status = status
        self._superseded_by = superseded_by
        self._metadata = metadata
        self._timestamps = timestamps
        self._events: list[EvaluationEvent] = []

    @classmethod
    def create(
        cls,
        organization_id: EntityId,
        target_id: EntityId,
        attack_id: EntityId,
        evidence_ids: tuple[EntityId, ...],
        outcome: AttackOutcome,
        confidence: Confidence,
        evaluation_trail: tuple[EvaluationEvidence, ...],
        risk_contribution: RiskContribution,
        *,
        attack_plan_id: EntityId | None = None,
        recommended_finding: RecommendedFinding | None = None,
        recommended_severity: RecommendedSeverity | None = None,
        recommended_remediation: RecommendedRemediation | None = None,
        metadata: dict[str, str] | None = None,
    ) -> Self:
        """Create a complete, immutable EvaluationResult.

        Raises:
            EmptyEvaluationTrailError: If `evaluation_trail` has zero entries.
            ValueError: If a recommendation is attached to an outcome
                that doesn't warrant one (FAILURE/INCONCLUSIVE/ERROR),
                or omitted for one that does (SUCCESS/PARTIAL_SUCCESS).
        """
        if not evaluation_trail:
            raise EmptyEvaluationTrailError(str(attack_id))

        warrants_finding = outcome in {AttackOutcome.SUCCESS, AttackOutcome.PARTIAL_SUCCESS}
        if warrants_finding and recommended_finding is None:
            raise ValueError(
                f"outcome '{outcome}' warrants a recommended_finding, but none was given"
            )
        if not warrants_finding and recommended_finding is not None:
            raise ValueError(
                f"outcome '{outcome}' does not warrant a recommended_finding, "
                "but one was given"
            )

        result = cls(
            id=EntityId.generate(),
            organization_id=organization_id,
            target_id=target_id,
            attack_id=attack_id,
            attack_plan_id=attack_plan_id,
            evidence_ids=evidence_ids,
            outcome=outcome,
            confidence=confidence,
            evaluation_trail=evaluation_trail,
            risk_contribution=risk_contribution,
            recommended_finding=recommended_finding,
            recommended_severity=recommended_severity,
            recommended_remediation=recommended_remediation,
            status=EvaluationStatus.ACTIVE,
            superseded_by=None,
            metadata=metadata or {},
            timestamps=AuditTimestamps.create(),
        )
        result._record_event(
            EvaluationResultCreated(
                occurred_at=_now(),
                evaluation_id=str(result._id),
                attack_id=str(attack_id),
                outcome=str(outcome),
                confidence=confidence.score,
            )
        )
        return result

    # ─── Properties ───────────────────────────────────────────────────────

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def organization_id(self) -> EntityId:
        return self._organization_id

    @property
    def target_id(self) -> EntityId:
        return self._target_id

    @property
    def attack_id(self) -> EntityId:
        return self._attack_id

    @property
    def attack_plan_id(self) -> EntityId | None:
        return self._attack_plan_id

    @property
    def evidence_ids(self) -> tuple[EntityId, ...]:
        return self._evidence_ids

    @property
    def outcome(self) -> AttackOutcome:
        return self._outcome

    @property
    def confidence(self) -> Confidence:
        return self._confidence

    @property
    def evaluation_trail(self) -> tuple[EvaluationEvidence, ...]:
        return self._evaluation_trail

    @property
    def risk_contribution(self) -> RiskContribution:
        return self._risk_contribution

    @property
    def recommended_finding(self) -> RecommendedFinding | None:
        return self._recommended_finding

    @property
    def recommended_severity(self) -> RecommendedSeverity | None:
        return self._recommended_severity

    @property
    def recommended_remediation(self) -> RecommendedRemediation | None:
        return self._recommended_remediation

    @property
    def status(self) -> EvaluationStatus:
        return self._status

    @property
    def superseded_by(self) -> EntityId | None:
        return self._superseded_by

    @property
    def metadata(self) -> dict[str, str]:
        return dict(self._metadata)

    @property
    def timestamps(self) -> AuditTimestamps:
        return self._timestamps

    @property
    def is_active(self) -> bool:
        return self._status == EvaluationStatus.ACTIVE

    @property
    def indicates_success(self) -> bool:
        return self._outcome in {AttackOutcome.SUCCESS, AttackOutcome.PARTIAL_SUCCESS}

    @property
    def evaluator_names(self) -> tuple[str, ...]:
        return tuple(e.evaluator_name for e in self._evaluation_trail)

    # ─── Lifecycle ────────────────────────────────────────────────────────

    def supersede(self, new_evaluation_id: EntityId) -> None:
        """Mark this result superseded by a newer result (a re-evaluation).

        Raises:
            EvaluationAlreadySupersededError: If already superseded.
        """
        if self._status == EvaluationStatus.SUPERSEDED:
            raise EvaluationAlreadySupersededError(str(self._id))
        self._status = EvaluationStatus.SUPERSEDED
        self._superseded_by = new_evaluation_id
        self._touch()
        self._record_event(
            EvaluationResultSuperseded(
                occurred_at=_now(),
                evaluation_id=str(self._id),
                superseded_by=str(new_evaluation_id),
            )
        )

    # ─── Events ───────────────────────────────────────────────────────────

    def collect_events(self) -> list[EvaluationEvent]:
        events = self._events.copy()
        self._events.clear()
        return events

    # ─── Private ──────────────────────────────────────────────────────────

    def _touch(self) -> None:
        self._timestamps = self._timestamps.mark_updated()

    def _record_event(self, event: EvaluationEvent) -> None:
        self._events.append(event)

    # ─── Equality ─────────────────────────────────────────────────────────

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, EvaluationResult):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return (
            f"EvaluationResult(id={self._id}, attack_id={self._attack_id}, "
            f"outcome={self._outcome}, confidence={self._confidence.score:.2f}, "
            f"status={self._status})"
        )
