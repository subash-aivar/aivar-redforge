"""Evaluation bounded context domain entities."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from evaluation.domain.value_objects.enums import ObjectiveOutcome
    from evaluation.domain.value_objects.evaluation_vos import (
        MitreAttackRef,
    )
    from evaluation.domain.value_objects.identifiers import ObjectiveAssessmentId


class ObjectiveAssessment:
    """Assessment of a single CampaignObjective against collected evidence.

    One per CampaignObjective; sealed once EvaluationState = Complete.
    """

    __slots__ = (
        "_assessed_at",
        "_evidence_refs",
        "_objective_id",
        "_objective_type",
        "_outcome",
        "_reason",
        "assessment_id",
    )

    def __init__(
        self,
        assessment_id: ObjectiveAssessmentId,
        objective_id: str,
        objective_type: str,
        outcome: ObjectiveOutcome,
        evidence_refs: list[str],
        reason: str = "",
        assessed_at: datetime | None = None,
    ) -> None:
        self.assessment_id = assessment_id
        self._objective_id = objective_id
        self._objective_type = objective_type
        self._outcome = outcome
        self._evidence_refs: list[str] = list(evidence_refs)
        self._reason = reason
        self._assessed_at = assessed_at

    @property
    def objective_id(self) -> str:
        return self._objective_id

    @property
    def objective_type(self) -> str:
        return self._objective_type

    @property
    def outcome(self) -> ObjectiveOutcome:
        return self._outcome

    @property
    def evidence_refs(self) -> list[str]:
        return list(self._evidence_refs)

    @property
    def reason(self) -> str:
        return self._reason

    @property
    def assessed_at(self) -> datetime | None:
        return self._assessed_at


class TechniqueOutcomeRecord:
    """Outcome record for one ATT&CK technique exercised in the campaign.

    One per technique; tracks success, detection, and evasion status.
    """

    __slots__ = (
        "_detected",
        "_evaded",
        "_succeeded",
        "_technique_ref",
        "action_ids",
        "finding_ids",
    )

    def __init__(
        self,
        technique_ref: MitreAttackRef,
        succeeded: bool,
        detected: bool,
        evaded: bool,
        action_ids: list[str] | None = None,
        finding_ids: list[str] | None = None,
    ) -> None:
        self._technique_ref = technique_ref
        self._succeeded = succeeded
        self._detected = detected
        self._evaded = evaded
        self.action_ids: list[str] = list(action_ids or [])
        self.finding_ids: list[str] = list(finding_ids or [])

    @property
    def technique_ref(self) -> MitreAttackRef:
        return self._technique_ref

    @property
    def succeeded(self) -> bool:
        return self._succeeded

    @property
    def detected(self) -> bool:
        return self._detected

    @property
    def evaded(self) -> bool:
        return self._evaded

    @property
    def technique_id(self) -> str:
        return self._technique_ref.technique_id


class LateDetectionRecord:
    """A DetectionFinding that arrived outside the primary correlation window.

    Not counted in primary DetectionCoveragePercent but visible for MTTD trend analysis.
    """

    __slots__ = (
        "_delay_seconds",
        "_technique_id",
        "finding_id",
    )

    def __init__(
        self,
        finding_id: str,
        technique_id: str,
        delay_seconds: float,
    ) -> None:
        self.finding_id = finding_id
        self._technique_id = technique_id
        self._delay_seconds = delay_seconds

    @property
    def technique_id(self) -> str:
        return self._technique_id

    @property
    def delay_seconds(self) -> float:
        return self._delay_seconds
