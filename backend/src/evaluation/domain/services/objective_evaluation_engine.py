"""ObjectiveEvaluationEngine — evaluates CampaignObjectives against M29/M28 evidence.

Stateless domain service. Criteria condition_types:
  FindingPresent | EvidencePresent | AttackActionCompleted | DetectionAbsent
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from evaluation.domain.entities.evaluation_entities import ObjectiveAssessment
from evaluation.domain.value_objects.enums import ObjectiveOutcome
from evaluation.domain.value_objects.identifiers import ObjectiveAssessmentId

if TYPE_CHECKING:
    from datetime import datetime

    from evaluation.domain.value_objects.evaluation_vos import (
        AttackActionRecord,
        DetectionFindingRecord,
        EvidenceRecord,
        ObjectiveSpec,
    )


class ObjectiveEvaluationEngine:
    """Evaluates each CampaignObjective's ObjectiveEvaluationCriteria.

    DetectionAbsent: criterion satisfied only if no M28 finding in the time window.
    Assessment is idempotent per objective_id for a given evaluation.
    """

    def evaluate(
        self,
        objective: ObjectiveSpec,
        actions: list[AttackActionRecord],
        findings: list[DetectionFindingRecord],
        evidence: list[EvidenceRecord],
        now: datetime,
    ) -> ObjectiveAssessment:
        condition = objective.condition_type
        if condition == "FindingPresent":
            outcome, refs, reason = self._eval_finding_present(objective, findings)
        elif condition == "EvidencePresent":
            outcome, refs, reason = self._eval_evidence_present(objective, evidence)
        elif condition == "AttackActionCompleted":
            outcome, refs, reason = self._eval_action_completed(objective, actions)
        elif condition == "DetectionAbsent":
            outcome, refs, reason = self._eval_detection_absent(objective, findings)
        else:
            outcome = ObjectiveOutcome.INCONCLUSIVE
            refs = []
            reason = f"Unknown condition_type '{condition}' — requires analyst review"

        return ObjectiveAssessment(
            assessment_id=ObjectiveAssessmentId.generate(),
            objective_id=objective.objective_id,
            objective_type=objective.objective_type,
            outcome=outcome,
            evidence_refs=refs,
            reason=reason,
            assessed_at=now,
        )

    def _eval_finding_present(
        self,
        objective: ObjectiveSpec,
        findings: list[DetectionFindingRecord],
    ) -> tuple[ObjectiveOutcome, list[str], str]:
        technique_id = objective.parameters.get("technique_id")
        matched = [f for f in findings if technique_id is None or f.technique_id == technique_id]
        if matched:
            return (
                ObjectiveOutcome.ACHIEVED,
                [f.finding_id for f in matched],
                f"Found {len(matched)} matching detection finding(s)",
            )
        return ObjectiveOutcome.FAILED, [], "No matching DetectionFinding present"

    def _eval_evidence_present(
        self,
        objective: ObjectiveSpec,
        evidence: list[EvidenceRecord],
    ) -> tuple[ObjectiveOutcome, list[str], str]:
        evidence_type = objective.parameters.get("evidence_type")
        matched = [e for e in evidence if evidence_type is None or e.evidence_type == evidence_type]
        if matched:
            return (
                ObjectiveOutcome.ACHIEVED,
                [e.evidence_id for e in matched],
                f"Found {len(matched)} matching evidence ref(s)",
            )
        return ObjectiveOutcome.FAILED, [], "No matching ExecutionEvidence present"

    def _eval_action_completed(
        self,
        objective: ObjectiveSpec,
        actions: list[AttackActionRecord],
    ) -> tuple[ObjectiveOutcome, list[str], str]:
        technique_id = objective.parameters.get("technique_id")
        matched = [
            a
            for a in actions
            if a.outcome in {"Success", "PartialSuccess"}
            and (technique_id is None or a.technique_id == technique_id)
        ]
        if matched:
            return (
                ObjectiveOutcome.ACHIEVED,
                [a.action_id for a in matched],
                f"{len(matched)} AttackAction(s) completed successfully",
            )
        return ObjectiveOutcome.FAILED, [], "No matching completed AttackAction"

    def _eval_detection_absent(
        self,
        objective: ObjectiveSpec,
        findings: list[DetectionFindingRecord],
    ) -> tuple[ObjectiveOutcome, list[str], str]:
        """Satisfied only if no M28 finding exists in the evaluation window."""
        technique_id = objective.parameters.get("technique_id")
        matched = [f for f in findings if technique_id is None or f.technique_id == technique_id]
        if not matched:
            return (
                ObjectiveOutcome.ACHIEVED,
                [],
                "No DetectionFinding in window — DetectionAbsent satisfied",
            )
        return (
            ObjectiveOutcome.FAILED,
            [f.finding_id for f in matched],
            f"DetectionAbsent failed: {len(matched)} finding(s) present",
        )
