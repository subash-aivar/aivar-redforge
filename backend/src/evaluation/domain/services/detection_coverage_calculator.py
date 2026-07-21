"""DetectionCoverageCalculator — correlates AttackActions with DetectionFindings.

Hardening rules:
- Correlation window configurable per campaign (default 30 minutes)
- Out-of-window findings → LateDetectionRecord (not primary coverage)
- Explicit graph link (linked_action_id) overrides heuristic window
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from evaluation.domain.entities.evaluation_entities import (
    LateDetectionRecord,
    TechniqueOutcomeRecord,
)
from evaluation.domain.value_objects.evaluation_vos import MitreAttackRef

if TYPE_CHECKING:
    from evaluation.domain.value_objects.evaluation_vos import (
        AttackActionRecord,
        DetectionCorrelationConfig,
        DetectionFindingRecord,
        EvaluationMetrics,
    )


@dataclass(frozen=True, slots=True)
class CoverageComputationResult:
    metrics: EvaluationMetrics
    technique_outcomes: tuple[TechniqueOutcomeRecord, ...]
    late_detections: tuple[LateDetectionRecord, ...]
    techniques_executed: int
    techniques_detected: int
    per_phase_coverage: tuple[tuple[str, float], ...] = ()


class DetectionCoverageCalculator:
    """Computes DetectionCoveragePercent, MeanTimeToDetect, and EvasionRate."""

    def compute(
        self,
        actions: list[AttackActionRecord],
        findings: list[DetectionFindingRecord],
        config: DetectionCorrelationConfig,
    ) -> CoverageComputationResult:
        from evaluation.domain.value_objects.evaluation_vos import EvaluationMetrics

        if not actions:
            empty = EvaluationMetrics()
            return CoverageComputationResult(
                metrics=empty,
                technique_outcomes=(),
                late_detections=(),
                techniques_executed=0,
                techniques_detected=0,
                per_phase_coverage=(),
            )

        window_seconds = config.correlation_window_minutes * 60
        actions_by_technique = self._group_actions(actions)
        findings_by_action = self._index_findings_by_action(findings)
        findings_by_asset_technique = self._index_findings_heuristic(findings)

        technique_outcomes: list[TechniqueOutcomeRecord] = []
        late_detections: list[LateDetectionRecord] = []
        mttd_samples: list[float] = []
        techniques_detected = 0
        techniques_succeeded = 0
        techniques_attempted = len(actions_by_technique)
        actions_failed = sum(1 for a in actions if a.outcome == "Failure")

        for technique_id, tech_actions in actions_by_technique.items():
            succeeded = any(a.outcome in {"Success", "PartialSuccess"} for a in tech_actions)
            if succeeded:
                techniques_succeeded += 1

            detected_findings: list[DetectionFindingRecord] = []
            late_for_tech: list[LateDetectionRecord] = []

            for action in tech_actions:
                linked = findings_by_action.get(action.action_id, [])
                if linked and config.include_graph_linked_findings:
                    detected_findings.extend(linked)
                    for f in linked:
                        delay = self._delay_seconds(action, f)
                        if delay is not None:
                            mttd_samples.append(delay)
                    continue

                heuristic = findings_by_asset_technique.get((action.asset_ref, technique_id), [])
                for f in heuristic:
                    delay = self._delay_seconds(action, f)
                    if delay is None:
                        continue
                    if 0 <= delay <= window_seconds:
                        detected_findings.append(f)
                        mttd_samples.append(delay)
                    elif delay > window_seconds:
                        late_for_tech.append(
                            LateDetectionRecord(
                                finding_id=f.finding_id,
                                technique_id=technique_id,
                                delay_seconds=delay,
                            )
                        )

            detected = len(detected_findings) > 0
            if detected:
                techniques_detected += 1
            late_detections.extend(late_for_tech)

            technique_outcomes.append(
                TechniqueOutcomeRecord(
                    technique_ref=MitreAttackRef(
                        technique_id=technique_id,
                        technique_name=technique_id,
                    ),
                    succeeded=succeeded,
                    detected=detected,
                    evaded=succeeded and not detected,
                    action_ids=[a.action_id for a in tech_actions],
                    finding_ids=[f.finding_id for f in detected_findings],
                )
            )

        techniques_executed = techniques_attempted
        coverage = (
            (techniques_detected / techniques_executed) * 100.0 if techniques_executed > 0 else 0.0
        )
        success_rate = (
            (techniques_succeeded / techniques_attempted) * 100.0
            if techniques_attempted > 0
            else 0.0
        )
        techniques_evaded = sum(1 for t in technique_outcomes if t.evaded)
        evasion = (
            (techniques_evaded / techniques_executed) * 100.0 if techniques_executed > 0 else 0.0
        )
        mttd = sum(mttd_samples) / len(mttd_samples) if mttd_samples else None

        metrics = EvaluationMetrics(
            detection_coverage_percent=round(coverage, 2),
            technique_success_rate=round(success_rate, 2),
            evasion_rate=round(evasion, 2),
            mean_time_to_detect_seconds=mttd,
            actions_executed_count=len(actions),
            actions_failed_count=actions_failed,
        )
        per_phase = self._per_phase_coverage(actions, technique_outcomes)
        return CoverageComputationResult(
            metrics=metrics,
            technique_outcomes=tuple(technique_outcomes),
            late_detections=tuple(late_detections),
            techniques_executed=techniques_executed,
            techniques_detected=techniques_detected,
            per_phase_coverage=per_phase,
        )

    def _per_phase_coverage(
        self,
        actions: list[AttackActionRecord],
        technique_outcomes: list[TechniqueOutcomeRecord],
    ) -> tuple[tuple[str, float], ...]:
        detected_by_tech = {t.technique_ref.technique_id: t.detected for t in technique_outcomes}
        phase_totals: dict[str, list[bool]] = {}
        for action in actions:
            phase = action.kill_chain_phase or "Unknown"
            phase_totals.setdefault(phase, []).append(
                detected_by_tech.get(action.technique_id, False)
            )
        result: list[tuple[str, float]] = []
        for phase, flags in sorted(phase_totals.items()):
            pct = (sum(1 for f in flags if f) / len(flags)) * 100.0 if flags else 0.0
            result.append((phase, round(pct, 2)))
        return tuple(result)

    def _group_actions(
        self, actions: list[AttackActionRecord]
    ) -> dict[str, list[AttackActionRecord]]:
        grouped: dict[str, list[AttackActionRecord]] = {}
        for a in actions:
            grouped.setdefault(a.technique_id, []).append(a)
        return grouped

    def _index_findings_by_action(
        self, findings: list[DetectionFindingRecord]
    ) -> dict[str, list[DetectionFindingRecord]]:
        indexed: dict[str, list[DetectionFindingRecord]] = {}
        for f in findings:
            if f.linked_action_id:
                indexed.setdefault(f.linked_action_id, []).append(f)
        return indexed

    def _index_findings_heuristic(
        self, findings: list[DetectionFindingRecord]
    ) -> dict[tuple[str, str], list[DetectionFindingRecord]]:
        indexed: dict[tuple[str, str], list[DetectionFindingRecord]] = {}
        for f in findings:
            key = (f.asset_ref, f.technique_id)
            indexed.setdefault(key, []).append(f)
        return indexed

    def _delay_seconds(
        self,
        action: AttackActionRecord,
        finding: DetectionFindingRecord,
    ) -> float | None:
        try:
            started = datetime.fromisoformat(action.started_at)
            detected = datetime.fromisoformat(finding.detected_at)
            return (detected - started).total_seconds()
        except ValueError:
            return None
