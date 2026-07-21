"""AIRiskScoringService — deterministic composite score from components."""

from __future__ import annotations

from ai_posture.domain.value_objects.posture_vos import (
    EXPOSURE_SCORE,
    SCORE_INPUT_VERSION,
    ScoreComponents,
    compute_composite_score,
)


class AIRiskScoringService:
    """Builds ScoreComponents and composite score. Never invoked on read path."""

    def build_components(
        self,
        *,
        max_exposure_score: float,
        provenance_integrity_component: float = 0.0,
        compliance_gap_component: float = 0.0,
        agent_deviation_component: float = 0.0,
    ) -> ScoreComponents:
        return ScoreComponents(
            threat_exposure_component=max_exposure_score,
            provenance_integrity_component=provenance_integrity_component,
            compliance_gap_component=compliance_gap_component,
            agent_deviation_component=agent_deviation_component,
        )

    def exposure_to_score(self, exposure_level_value: str) -> float:
        from ai_posture.domain.value_objects.enums import ExposureLevel

        return EXPOSURE_SCORE[ExposureLevel(exposure_level_value)]

    def compute_composite(self, components: ScoreComponents) -> float:
        return compute_composite_score(components)

    @property
    def score_input_version(self) -> str:
        return SCORE_INPUT_VERSION
