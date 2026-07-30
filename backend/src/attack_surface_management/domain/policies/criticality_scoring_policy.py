"""CriticalityScoringPolicy — computes a numeric `CriticalityScore`
(0-100) that combines an asset's business-assigned `Criticality` tier
with its observed `ExposureState`, so prioritization reflects both "how
important is this asset" and "how reachable is it right now" rather
than either alone."""

from __future__ import annotations

from attack_surface_management.domain.value_objects.criticality_score import CriticalityScore
from attack_surface_management.domain.value_objects.enums import Criticality, ExposureState

_BASE_SCORE: dict[Criticality, int] = {
    Criticality.CRITICAL: 80,
    Criticality.HIGH: 60,
    Criticality.MEDIUM: 40,
    Criticality.LOW: 20,
    Criticality.UNRATED: 10,
}

_EXPOSURE_BONUS: dict[ExposureState, int] = {
    ExposureState.EXPOSED_HIGH_RISK: 20,
    ExposureState.INTERNET_FACING: 10,
    ExposureState.NOT_EXPOSED: 0,
    ExposureState.UNKNOWN: 0,
}


class CriticalityScoringPolicy:
    @staticmethod
    def score(criticality: Criticality, exposure_state: ExposureState) -> CriticalityScore:
        base = _BASE_SCORE[criticality]
        bonus = _EXPOSURE_BONUS[exposure_state]
        return CriticalityScore(min(100, base + bonus))
