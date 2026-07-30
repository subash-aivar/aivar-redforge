"""CriticalityScore value object (M49A) — the numeric 0-100 priority
score produced by `CriticalityScoringPolicy`/`CriticalityScoringService`
from an asset's business `Criticality` tier and observed
`ExposureState`."""

from __future__ import annotations

from dataclasses import dataclass

from attack_surface_management.domain.exceptions.domain_exceptions import (
    InvalidCriticalityScoreError,
)


@dataclass(frozen=True, slots=True)
class CriticalityScore:
    value: int

    def __post_init__(self) -> None:
        if not (0 <= self.value <= 100):
            raise InvalidCriticalityScoreError(self.value)
