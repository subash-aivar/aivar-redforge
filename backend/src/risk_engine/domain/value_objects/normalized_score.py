"""NormalizedRiskScore — a risk value already converted onto this
context's canonical 0.0-10.0 scale (M48B)."""

from __future__ import annotations

import math
from dataclasses import dataclass

from risk_engine.domain.exceptions.domain_exceptions import InvalidNormalizedRiskScoreError


@dataclass(frozen=True, slots=True)
class NormalizedRiskScore:
    value: float

    def __post_init__(self) -> None:
        if math.isnan(self.value) or math.isinf(self.value):
            raise InvalidNormalizedRiskScoreError(self.value)
        if not (0.0 <= self.value <= 10.0):
            raise InvalidNormalizedRiskScoreError(self.value)
