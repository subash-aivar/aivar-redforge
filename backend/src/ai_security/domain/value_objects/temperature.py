"""Temperature — a validated sampling-temperature value object
(M47A). Bounded to the conventional 0.0-2.0 range; no relation to
actual inference-time sampling behavior."""

from __future__ import annotations

from dataclasses import dataclass

from ai_security.domain.exceptions.domain_exceptions import InvalidTemperatureError


@dataclass(frozen=True, slots=True)
class Temperature:
    value: float

    def __post_init__(self) -> None:
        if not (0.0 <= self.value <= 2.0):
            raise InvalidTemperatureError(self.value)

    def __str__(self) -> str:
        return str(self.value)
