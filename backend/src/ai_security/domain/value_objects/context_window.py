"""ContextWindow — a positive-integer token-count value object
(M47A). No relation to actual context truncation/handling logic."""

from __future__ import annotations

from dataclasses import dataclass

from ai_security.domain.exceptions.domain_exceptions import InvalidContextWindowError


@dataclass(frozen=True, slots=True)
class ContextWindow:
    value: int

    def __post_init__(self) -> None:
        if self.value <= 0:
            raise InvalidContextWindowError(self.value)

    def __str__(self) -> str:
        return str(self.value)
