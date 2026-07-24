"""TokenLimit — a positive-integer token-limit value object (M47A). No
relation to actual token-counting or rate-limiting logic."""

from __future__ import annotations

from dataclasses import dataclass

from ai_security.domain.exceptions.domain_exceptions import InvalidTokenLimitError


@dataclass(frozen=True, slots=True)
class TokenLimit:
    value: int

    def __post_init__(self) -> None:
        if self.value <= 0:
            raise InvalidTokenLimitError(self.value)

    def __str__(self) -> str:
        return str(self.value)
