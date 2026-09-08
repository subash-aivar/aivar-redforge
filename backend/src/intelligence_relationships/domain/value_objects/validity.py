"""Validity — the temporal window over which a relationship claim is
asserted to hold. `valid_until=None` means "still asserted"."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from intelligence_relationships.domain.exceptions.domain_exceptions import (
    InvalidValidityWindowError,
)

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class Validity:
    valid_from: datetime
    valid_until: datetime | None = None

    def __post_init__(self) -> None:
        if self.valid_until is not None and self.valid_until <= self.valid_from:
            raise InvalidValidityWindowError()

    def is_open_ended(self) -> bool:
        return self.valid_until is None

    def covers(self, moment: datetime) -> bool:
        if moment < self.valid_from:
            return False
        return self.valid_until is None or moment < self.valid_until
