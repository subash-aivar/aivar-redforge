"""ValidityWindow — generalizes `redforge.domain.threat_intel.
fusion_value_objects.TemporalValidity`'s exact shape for ioc_intelligence
(M51.2 Phase A)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class ValidityWindow:
    valid_from: datetime
    valid_until: datetime | None

    def is_valid_at(self, when: datetime) -> bool:
        if when < self.valid_from:
            return False
        if self.valid_until is None:
            return True
        return when <= self.valid_until
