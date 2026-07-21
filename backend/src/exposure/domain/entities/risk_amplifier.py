"""RiskAmplifier entity — owned by ExposureRecord aggregate."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from exposure.domain.value_objects.enums import RiskAmplifierType
    from exposure.domain.value_objects.identifiers import RiskAmplifierId


@dataclass(slots=True)
class RiskAmplifier:
    amplifier_id: RiskAmplifierId
    type: RiskAmplifierType
    source_ref: str
    first_observed_at: datetime
    last_confirmed_at: datetime
    applied_weight: Decimal
    is_active: bool

    def confirm(self, at: datetime) -> None:
        self.last_confirmed_at = at
        self.is_active = True

    def deactivate(self) -> None:
        self.is_active = False
