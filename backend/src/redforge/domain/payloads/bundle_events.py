"""Domain events for the PayloadBundle aggregate."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.domain.payloads.events import PayloadEvent
from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class PayloadBundleCreated(PayloadEvent):
    """A new payload bundle was generated for an attack plan."""

    bundle_id: str
    attack_plan_id: str
    variant_count: int


@dataclass(frozen=True, slots=True)
class PayloadBundleSuperseded(PayloadEvent):
    """A payload bundle was superseded by a newer bundle (a regeneration)."""

    bundle_id: str
    superseded_by: str


def _now() -> datetime:
    return utc_now()
