"""Domain events for Threat Fusion — M22 Phase 4.

Hardening Review requires at least `IndicatorFused` so downstream
subscribers (audit, future investigation adapter) are not forced into
synchronous coupling with the fusion service.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class IndicatorFused:
    indicator_id: str
    canonical_key: str
    confidence: str
    source_count: int
    fused_at: datetime


@dataclass(frozen=True, slots=True)
class IndicatorLifecycleChanged:
    indicator_id: str
    canonical_key: str
    from_lifecycle: str
    to_lifecycle: str
    changed_at: datetime


FusionDomainEvent = IndicatorFused | IndicatorLifecycleChanged
