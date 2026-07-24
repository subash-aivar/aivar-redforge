"""BaselineFindingRecord — the read-only projection of a
`BaselineFinding` returned by the application layer (M45F)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from cloud_security.domain.value_objects.enums import (
        CloudSeverity,
        FindingCategory,
        FindingStatus,
    )


@dataclass(frozen=True, slots=True)
class BaselineFindingRecord:
    finding_id: str
    asset_id: str
    severity: CloudSeverity
    category: FindingCategory
    rule_id: str
    rule_name: str
    description: str
    recommendation: str
    evidence_reference: str
    status: FindingStatus
    detected_at: datetime
