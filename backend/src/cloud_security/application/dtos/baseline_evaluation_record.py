"""BaselineEvaluationRecord — the read-only projection of a
`CloudSecurityEvaluation` returned by the application layer (M45F).
Never mutated; rebuilt fresh from the aggregate each time."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from cloud_security.application.dtos.baseline_finding_record import BaselineFindingRecord
    from cloud_security.domain.value_objects.enums import EvaluationStatus


@dataclass(frozen=True, slots=True)
class BaselineEvaluationRecord:
    evaluation_id: str
    tenant_id: str
    account_id: str
    provider_id: str
    status: EvaluationStatus
    started_at: datetime
    evaluated_asset_count: int
    finding_count: int
    failed_count: int
    findings: tuple[BaselineFindingRecord, ...] = field(default_factory=tuple)
    completed_at: datetime | None = None
    failure_reason: str | None = None
