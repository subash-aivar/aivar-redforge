from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class BaseHuntEvent:
    event_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    tenant_id: str = ""
    aggregate_id: str = ""


@dataclass(frozen=True, slots=True, kw_only=True)
class ThreatHuntCandidateGenerated(BaseHuntEvent):
    candidate_id: str
    technique_coverage: tuple[str, ...]
    confidence_score: float


@dataclass(frozen=True, slots=True, kw_only=True)
class ThreatHuntCandidatePromoted(BaseHuntEvent):
    candidate_id: str
    promoted_rule_version_id: str
    promoted_by: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ThreatHuntCandidateRejected(BaseHuntEvent):
    candidate_id: str
    rejected_by: str
    rejection_reason: str
