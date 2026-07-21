"""ACL-translated reference value objects — M34-owned; no upstream types."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class EscalatedFindingRef:
    finding_id: str
    severity: str
    asset_ref: str
    rule_id: str
    detected_at: datetime
    escalated_by: str


@dataclass(frozen=True, slots=True)
class InvestigationRef:
    investigation_id: str
    concluded_at: datetime | None
    conclusion: str


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    evidence_chain_id: str
    engagement_ref: str
    sealed_at: datetime | None


@dataclass(frozen=True, slots=True)
class ExposureScopeRef:
    asset_ref_id: str
    composite_score: float
    assessed_at: datetime


@dataclass(frozen=True, slots=True)
class EradicationEvidenceRef:
    evidence_id: str
    description: str
