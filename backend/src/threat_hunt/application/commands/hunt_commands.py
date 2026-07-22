from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True, slots=True)
class GenerateThreatHuntCandidate:
    tenant_id: UUID
    anomaly_signal_ids: tuple[str, ...]
    technique_ids: tuple[str, ...]
    detection_logic_draft: str
    confidence_score: float
    roles: tuple[str, ...]
    detection_rule_format: str = "sigma"


@dataclass(frozen=True, slots=True)
class PromoteThreatHuntCandidate:
    tenant_id: UUID
    candidate_id: UUID
    promoted_by: str
    promoted_rule_version_id: UUID
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RejectThreatHuntCandidate:
    tenant_id: UUID
    candidate_id: UUID
    rejected_by: str
    rejection_reason: str
    roles: tuple[str, ...]
