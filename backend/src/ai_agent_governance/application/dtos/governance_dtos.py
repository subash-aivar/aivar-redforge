from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class EnvelopeDTO:
    envelope_id: str
    tenant_id: str
    ai_system_asset_id: str
    state: str
    envelope_version: int
    action_categories: list[str] = field(default_factory=list)
    requires_human_approval_for: list[str] = field(default_factory=list)
    approved_by: str | None = None


@dataclass(frozen=True, slots=True)
class DeviationDTO:
    deviation_id: str
    tenant_id: str
    ai_system_asset_id: str
    deviation_type: str
    severity: str
    review_state: str
    envelope_version: int
    review_notes: str = ""


@dataclass(frozen=True, slots=True)
class ReportActionResultDTO:
    status: str  # compliant | deviation | duplicate
    deviation: DeviationDTO | None = None


@dataclass(frozen=True, slots=True)
class AdvisoryDTO:
    envelope_id: str
    deviation_type: str
    confirmed_benign_count: int
    recommendation: str
