"""DTOs for ai_posture."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class AISystemAssetDTO:
    asset_id: str
    tenant_id: str
    asset_ref_id: str
    lifecycle_state: str
    registration_status: str
    ai_system_kind: str | None
    owner_id: str | None
    threat_profile_id: str | None
    risk_score_snapshot_id: str | None
    data_sensitivity: str


@dataclass(frozen=True, slots=True)
class ShadowAIAlertDTO:
    alert_id: str
    tenant_id: str
    state: str
    fingerprint_hash: str
    discovery_source: str
    cloud_account: str
    service_type: str
    resolution_action: str | None
    linked_asset_id: str | None


@dataclass(frozen=True, slots=True)
class AIThreatProfileDTO:
    profile_id: str
    tenant_id: str
    ai_system_asset_id: str
    ai_system_kind: str
    requires_reassessment: bool
    archived: bool
    max_exposure_level: str
    applicable_categories: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class AIRiskScoreSnapshotDTO:
    snapshot_id: str
    tenant_id: str
    ai_system_asset_id: str
    composite_score: float
    score_input_version: str
    is_stale: bool
    components: dict[str, float] = field(default_factory=dict)
    computed_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class BulkTriageResultDTO:
    triaged_count: int
    alert_ids: list[str]


@dataclass(frozen=True, slots=True)
class TriageBacklogAgeDTO:
    buckets: dict[str, int]
    open_total: int


@dataclass(frozen=True, slots=True)
class StalenessSweepResultDTO:
    profiles_flagged: int
    scores_recomputed: int
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AIComplianceMappingDTO:
    mapping_id: str
    tenant_id: str
    ai_system_asset_id: str
    framework_id: str
    control_id: str
    control_title: str
    control_status: str
    requires_human_attestation: bool
    evaluation_mode: str
    attestor_id: str | None
    attested_at: datetime | None
    recorded_at: datetime
