from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, Field


class SuppressExposureRequest(BaseModel):
    justification: str = Field(min_length=1)
    suppressed_by: str = Field(min_length=1)


class ConfigureWeightsRequest(BaseModel):
    weights: dict[str, float]
    change_rationale: str = Field(min_length=1)
    changed_by: str = Field(min_length=1)


class IngestVulnerabilityRequest(BaseModel):
    event_id: str
    vulnerability_instance_id: str
    asset_ref_id: UUID
    cvss_base: float = Field(ge=0.0, le=10.0)
    is_kev: bool = False
    technique_refs: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    asset_classes: list[str] = Field(default_factory=list)


class ResolveVulnerabilityRequest(BaseModel):
    event_id: str
    vulnerability_instance_id: str


class KevStatusChangedRequest(BaseModel):
    event_id: str
    vulnerability_instance_id: str
    is_kev: bool


class IngestCloudSecurityRequest(BaseModel):
    event_id: str
    misconfiguration_id: str
    asset_ref_id: UUID
    severity_score: float = Field(ge=0.0, le=10.0)
    has_internet_exposure: bool = False


class RemediateCloudSecurityRequest(BaseModel):
    event_id: str
    misconfiguration_id: str


class IngestDetectionGapRequest(BaseModel):
    event_id: str
    gap_id: str
    technique_ref: str
    asset_ref_id: UUID
    is_open: bool = True


class IngestAISystemRiskRequest(BaseModel):
    event_id: str
    asset_ref_id: UUID
    exposure_level: float = Field(ge=0.0, le=10.0)
    amplifier_weight: float = Field(ge=0.0)
    profile_ref: str


class ThreatActorTargetingUpdatedRequest(BaseModel):
    event_id: str
    threat_actor_ref: str
    targeted_cve_ids: list[str] = Field(default_factory=list)
    targeted_asset_classes: list[str] = Field(default_factory=list)
    targeted_techniques: list[str] = Field(default_factory=list)
    targeted_iocs: list[str] = Field(default_factory=list)
    targeting_confidence: str = "Medium"


class IngestConfirmedExploitationRequest(BaseModel):
    event_id: str
    asset_ref_id: UUID
    evidence_ref: str
    cve_id: str | None = None


class QueryExposureScopeRequest(BaseModel):
    max_assets: int = Field(default=100, ge=1, le=1000)
    min_exposure_score: float | None = None
    amplifier_filter: list[str] = Field(default_factory=list)
    asset_kind_filter: list[str] = Field(default_factory=list)
    include_stale_scores: bool = False
