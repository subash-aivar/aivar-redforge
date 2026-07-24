from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from exposure.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class IngestVulnerabilitySignalCommand:
    tenant_id: TenantId
    event_id: str
    vulnerability_instance_id: str
    asset_ref_id: UUID
    cvss_base: float
    is_kev: bool
    technique_refs: tuple[str, ...]
    cve_ids: tuple[str, ...] = ()
    asset_classes: tuple[str, ...] = ()
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ResolveVulnerabilitySignalCommand:
    tenant_id: TenantId
    event_id: str
    vulnerability_instance_id: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class VulnerabilityKevStatusChangedCommand:
    tenant_id: TenantId
    event_id: str
    vulnerability_instance_id: str
    is_kev: bool
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SuppressExposureRecordCommand:
    tenant_id: TenantId
    record_id: UUID
    justification: str
    suppressed_by: str
    actor_roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ConfigureAmplifierWeightsCommand:
    tenant_id: TenantId
    weights: dict[str, float]
    change_rationale: str
    changed_by: str
    actor_roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class IngestCloudSecuritySignalCommand:
    tenant_id: TenantId
    event_id: str
    misconfiguration_id: str
    asset_ref_id: UUID
    severity_score: float
    has_internet_exposure: bool
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RemediateCloudSecuritySignalCommand:
    tenant_id: TenantId
    event_id: str
    misconfiguration_id: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class IngestDetectionGapSignalCommand:
    tenant_id: TenantId
    event_id: str
    gap_id: str
    technique_ref: str
    asset_ref_id: UUID
    is_open: bool
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class IngestAISystemRiskSignalCommand:
    tenant_id: TenantId
    event_id: str
    asset_ref_id: UUID
    exposure_level: float
    amplifier_weight: float
    profile_ref: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class FlushPendingRecomputationsCommand:
    tenant_id: TenantId
    actor_roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ThreatActorTargetingUpdatedCommand:
    tenant_id: TenantId
    event_id: str
    threat_actor_ref: str
    targeted_cve_ids: tuple[str, ...]
    targeted_asset_classes: tuple[str, ...]
    targeted_techniques: tuple[str, ...] = ()
    targeted_iocs: tuple[str, ...] = ()
    targeting_confidence: str = "Medium"
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class IngestConfirmedExploitationCommand:
    tenant_id: TenantId
    event_id: str
    asset_ref_id: UUID
    evidence_ref: str
    cve_id: str | None = None
    actor_roles: tuple[str, ...] = ()
