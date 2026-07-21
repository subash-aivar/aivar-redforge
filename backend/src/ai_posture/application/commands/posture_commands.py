"""Application commands for Phase 1 + Phase 2."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class RegisterAISystemAssetCommand:
    tenant_id: UUID
    asset_ref_id: UUID
    discovery_source: str
    data_sensitivity: str = "Internal"
    as_shadow: bool = False
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ClassifyAISystemAssetCommand:
    tenant_id: UUID
    asset_id: UUID
    ai_system_kind: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AssignAssetOwnerCommand:
    tenant_id: UUID
    asset_id: UUID
    owner_id: str
    owner_display_name: str = ""
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ApproveAISystemAssetRegistrationCommand:
    tenant_id: UUID
    asset_id: UUID
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DeprecateAISystemAssetCommand:
    tenant_id: UUID
    asset_id: UUID
    reason: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DecommissionAISystemAssetCommand:
    tenant_id: UUID
    asset_id: UUID
    reason: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RaiseShadowAIAlertCommand:
    tenant_id: UUID
    cloud_account: str
    resource_identifier: str
    service_type: str
    region: str
    discovery_source: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class TriageShadowAIAlertCommand:
    tenant_id: UUID
    alert_id: UUID
    triaged_by: str
    notes: str = ""
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ConfirmShadowAIAlertCommand:
    tenant_id: UUID
    alert_id: UUID
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DismissShadowAIAlertFalsePositiveCommand:
    tenant_id: UUID
    alert_id: UUID
    reason: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ResolveShadowAIAlertCommand:
    tenant_id: UUID
    alert_id: UUID
    resolution_action: str
    linked_asset_id: UUID | None = None
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class BulkTriageShadowAIAlertsCommand:
    tenant_id: UUID
    triaged_by: str
    discovery_source: str | None = None
    cloud_account: str | None = None
    service_type: str | None = None
    notes: str = ""
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class BulkResolveShadowAIAlertsCommand:
    tenant_id: UUID
    alert_ids: tuple[UUID, ...]
    resolution_action: str
    confirm_as: str  # ConfirmedShadowAI | ConfirmedFalsePositive
    false_positive_reason: str = ""
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SetDiscoveryOnlyModeCommand:
    tenant_id: UUID
    enabled: bool
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CreateThreatProfileCommand:
    tenant_id: UUID
    asset_id: UUID
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AssessThreatProfileCommand:
    tenant_id: UUID
    asset_id: UUID
    evidence_refs: list[str] = field(default_factory=list)
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ComputeRiskScoreCommand:
    tenant_id: UUID
    asset_id: UUID
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RunStalenessSweepCommand:
    tenant_id: UUID
    threat_threshold_days: int = 90
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EvaluateComplianceMappingCommand:
    tenant_id: UUID
    asset_id: UUID
    framework_id: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RecordComplianceAttestationCommand:
    tenant_id: UUID
    mapping_id: UUID
    attestor_id: str
    satisfied: bool = True
    notes: str = ""
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RebuildProjectionsCommand:
    tenant_id: UUID
    actor_roles: tuple[str, ...] = ()
