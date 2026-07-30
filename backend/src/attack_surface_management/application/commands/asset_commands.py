"""Immutable CQRS command objects for `Asset` lifecycle (M49B).

Each command carries only primitives/value-objects the M49A domain
already defines — no command duplicates domain validation or
computation; every command is handled by `AssetApplicationService`
which delegates straight to `AssetFactory`/domain aggregate
methods/domain services."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from attack_surface_management.domain.value_objects.domain_name import DomainName, Subdomain
    from attack_surface_management.domain.value_objects.enums import (
        AssetClassification,
        AssetLifecycleState,
        AssetType,
        CertificateStatus,
        Criticality,
        DiscoverySource,
        DnsRecordType,
        PortProtocol,
    )
    from attack_surface_management.domain.value_objects.identifiers import (
        AssetId,
        CertificateId,
        DnsRecordId,
        PortId,
        TenantId,
    )
    from attack_surface_management.domain.value_objects.ip_address import IPAddress
    from attack_surface_management.domain.value_objects.service_banner import ServiceBanner


@dataclass(frozen=True, slots=True)
class RegisterAssetCommand:
    tenant_id: TenantId
    asset_type: AssetType
    domain_name: DomainName | None = None
    subdomain: Subdomain | None = None
    ip_address: IPAddress | None = None
    discovery_source: DiscoverySource | None = None
    asset_id: AssetId | None = None


@dataclass(frozen=True, slots=True)
class RecordOpenPortCommand:
    tenant_id: TenantId
    asset_id: AssetId
    port_number: int
    protocol: PortProtocol
    service: ServiceBanner | None = None
    port_id: PortId | None = None


@dataclass(frozen=True, slots=True)
class ClosePortCommand:
    tenant_id: TenantId
    asset_id: AssetId
    port_id: PortId


@dataclass(frozen=True, slots=True)
class AttachCertificateCommand:
    tenant_id: TenantId
    asset_id: AssetId
    common_name: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    status: CertificateStatus
    certificate_id: CertificateId | None = None


@dataclass(frozen=True, slots=True)
class RevokeCertificateCommand:
    tenant_id: TenantId
    asset_id: AssetId
    certificate_id: CertificateId


@dataclass(frozen=True, slots=True)
class AddDnsRecordCommand:
    tenant_id: TenantId
    asset_id: AssetId
    record_type: DnsRecordType
    name: str
    value: str
    ttl_seconds: int
    record_id: DnsRecordId | None = None


@dataclass(frozen=True, slots=True)
class RemoveDnsRecordCommand:
    tenant_id: TenantId
    asset_id: AssetId
    record_id: DnsRecordId


@dataclass(frozen=True, slots=True)
class AddTechnologyFingerprintCommand:
    tenant_id: TenantId
    asset_id: AssetId
    name: str
    version: str | None
    confidence: float


@dataclass(frozen=True, slots=True)
class EvaluateExposureCommand:
    """Recomputes exposure state via
    `ExposureEvaluationService`/`ExposureClassificationPolicy` and, if
    it changed, applies it via `Asset.update_exposure_state`."""

    tenant_id: TenantId
    asset_id: AssetId


@dataclass(frozen=True, slots=True)
class RecomputeCriticalityScoreCommand:
    """Recomputes the derived `CriticalityScore` via
    `CriticalityScoringService` from the asset's current
    business-assigned `Criticality` tier, observed `ExposureState`, and
    certificate-expiry risk. This is a pure read/derived computation —
    `Asset` has no persisted numeric-score field to mutate, so no
    aggregate state changes and nothing is saved."""

    tenant_id: TenantId
    asset_id: AssetId


@dataclass(frozen=True, slots=True)
class SetCriticalityCommand:
    tenant_id: TenantId
    asset_id: AssetId
    criticality: Criticality


@dataclass(frozen=True, slots=True)
class ReclassifyAssetCommand:
    tenant_id: TenantId
    asset_id: AssetId
    classification: AssetClassification


@dataclass(frozen=True, slots=True)
class UpdateOwnershipCommand:
    tenant_id: TenantId
    asset_id: AssetId
    owning_team: str
    contact: str | None = None


@dataclass(frozen=True, slots=True)
class TransitionAssetLifecycleCommand:
    tenant_id: TenantId
    asset_id: AssetId
    new_state: AssetLifecycleState


@dataclass(frozen=True, slots=True)
class DecommissionAssetCommand:
    tenant_id: TenantId
    asset_id: AssetId
