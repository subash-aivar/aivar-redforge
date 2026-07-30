"""Domain events emitted by the `Asset` aggregate (M49A)."""

from __future__ import annotations

from dataclasses import dataclass

from attack_surface_management.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class AssetDiscovered(BaseDomainEvent):
    asset_type: str = ""
    primary_identifier: str = ""


@dataclass(frozen=True, slots=True)
class AssetPortDiscovered(BaseDomainEvent):
    port_number: int = 0
    protocol: str = ""


@dataclass(frozen=True, slots=True)
class AssetPortClosed(BaseDomainEvent):
    port_number: int = 0
    protocol: str = ""


@dataclass(frozen=True, slots=True)
class AssetCertificateAdded(BaseDomainEvent):
    common_name: str = ""
    serial_number: str = ""


@dataclass(frozen=True, slots=True)
class AssetCertificateRevoked(BaseDomainEvent):
    serial_number: str = ""


@dataclass(frozen=True, slots=True)
class AssetDnsRecordAdded(BaseDomainEvent):
    record_type: str = ""
    name: str = ""


@dataclass(frozen=True, slots=True)
class AssetDnsRecordRemoved(BaseDomainEvent):
    record_type: str = ""
    name: str = ""


@dataclass(frozen=True, slots=True)
class AssetTechnologyFingerprintAdded(BaseDomainEvent):
    technology_name: str = ""


@dataclass(frozen=True, slots=True)
class AssetExposureStateChanged(BaseDomainEvent):
    from_state: str = ""
    to_state: str = ""


@dataclass(frozen=True, slots=True)
class AssetCriticalityChanged(BaseDomainEvent):
    from_criticality: str = ""
    to_criticality: str = ""


@dataclass(frozen=True, slots=True)
class AssetReclassified(BaseDomainEvent):
    from_classification: str = ""
    to_classification: str = ""


@dataclass(frozen=True, slots=True)
class AssetOwnershipAssigned(BaseDomainEvent):
    owning_team: str = ""


@dataclass(frozen=True, slots=True)
class AssetLifecycleTransitioned(BaseDomainEvent):
    from_state: str = ""
    to_state: str = ""
