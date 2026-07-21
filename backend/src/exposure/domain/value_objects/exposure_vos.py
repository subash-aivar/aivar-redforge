"""Value objects for exposure aggregates."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from uuid import UUID

from exposure.domain.value_objects.enums import RiskAmplifierType, SignalDomain


@dataclass(frozen=True, slots=True)
class AssetRef:
    asset_ref_id: UUID

    def __str__(self) -> str:
        return str(self.asset_ref_id)


@dataclass(frozen=True, slots=True)
class SignalSourceRef:
    """Opaque external signal id (VulnerabilityInstanceId or CloudMisconfigId)."""

    value: str

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class ExposureLevel:
    """Base exposure in [0.0, 10.0] (CVSS or misconfig severity)."""

    value: float

    def __post_init__(self) -> None:
        if not 0.0 <= self.value <= 10.0:
            raise ValueError(f"ExposureLevel must be in [0, 10], got {self.value}")


@dataclass(frozen=True, slots=True)
class ScoreInputVersion:
    """References AmplifierWeightConfiguration.version at compute time."""

    value: int

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class AmplifierWeight:
    amplifier_type: RiskAmplifierType
    weight: Decimal


@dataclass(frozen=True, slots=True)
class ExposureIdentityKey:
    """Canonical ExposureRecord identity (ADR-M32-001)."""

    tenant_id: UUID
    asset_ref_id: UUID
    signal_domain: SignalDomain
    signal_source_ref: str
