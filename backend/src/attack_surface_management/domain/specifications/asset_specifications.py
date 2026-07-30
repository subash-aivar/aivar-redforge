"""Simple predicate specifications for attack_surface_management (M49A).

Implemented as lightweight frozen dataclasses with an
`is_satisfied_by(...)` method, consistent with `risk_engine`'s
Specification-pattern precedent (this codebase has no other
pre-existing Specification implementation to mirror instead)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from attack_surface_management.domain.value_objects.enums import ExposureState, PortState

if TYPE_CHECKING:
    from attack_surface_management.domain.aggregates.asset import Asset


@dataclass(frozen=True, slots=True)
class IsExposedHighRiskSpecification:
    def is_satisfied_by(self, asset: Asset) -> bool:
        return asset.exposure_state == ExposureState.EXPOSED_HIGH_RISK


@dataclass(frozen=True, slots=True)
class IsStaleAssetSpecification:
    max_age: timedelta

    def is_satisfied_by(self, asset: Asset, now: datetime) -> bool:
        return (now - asset.updated_at) > self.max_age


@dataclass(frozen=True, slots=True)
class HasOpenHighRiskPortSpecification:
    def is_satisfied_by(self, asset: Asset) -> bool:
        return any(port.state == PortState.OPEN and port.is_high_risk for port in asset.ports)


@dataclass(frozen=True, slots=True)
class HasExpiredCertificateSpecification:
    def is_satisfied_by(self, asset: Asset, now: datetime) -> bool:
        return any(cert.is_expired(now) for cert in asset.certificates)


@dataclass(frozen=True, slots=True)
class IsUnownedSpecification:
    def is_satisfied_by(self, asset: Asset) -> bool:
        return asset.ownership is None
