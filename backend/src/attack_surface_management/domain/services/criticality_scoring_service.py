"""CriticalityScoringService — orchestrates `CriticalityScoringPolicy`
against an `Asset`'s current criticality/exposure state, and additionally
factors in certificate-expiry risk, which the policy alone (criticality
x exposure) does not model: an asset with an expired/soon-to-expire
public certificate should score as more urgent regardless of its base
criticality tier."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from attack_surface_management.domain.policies.criticality_scoring_policy import (
    CriticalityScoringPolicy,
)
from attack_surface_management.domain.value_objects.criticality_score import CriticalityScore

if TYPE_CHECKING:
    from attack_surface_management.domain.aggregates.asset import Asset

_CERTIFICATE_EXPIRY_WARNING_DAYS = 30
_EXPIRY_PENALTY = 15


class CriticalityScoringService:
    @staticmethod
    def score(asset: Asset, now: datetime) -> CriticalityScore:
        base = CriticalityScoringPolicy.score(asset.criticality, asset.exposure_state)
        if CriticalityScoringService._has_certificate_expiry_risk(asset, now):
            return CriticalityScore(min(100, base.value + _EXPIRY_PENALTY))
        return base

    @staticmethod
    def _has_certificate_expiry_risk(asset: Asset, now: datetime) -> bool:
        return any(
            cert.is_expired(now) or cert.expires_within(now, _CERTIFICATE_EXPIRY_WARNING_DAYS)
            for cert in asset.certificates
        )
