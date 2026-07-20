"""Stub threat-intel ACL for Phase 7 — returns 0 (no TI correlation yet)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redforge.domain.cloud_security.cloud_asset import CloudAsset


class ThreatIntelRiskACL:
    """Phase 7 stub: threat intel dimension is always 0.0."""

    async def threat_intel_score_for_asset(self, asset: CloudAsset) -> float:
        _ = asset
        return 0.0
