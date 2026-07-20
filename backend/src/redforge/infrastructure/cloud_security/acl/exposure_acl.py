"""Derive exposure signals from CloudAsset.NormalizedConfig (read-only)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redforge.domain.cloud_security.cloud_asset import CloudAsset
    from redforge.domain.cloud_security.value_objects import NormalizedConfig


class ExposureSignalACL:
    """Maps NormalizedConfig → exposure fields for RiskSignalSnapshot."""

    @staticmethod
    def from_config(config: NormalizedConfig) -> dict[str, object]:
        exposure = config.network_exposure.value
        public = bool(config.public_endpoints) or exposure in {"PUBLIC", "INTERNET"}
        enc = True if config.encryption_at_rest is None else bool(config.encryption_at_rest)
        return {
            "network_exposure": exposure,
            "encryption_at_rest": enc,
            "public_accessibility": public,
            "internet_exposure": exposure in {"PUBLIC", "INTERNET"},
        }

    def from_asset(self, asset: CloudAsset) -> dict[str, object]:
        return self.from_config(asset.normalized_config)
