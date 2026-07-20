"""Build ResourceSnapshot evaluation inputs from CloudAsset aggregates."""

from __future__ import annotations

from datetime import UTC, datetime

from redforge.domain.cloud_security.cloud_asset import CloudAsset, compute_config_hash
from redforge.domain.cloud_security.cspm.value_objects import ResourceSnapshot


class ResourceSnapshotBuilder:
    """Maps CloudAsset + provider_type into a provider-agnostic ResourceSnapshot."""

    def build(self, asset: CloudAsset, *, provider_type: str) -> ResourceSnapshot:
        config = asset.normalized_config.to_dict()
        config_hash = asset.posture_state.config_hash or compute_config_hash(
            asset.normalized_config
        )
        return ResourceSnapshot(
            cloud_asset_id=str(asset.id),
            organization_id=str(asset.organization_id),
            cloud_account_id=str(asset.cloud_account_id),
            asset_type=asset.asset_type.value,
            provider_type=provider_type.upper(),
            provider_id=asset.provider_id,
            display_name=asset.display_name,
            region_code=asset.region.region_code,
            tags=dict(asset.tags),
            normalized_config=dict(config),
            config_hash=config_hash,
            captured_at=datetime.now(UTC),
        )
