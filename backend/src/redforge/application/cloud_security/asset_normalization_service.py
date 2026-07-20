"""Thin application wrapper around infrastructure asset normalizers."""

from __future__ import annotations

from redforge.domain.cloud_security.ports import RawAsset
from redforge.infrastructure.cloud_security.normalizers import (
    NormalizedAssetDraft,
    normalize_raw_asset,
)


class AssetNormalizationService:
    """Normalizes RawAsset payloads into NormalizedAssetDraft records."""

    def normalize(self, raw: RawAsset) -> NormalizedAssetDraft:
        return normalize_raw_asset(raw)
