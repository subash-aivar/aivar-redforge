"""Cloud asset and IAM normalizers — Raw* → Normalized*Draft."""

from __future__ import annotations

from redforge.infrastructure.cloud_security.normalizers.iam_normalize import (
    normalize_raw_iam_principal,
)
from redforge.infrastructure.cloud_security.normalizers.iam_types import (
    NormalizedIAMPrincipalDraft,
)
from redforge.infrastructure.cloud_security.normalizers.normalize import normalize_raw_asset
from redforge.infrastructure.cloud_security.normalizers.types import NormalizedAssetDraft

__all__ = [
    "NormalizedAssetDraft",
    "NormalizedIAMPrincipalDraft",
    "normalize_raw_asset",
    "normalize_raw_iam_principal",
]
