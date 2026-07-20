"""Thin application wrapper around infrastructure IAM principal normalizers."""

from __future__ import annotations

from redforge.domain.cloud_security.ports import RawIAMPrincipal
from redforge.infrastructure.cloud_security.normalizers import (
    NormalizedIAMPrincipalDraft,
    normalize_raw_iam_principal,
)


class IdentityNormalizationService:
    """Normalizes RawIAMPrincipal payloads into NormalizedIAMPrincipalDraft records."""

    def normalize(self, raw: RawIAMPrincipal) -> NormalizedIAMPrincipalDraft:
        return normalize_raw_iam_principal(raw)
