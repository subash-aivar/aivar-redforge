"""Closed enums for the siem_normalization bounded context (M37 §2.4)."""

from __future__ import annotations

from enum import StrEnum


class NormalizationFailureReason(StrEnum):
    """Why a source-specific event could not be mapped to the CEM.

    Failures are first-class, not silent drops (M37 §2.4) — every
    `NormalizationFailed` event carries one of these so `siem_analytics`
    can report normalization health.
    """

    SCHEMA_MISMATCH = "schema_mismatch"
    MALFORMED_PAYLOAD = "malformed_payload"
    UNSUPPORTED_SOURCE = "unsupported_source"
    MAPPING_ERROR = "mapping_error"


class NormalizationRole(StrEnum):
    """RBAC scopes for siem_normalization's application layer (M37 §16 —
    extends the existing platform RBAC, no parallel model)."""

    VIEWER = "siem_normalization:viewer"
    EXECUTOR = "siem_normalization:execute"
    ADMIN = "siem_normalization:admin"
