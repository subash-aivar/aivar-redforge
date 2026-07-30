"""Closed enums for the risk_engine bounded context (M48B). Vocabulary
only — no scoring computation from any other bounded context is ever
duplicated here; these enums only categorize already-computed signals
and this context's own composite-scoring/lifecycle vocabulary."""

from __future__ import annotations

from enum import StrEnum


class RiskDimension(StrEnum):
    """The fixed set of risk dimensions a composite score can be
    composed from. Each dimension corresponds to a category of
    already-computed signal contributed by another bounded context (or
    an internal operational concern) — never recomputed here."""

    VULNERABILITY = "vulnerability"
    CLOUD = "cloud"
    AI = "ai"
    DETECTION = "detection"
    IDENTITY = "identity"
    CREDENTIAL = "credential"
    EXPOSURE = "exposure"
    COMPLIANCE = "compliance"
    ASSET_CRITICALITY = "asset_criticality"
    OPERATIONAL = "operational"


class RiskTrendDirection(StrEnum):
    """The direction a subject's composite risk score is heading,
    as determined by `RiskTrendAnalysisService`'s heuristic."""

    INCREASING = "increasing"
    DECREASING = "decreasing"
    STABLE = "stable"
    VOLATILE = "volatile"


class RiskProfileStatus(StrEnum):
    """The lifecycle status of an `EnterpriseRiskProfile`:
    `OPEN → ACKNOWLEDGED → (MITIGATED | ACCEPTED) → CLOSED`, with
    `CLOSED` reachable directly from any non-terminal state."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    MITIGATED = "mitigated"
    ACCEPTED = "accepted"
    CLOSED = "closed"


class RiskSignalType(StrEnum):
    """Categorizes the *shape* of a raw signal referenced by a
    `RiskSignalReference` — never its source bounded context. A small,
    deliberately generic vocabulary so this context never needs to
    know the internal taxonomy of the context that produced the
    signal."""

    SEVERITY_RATING = "severity_rating"
    """A qualitative-to-numeric severity rating (e.g. a CVSS-shaped
    score) produced by the source context."""

    PROBABILITY_SCORE = "probability_score"
    """A 0-1 probability/likelihood estimate (e.g. exploit
    probability) produced by the source context."""

    COMPOSITE_SCORE = "composite_score"
    """An already-aggregated composite score the source context
    computed internally (e.g. an AI posture score)."""

    POLICY_VIOLATION = "policy_violation"
    """A signal representing the degree of a policy/compliance
    violation."""

    ANOMALY_SCORE = "anomaly_score"
    """A behavioral/detection anomaly score."""


class RiskScale(StrEnum):
    """The native scale a `RiskSignalReference.raw_value` was reported
    on by its source context — the input `RiskNormalizationService`
    converts from."""

    CVSS_0_10 = "cvss_0_10"
    """Native range 0.0-10.0 (already risk_engine's target scale)."""

    PROBABILITY_0_1 = "probability_0_1"
    """Native range 0.0-1.0 (a probability/likelihood fraction)."""

    PERCENTAGE_0_100 = "percentage_0_100"
    """Native range 0.0-100.0 (a percentage)."""

    CUSTOM_WEIGHTED = "custom_weighted"
    """No fixed native range — the source context's own weighted
    formula. The caller must pre-normalize to 0-10 before referencing
    it; `RiskNormalizationService` only validates it is already in
    range for this scale."""
