"""Value objects for Threat Fusion — M22 Phase 4.

Fusion consumes the normalized Phase 1 reference-data catalog as
populated by Phase 3's STIX/TAXII connector (and Phase 1 admin loads).
It does **not** invent IOCs from telemetry and does **not** re-implement
STIX parsing.

`FusionConfidence` is intentionally a separate type from M21's
`CorrelationConfidence` (Hardening Review Part 2): fusion calibrates
source-weight / corroboration quality; investigation correlation
calibrates cross-domain evidence strength. Shared string values must
not silently couple future recalibration of either domain.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import StrEnum, unique
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

from redforge.domain.threat_intel.fusion_exceptions import (
    InvalidFusionConfidenceError,
    InvalidFusionWeightError,
    InvalidIndicatorCanonicalKeyError,
)

_CANONICAL_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{1,31}:.{1,256}$")


@unique
class FusedIndicatorType(StrEnum):
    """Closed set of fused intelligence indicator kinds.

    Derived exclusively from Phase 3 STIX/TAXII → Phase 1 reference-data
    outputs (and STIX relationship endpoint prefixes for software /
    campaign / group / mitigation objects that Phase 1 records as raw
    `source_ref`/`target_ref` without full entity models).
    """

    TECHNIQUE = "technique"
    TACTIC = "tactic"
    VULNERABILITY = "vulnerability"
    SOFTWARE = "software"
    CAMPAIGN = "campaign"
    GROUP = "group"
    MITIGATION = "mitigation"


@unique
class IndicatorLifecycle(StrEnum):
    """Lifecycle of one fused indicator. Transitions are enforced by the
    aggregate, never by the API or ORM."""

    ACTIVE = "active"
    SUPERSEDED = "superseded"
    EXPIRED = "expired"
    REVOKED = "revoked"


ACTIVE_LIFECYCLES: frozenset[IndicatorLifecycle] = frozenset({
    IndicatorLifecycle.ACTIVE,
})


@unique
class FusionConfidence(StrEnum):
    """Explainable four-level fusion confidence — never a mysterious
    0-100 score. Distinct type from M21 `CorrelationConfidence`."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    VERY_HIGH = "VERY_HIGH"


_FUSION_CONFIDENCE_ORDER: dict[FusionConfidence, int] = {
    FusionConfidence.LOW: 0,
    FusionConfidence.MEDIUM: 1,
    FusionConfidence.HIGH: 2,
    FusionConfidence.VERY_HIGH: 3,
}


def fusion_confidence_rank(level: FusionConfidence) -> int:
    return _FUSION_CONFIDENCE_ORDER[level]


def min_fusion_confidence(a: FusionConfidence, b: FusionConfidence) -> FusionConfidence:
    """Weakest-link helper used by path confidence and risk floors."""
    return a if _FUSION_CONFIDENCE_ORDER[a] <= _FUSION_CONFIDENCE_ORDER[b] else b


def max_fusion_confidence(a: FusionConfidence, b: FusionConfidence) -> FusionConfidence:
    return a if _FUSION_CONFIDENCE_ORDER[a] >= _FUSION_CONFIDENCE_ORDER[b] else b


@unique
class AggregatedRiskState(StrEnum):
    """Explicit fusion outcome state (Hardening Review P0: all-sources-
    failed must not silently reuse stale evidence as current risk)."""

    COMPUTED = "computed"
    NO_EVIDENCE = "no_evidence"
    CONFLICT = "conflict"


@unique
class FusionConflictReason(StrEnum):
    WEIGHT_PREVAILED = "weight_prevailed"
    RECENCY_TIEBREAK = "recency_tiebreak"
    CORROBORATION_INSUFFICIENT = "corroboration_insufficient"


@dataclass(frozen=True, slots=True)
class FusionWeight:
    """Per-source trust weight used by `FusionConflictPolicy`.

    Belongs in policy/config (Hardening Review P2) — never owned by the
    fused indicator itself. Valid range: (0.0, 1.0].
    """

    source_system: str
    weight: float

    def __post_init__(self) -> None:
        if not self.source_system or not self.source_system.strip():
            raise InvalidFusionWeightError("source_system must be non-empty")
        if not (0.0 < self.weight <= 1.0):
            raise InvalidFusionWeightError(
                f"weight must be in (0.0, 1.0], got {self.weight!r}"
            )


@dataclass(frozen=True, slots=True)
class SourceAttribution:
    """One source's contribution to a fused indicator — provenance that
    travels with every fusion result."""

    source_system: str
    external_id: str
    content_hash: str | None
    observed_at: datetime
    weight_applied: float
    confidence: FusionConfidence
    feed_id: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RiskSourceBreakdown:
    """One row of the per-source breakdown inside `AggregatedRisk`."""

    source_system: str
    weight_applied: float
    confidence: FusionConfidence
    observed_at: datetime
    prevailed: bool
    conflict_reason: FusionConflictReason | None = None


@dataclass(frozen=True, slots=True)
class AggregatedRisk:
    """Cross-source fused risk signal with full provenance.

    Never a scalar from nowhere: either `COMPUTED`/`CONFLICT` with a
    non-empty breakdown, or an explicit `NO_EVIDENCE` sentinel.
    """

    state: AggregatedRiskState
    confidence: FusionConfidence | None
    sources: tuple[RiskSourceBreakdown, ...]
    computed_at: datetime
    winner_source_system: str | None = None

    def __post_init__(self) -> None:
        if self.state is AggregatedRiskState.NO_EVIDENCE:
            if self.confidence is not None or self.sources:
                raise InvalidFusionConfidenceError(
                    "NO_EVIDENCE AggregatedRisk must carry no confidence "
                    "and an empty source breakdown"
                )
            return
        if self.confidence is None:
            raise InvalidFusionConfidenceError(
                f"{self.state.value} AggregatedRisk requires a confidence level"
            )
        if not self.sources:
            raise InvalidFusionConfidenceError(
                f"{self.state.value} AggregatedRisk requires a non-empty "
                "per-source breakdown"
            )


@dataclass(frozen=True, slots=True)
class TemporalValidity:
    """Valid-from / valid-until window for a fused indicator."""

    valid_from: datetime
    valid_until: datetime | None

    def is_valid_at(self, when: datetime) -> bool:
        if when < self.valid_from:
            return False
        if self.valid_until is None:
            return True
        return when <= self.valid_until


@dataclass(frozen=True, slots=True)
class CanonicalIndicatorKey:
    """Deterministic deduplication key: `{type}:{normalized_value}`.

    Normalization is type-specific and applied before construction so
    two STIX-derived records of the same technique/CVE always collide
    on one fused indicator.
    """

    value: str

    def __post_init__(self) -> None:
        if not _CANONICAL_KEY_RE.match(self.value):
            raise InvalidIndicatorCanonicalKeyError(self.value)

    @classmethod
    def for_type(cls, indicator_type: FusedIndicatorType, raw_value: str) -> CanonicalIndicatorKey:
        normalized = _normalize_value(indicator_type, raw_value)
        return cls(f"{indicator_type.value}:{normalized}")

    @property
    def indicator_type(self) -> FusedIndicatorType:
        prefix, _sep, _rest = self.value.partition(":")
        return FusedIndicatorType(prefix)

    @property
    def raw_value(self) -> str:
        _prefix, _sep, rest = self.value.partition(":")
        return rest

    def content_fingerprint(self, *parts: str) -> str:
        """Stable SHA-256 fingerprint for change detection across feeds."""
        material = "|".join((self.value, *parts))
        return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _normalize_value(indicator_type: FusedIndicatorType, raw_value: str) -> str:
    value = raw_value.strip()
    if not value:
        raise InvalidIndicatorCanonicalKeyError(f"{indicator_type.value}:")
    if indicator_type is FusedIndicatorType.TECHNIQUE:
        return value.upper()
    if indicator_type is FusedIndicatorType.TACTIC:
        return value.upper()
    if indicator_type is FusedIndicatorType.VULNERABILITY:
        return value.upper()
    # STIX IDs / names for software/campaign/group/mitigation
    return value.lower()


# STIX type-prefix → fused indicator type for relationship endpoints
# that Phase 1 stores as raw refs without full entity models.
_STIX_PREFIX_TO_FUSED_TYPE: dict[str, FusedIndicatorType] = {
    "attack-pattern": FusedIndicatorType.TECHNIQUE,
    "x-mitre-tactic": FusedIndicatorType.TACTIC,
    "vulnerability": FusedIndicatorType.VULNERABILITY,
    "malware": FusedIndicatorType.SOFTWARE,
    "tool": FusedIndicatorType.SOFTWARE,
    "campaign": FusedIndicatorType.CAMPAIGN,
    "intrusion-set": FusedIndicatorType.GROUP,
    "threat-actor": FusedIndicatorType.GROUP,
    "course-of-action": FusedIndicatorType.MITIGATION,
}


def fused_type_for_stix_ref(stix_ref: str) -> FusedIndicatorType | None:
    """Map a STIX object id prefix to a fused indicator type, or None
    when the prefix is outside this phase's closed set."""
    prefix, sep, _rest = stix_ref.partition("--")
    if not sep:
        return None
    return _STIX_PREFIX_TO_FUSED_TYPE.get(prefix)
