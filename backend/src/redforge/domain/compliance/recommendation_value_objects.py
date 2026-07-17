"""M24 Phase 3 — Evidence Recommendation value objects.

Recommendations never certify compliance and never embed owned
Finding / ThreatIntel / Investigation aggregates — reference IDs only.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime  # noqa: TC003
from enum import StrEnum, unique


@unique
class RecommendationStatus(StrEnum):
    """Lifecycle for an EvidenceRecommendation.

    recommended → accepted → linked
    recommended → rejected
    accepted → rejected (withdraw before link)
    """

    RECOMMENDED = "recommended"
    ACCEPTED = "accepted"
    LINKED = "linked"
    REJECTED = "rejected"


@unique
class EvidenceSourceKind(StrEnum):
    """Origin of a referenced evidence candidate (read-only cross-context)."""

    VALIDATION_EVIDENCE = "validation_evidence"
    SECURITY_FINDING = "security_finding"
    INVESTIGATION_EVIDENCE = "investigation_evidence"
    THREAT_INTELLIGENCE = "threat_intelligence"
    CLOUD_SCAN = "cloud_scan"
    CONFIRMED_CONTROL_EVIDENCE = "confirmed_control_evidence"


class RecommendationConfidenceCode:
    """Known confidence bands — stored as VARCHAR for forward compatibility."""

    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"

    KNOWN: frozenset[str] = frozenset(
        {VERY_LOW, LOW, MEDIUM, HIGH, VERY_HIGH}
    )

    ORDER: tuple[str, ...] = (
        VERY_LOW,
        LOW,
        MEDIUM,
        HIGH,
        VERY_HIGH,
    )


@dataclass(frozen=True, slots=True)
class RecommendationConfidence:
    """Extensible confidence label. Unknown future values are preserved."""

    value: str

    def __post_init__(self) -> None:
        cleaned = self.value.strip().lower()
        if not cleaned:
            raise ValueError("RecommendationConfidence value must be non-empty")
        if len(cleaned) > 32:
            raise ValueError("RecommendationConfidence value exceeds 32 characters")
        if cleaned != self.value:
            object.__setattr__(self, "value", cleaned)

    @classmethod
    def parse(cls, raw: str) -> RecommendationConfidence:
        return cls(value=raw)

    @classmethod
    def from_score(cls, score: float) -> RecommendationConfidence:
        """Map a normalized 0.0-1.0 score to a known band (configurable thresholds)."""
        if score < 0.0 or score > 1.0:
            raise ValueError(f"score must be in [0,1], got {score}")
        if score < 0.2:
            return cls(value=RecommendationConfidenceCode.VERY_LOW)
        if score < 0.4:
            return cls(value=RecommendationConfidenceCode.LOW)
        if score < 0.6:
            return cls(value=RecommendationConfidenceCode.MEDIUM)
        if score < 0.8:
            return cls(value=RecommendationConfidenceCode.HIGH)
        return cls(value=RecommendationConfidenceCode.VERY_HIGH)

    @property
    def is_known(self) -> bool:
        return self.value in RecommendationConfidenceCode.KNOWN

    def rank_index(self) -> int:
        try:
            return RecommendationConfidenceCode.ORDER.index(self.value)
        except ValueError:
            return -1


@dataclass(frozen=True, slots=True)
class EvidenceReference:
    """Immutable cross-context evidence pointer (ID only)."""

    source_kind: EvidenceSourceKind
    source_entity_id: str

    def __post_init__(self) -> None:
        eid = self.source_entity_id.strip()
        if not eid:
            raise ValueError("EvidenceReference.source_entity_id must be non-empty")
        if len(eid) > 64:
            raise ValueError("EvidenceReference.source_entity_id exceeds 64 characters")
        if eid != self.source_entity_id:
            object.__setattr__(self, "source_entity_id", eid)

    def dedup_token(self) -> str:
        return f"{self.source_kind.value}:{self.source_entity_id}"


@dataclass(frozen=True, slots=True)
class EvidenceCandidate:
    """Scored candidate produced by a read-only source adapter."""

    reference: EvidenceReference
    raw_score: float
    rationale: str
    signals: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not (0.0 <= self.raw_score <= 1.0):
            raise ValueError(f"raw_score must be in [0,1], got {self.raw_score}")
        if len(self.rationale) > 2000:
            raise ValueError("EvidenceCandidate.rationale exceeds 2000 characters")


@dataclass(frozen=True, slots=True)
class RecommendationDecision:
    """Human decision recorded on a recommendation."""

    decided_by: str
    decided_at: datetime
    rationale: str = ""

    def __post_init__(self) -> None:
        if not self.decided_by.strip():
            raise ValueError("RecommendationDecision.decided_by is required")
        if len(self.rationale) > 2000:
            raise ValueError("RecommendationDecision.rationale exceeds 2000 characters")


@dataclass(frozen=True, slots=True)
class ConfidenceScoringWeights:
    """Configurable weights for ConfidenceScoringService (not controller logic)."""

    source_weight: float = 0.45
    signal_bonus: float = 0.15
    mapping_hint_boost: float = 0.25
    recency_boost: float = 0.15

    def __post_init__(self) -> None:
        total = (
            self.source_weight
            + self.signal_bonus
            + self.mapping_hint_boost
            + self.recency_boost
        )
        if abs(total - 1.0) > 1e-6:
            raise ValueError(
                f"ConfidenceScoringWeights must sum to 1.0, got {total}"
            )


@dataclass(frozen=True, slots=True)
class RecommendationPolicy:
    """Policy gates for recommendation generation (never auto-link / auto-certify)."""

    minimum_confidence_to_recommend: RecommendationConfidence = RecommendationConfidence(
        value=RecommendationConfidenceCode.LOW
    )
    max_recommendations_per_assessment: int = 25
    allow_auto_accept: bool = False  # permanently False in Phase 3 — human only

    def __post_init__(self) -> None:
        if self.allow_auto_accept:
            raise ValueError(
                "RecommendationPolicy.allow_auto_accept must be False — "
                "recommendations never bypass human approval"
            )
        if self.max_recommendations_per_assessment < 1:
            raise ValueError("max_recommendations_per_assessment must be ≥ 1")
