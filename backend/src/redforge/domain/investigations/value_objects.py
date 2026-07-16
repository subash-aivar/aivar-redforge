"""Value objects for the Investigation bounded context — M21.

Enums are all StrEnum + @unique following the exact pattern from M19/M20.
No mysterious 0-100 scores: confidence is an explainable four-level enum.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum, unique


@unique
class InvestigationStatus(StrEnum):
    """Explicit lifecycle states for an investigation case.

    Transitions are enforced by the domain aggregate, not by the DB or API.
    OPEN → ACKNOWLEDGED → INVESTIGATING → RESOLVED
    RESOLVED → OPEN (reopen on recurrence within window)
    """

    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"


# Terminal statuses: new evidence after resolution triggers recurrence logic.
TERMINAL_STATUSES: frozenset[InvestigationStatus] = frozenset({
    InvestigationStatus.RESOLVED,
})

# Non-terminal statuses used in the partial unique index.
ACTIVE_STATUSES: frozenset[InvestigationStatus] = frozenset({
    InvestigationStatus.OPEN,
    InvestigationStatus.ACKNOWLEDGED,
    InvestigationStatus.INVESTIGATING,
})

# String tuple for SQL WHERE clause
ACTIVE_STATUS_STRINGS: tuple[str, ...] = tuple(s.value for s in ACTIVE_STATUSES)


@unique
class InvestigationSeverity(StrEnum):
    """Case severity — deterministic, based on source evidence only.

    Severity only increases as new evidence is attached. A manual
    downgrade by an analyst requires explicit acknowledgement and audit.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# Monotonic severity ordering: higher index = more severe.
_SEVERITY_ORDER: dict[InvestigationSeverity, int] = {
    InvestigationSeverity.LOW: 0,
    InvestigationSeverity.MEDIUM: 1,
    InvestigationSeverity.HIGH: 2,
    InvestigationSeverity.CRITICAL: 3,
}


def max_severity(
    a: InvestigationSeverity, b: InvestigationSeverity
) -> InvestigationSeverity:
    """Return the more severe of two severity levels."""
    return a if _SEVERITY_ORDER[a] >= _SEVERITY_ORDER[b] else b


@unique
class CorrelationConfidence(StrEnum):
    """Explainable four-level confidence -- never a mysterious 0-100 score.

    Confidence increases only from deterministic, documented criteria.
    Every confidence level maps to exactly one set of observable conditions.
    """

    LOW = "LOW"        # Single domain, single entity, single event
    MEDIUM = "MEDIUM"  # Temporal recurrence OR same entity, different event types
    HIGH = "HIGH"      # Two independent domains, same normalized entity
    VERY_HIGH = "VERY_HIGH"  # 3+ domains, OR 2 domains + threat-intel corroboration


_CONFIDENCE_ORDER: dict[CorrelationConfidence, int] = {
    CorrelationConfidence.LOW: 0,
    CorrelationConfidence.MEDIUM: 1,
    CorrelationConfidence.HIGH: 2,
    CorrelationConfidence.VERY_HIGH: 3,
}


def max_confidence(
    a: CorrelationConfidence, b: CorrelationConfidence
) -> CorrelationConfidence:
    """Return the higher of two confidence levels."""
    return a if _CONFIDENCE_ORDER[a] >= _CONFIDENCE_ORDER[b] else b


@unique
class SourceDomain(StrEnum):
    """Source domains that M21 can correlate evidence from.

    Only domains with a real canonical evidence producer in this repository.
    """

    BEHAVIOR = "behavior"      # M20 BehaviorDetection
    DDOS = "ddos"              # M19 DDoSIncident
    THREAT_INTEL = "threat_intel"  # M18 ThreatIntel canonical matches


@unique
class NormalizedEntityType(StrEnum):
    """Typed normalized entity categories for correlation.

    Only types where deterministic identity resolution exists in this repo.
    """

    IP_ADDRESS = "IP_ADDRESS"   # Canonical IP (IPv4 or IPv6, normalized)
    RESOURCE = "RESOURCE"       # DDoS protected resource (stable DB ID)
    DETECTION = "DETECTION"     # Behavior detection entity (stable correlation_key)


@unique
class RelationshipType(StrEnum):
    """How a piece of evidence is related to the investigation."""

    DIRECT = "DIRECT"       # Evidence directly involves a case entity
    CORRELATED = "CORRELATED"  # Evidence correlated via shared entity
    ENRICHED = "ENRICHED"   # Threat-intel enrichment of an existing entity


@unique
class EvidenceObservability(StrEnum):
    """Epistemic status of an entity/relationship in the investigation.

    Never render INFERRED as observed fact in the UI.
    """

    OBSERVED = "OBSERVED"       # Directly recorded from sensor/source
    INFERRED = "INFERRED"       # Derived from multiple observed facts
    SUSPECTED = "SUSPECTED"     # Heuristic, not yet observed or confirmed


@unique
class CorrelationRuleId(StrEnum):
    """Closed set of deterministic correlation rules.

    Every rule has a stable ID, a fixed version, and a documented
    rationale. Rule IDs appear in correlation_reason for explainability.
    """

    SAME_ENTITY_CROSS_DOMAIN = "R01_SAME_ENTITY_CROSS_DOMAIN"
    RELATED_ENTITIES = "R02_RELATED_ENTITIES"
    RECURRENT_SIGNAL = "R03_RECURRENT_SIGNAL"
    MULTI_DOMAIN_ESCALATION = "R04_MULTI_DOMAIN_ESCALATION"
    THREAT_INTEL_ENRICHMENT = "R05_THREAT_INTEL_ENRICHMENT"
    DDOS_PLUS_BEHAVIOR = "R06_DDOS_PLUS_BEHAVIOR"
    NETWORK_SECURITY_PLUS_BEHAVIOR = "R07_NETWORK_SECURITY_PLUS_BEHAVIOR"


@unique
class CaseEventType(StrEnum):
    """Timeline event types for an investigation case."""

    CASE_OPENED = "CASE_OPENED"
    EVIDENCE_ATTACHED = "EVIDENCE_ATTACHED"
    ENTITY_LINKED = "ENTITY_LINKED"
    SEVERITY_ESCALATED = "SEVERITY_ESCALATED"
    CONFIDENCE_INCREASED = "CONFIDENCE_INCREASED"
    CASE_ACKNOWLEDGED = "CASE_ACKNOWLEDGED"
    INVESTIGATION_STARTED = "INVESTIGATION_STARTED"
    CASE_RESOLVED = "CASE_RESOLVED"
    CASE_REOPENED = "CASE_REOPENED"
    DOMAIN_JOINED = "DOMAIN_JOINED"


@unique
class ResolutionReason(StrEnum):
    """Bounded resolution reasons — analyst must pick one."""

    TRUE_POSITIVE_REMEDIATED = "TRUE_POSITIVE_REMEDIATED"
    TRUE_POSITIVE_ACCEPTED_RISK = "TRUE_POSITIVE_ACCEPTED_RISK"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    BENIGN_ACTIVITY = "BENIGN_ACTIVITY"
    DUPLICATE = "DUPLICATE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    EXPIRED = "EXPIRED"


@dataclass(frozen=True, slots=True)
class NormalizedEntity:
    """A typed, normalized entity identity for correlation.

    Only created when identity can be canonically resolved.
    Never created from display names or unverified strings.
    """

    entity_type: NormalizedEntityType
    entity_id: str  # canonical form (e.g., normalized IP string, stable DB ID)

    def __str__(self) -> str:
        return f"{self.entity_type.value}:{self.entity_id}"


def normalize_ip(raw_ip: str) -> NormalizedEntity | None:
    """Normalize an IP address to canonical form.

    Returns None if the string is not a valid IP address.
    IPv4: dotted decimal (e.g., "192.168.1.1")
    IPv6: compressed canonical lower-case (e.g., "::1")
    """
    try:
        addr = ipaddress.ip_address(raw_ip.strip())
        return NormalizedEntity(
            entity_type=NormalizedEntityType.IP_ADDRESS,
            entity_id=str(addr).lower(),
        )
    except ValueError:
        return None


def normalize_resource_id(resource_id: str) -> NormalizedEntity | None:
    """Normalize a DDoS protected resource ID (stable ULID from DB)."""
    if not resource_id or len(resource_id) not in (26, 36):
        return None
    return NormalizedEntity(
        entity_type=NormalizedEntityType.RESOURCE,
        entity_id=resource_id.strip(),
    )


def normalize_detection_entity(correlation_key: str) -> NormalizedEntity | None:
    """Normalize a behavior detection entity via its correlation key."""
    if not correlation_key:
        return None
    return NormalizedEntity(
        entity_type=NormalizedEntityType.DETECTION,
        entity_id=correlation_key.strip(),
    )


@dataclass(frozen=True, slots=True)
class CorrelationDecision:
    """Explainable correlation decision.

    Every decision answers: what matched, why, and at what confidence.
    Never opaque — every field has a deterministic origin.
    """

    rule_id: CorrelationRuleId
    rule_version: int  # bump when rule semantics change
    shared_entities: tuple[NormalizedEntity, ...]
    source_domains: tuple[SourceDomain, ...]
    correlation_window_seconds: int
    confidence: CorrelationConfidence
    severity: InvestigationSeverity
    reason: str  # human-readable explanation, deterministically generated
    observability: EvidenceObservability


@dataclass(frozen=True, slots=True)
class EvidenceCandidate:
    """A source-domain signal ready for correlation evaluation.

    Typed value object — no untyped dict soup.
    """

    organization_id: str
    source_domain: SourceDomain
    source_entity_type: str         # domain-specific entity type label
    source_entity_id: str           # stable DB ID from source domain
    event_type: str                 # e.g., "DETECTION_OPENED", "INCIDENT_OPENED"
    severity: InvestigationSeverity
    observed_at: datetime
    normalized_entities: tuple[NormalizedEntity, ...]  # correlation anchors
    evidence_snapshot: dict[str, object]  # bounded metadata for case
    dedup_key: str  # idempotency: same evidence never creates duplicate membership


def build_correlation_key(
    org_id: str,
    rule_id: CorrelationRuleId,
    rule_version: int,
    entity_ids: list[str],
) -> str:
    """Deterministic correlation key for case deduplication.

    Title/summary NEVER part of the key.
    Entity list is sorted for stability regardless of discovery order.
    """
    sorted_entities = ":".join(sorted(set(entity_ids)))
    return f"{org_id}|{rule_id.value}|v{rule_version}|{sorted_entities}"


@dataclass(frozen=True, slots=True)
class InvestigationTimestamps:
    """All timestamps for an investigation case."""

    opened_at: datetime
    first_observed_at: datetime
    last_observed_at: datetime
    acknowledged_at: datetime | None = None
    investigating_at: datetime | None = None
    resolved_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))


# Default correlation window for temporal proximity checks.
DEFAULT_CORRELATION_WINDOW_SECONDS = 4 * 3600  # 4 hours

# If new evidence arrives within this window after resolution, reopen.
REOPEN_WINDOW_SECONDS = 24 * 3600  # 24 hours
