"""Closed enums for intelligence_relationships (M51.4 Phase C1)."""

from __future__ import annotations

from enum import StrEnum, unique

__all__ = [
    "EntityType",
    "EpistemicState",
    "RelationshipConfidence",
    "RelationshipDirection",
    "RelationshipLifecycleStatus",
    "RelationshipType",
]


@unique
class EntityType(StrEnum):
    """The closed vocabulary of endpoint kinds a relationship may join.

    Every value is an *opaque reference kind* only — this context owns
    none of these entities. Three of them (IOC, THREAT_ACTOR,
    ATTACK_PATTERN) have RedForge-native owning bounded contexts whose
    existence is checked through read-only ACL ports; the rest
    (MALWARE, TOOL, CAMPAIGN, INFRASTRUCTURE, THREAT_REPORT) have no
    owning module at all and are unverifiable opaque strings by
    design.
    """

    IOC = "ioc"
    MALWARE = "malware"
    TOOL = "tool"
    THREAT_ACTOR = "threat_actor"
    CAMPAIGN = "campaign"
    ATTACK_PATTERN = "attack_pattern"
    INFRASTRUCTURE = "infrastructure"
    THREAT_REPORT = "threat_report"


@unique
class RelationshipType(StrEnum):
    """The closed vocabulary of relationship kinds. Each value implies
    an exact (source entity_type, target entity_type) pairing —
    enforced by `RelationshipTypeCompatibilityPolicy`, which is the
    single source of truth for that mapping."""

    IOC_TO_MALWARE = "ioc_to_malware"
    IOC_TO_TOOL = "ioc_to_tool"
    IOC_TO_INFRASTRUCTURE = "ioc_to_infrastructure"
    IOC_TO_THREAT_ACTOR = "ioc_to_threat_actor"
    IOC_TO_CAMPAIGN = "ioc_to_campaign"
    IOC_TO_ATTACK_PATTERN = "ioc_to_attack_pattern"
    MALWARE_TO_CAMPAIGN = "malware_to_campaign"
    CAMPAIGN_TO_THREAT_ACTOR = "campaign_to_threat_actor"
    TOOL_TO_THREAT_ACTOR = "tool_to_threat_actor"
    INFRASTRUCTURE_TO_CAMPAIGN = "infrastructure_to_campaign"

    # M51.9 Phase H1 — closes the THREAT_REPORT vocabulary gap flagged
    # during threat_report_intel's certification: THREAT_REPORT existed
    # in `EntityType` but had no relationship type admitting it.
    THREAT_REPORT_TO_THREAT_ACTOR = "threat_report_to_threat_actor"
    THREAT_REPORT_TO_CAMPAIGN = "threat_report_to_campaign"
    THREAT_REPORT_TO_MALWARE = "threat_report_to_malware"
    THREAT_REPORT_TO_TOOL = "threat_report_to_tool"
    THREAT_REPORT_TO_INFRASTRUCTURE = "threat_report_to_infrastructure"
    THREAT_REPORT_TO_ATTACK_PATTERN = "threat_report_to_attack_pattern"
    THREAT_REPORT_TO_IOC = "threat_report_to_ioc"


@unique
class RelationshipDirection(StrEnum):
    """Whether the asserted claim reads only source -> target, or holds
    symmetrically in both directions."""

    UNIDIRECTIONAL = "unidirectional"
    BIDIRECTIONAL = "bidirectional"


@unique
class RelationshipConfidence(StrEnum):
    """Per-relationship trust judgment. Own type, deliberately not
    `ioc_intelligence`'s `SourceConfidence` — sharing a confidence type
    across bounded contexts silently couples their independent
    recalibration."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


@unique
class EpistemicState(StrEnum):
    """How strongly RedForge trusts this relationship claim — the same
    9-value Claim Hierarchy vocabulary `ioc_intelligence` uses,
    replicated locally (never imported) per the bounded-context
    independence rule. Distinct from `RelationshipLifecycleStatus`
    (operational relevance). See `EpistemicTransitionPolicy` for the
    enforced transition table."""

    OBSERVATION = "observation"
    EVIDENCE = "evidence"
    HYPOTHESIS = "hypothesis"
    CORROBORATED = "corroborated"
    VALIDATED = "validated"
    DISPUTED = "disputed"
    REFUTED = "refuted"
    HISTORICAL = "historical"
    RETIRED = "retired"


@unique
class RelationshipLifecycleStatus(StrEnum):
    """RedForge-native operational lifecycle of a relationship — the
    same 4-value shape (and transition table) `attack_pattern_intel`'s
    `TechniqueLifecycleStatus` uses, defined locally. See
    `LifecycleTransitionPolicy`."""

    ACTIVE = "active"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"
    SUPERSEDED = "superseded"
