"""Closed enums for ioc_intelligence (M51.2 Phase A / Phase A.1 R2).

`IocType` is the neutral shared-kernel `redforge.shared.ioc_vocabulary.
IndicatorType` (IP/DOMAIN/URL/HASH) — the same type object
`redforge.domain.threat_intel` uses, imported from the shared kernel
(matching the `TenantId`/`EntityId` precedent, ADR-0005) rather than
duplicated. This removes the M51.2 Phase A.1 ownership-reconciliation
finding R2: two independently-defined, identically-valued enums risked
silent drift. `ioc_intelligence` still does not import
`redforge.domain.threat_intel` directly — both contexts depend on the
same neutral primitive, neither depends on the other.
"""

from __future__ import annotations

from enum import StrEnum, unique

from redforge.shared.ioc_vocabulary import IndicatorType as IocType

__all__ = ["EpistemicState", "IocLifecycle", "IocType", "SourceConfidence"]


@unique
class IocLifecycle(StrEnum):
    """Operational relevance of one IOC — generalizes `redforge.domain.
    threat_intel.fusion_value_objects.IndicatorLifecycle`'s exact
    4-state shape (same values, own type per the established
    per-context-confidence/lifecycle-type precedent). See
    `IocLifecyclePolicy` for the enforced transition table."""

    ACTIVE = "active"
    SUPERSEDED = "superseded"
    EXPIRED = "expired"
    REVOKED = "revoked"


@unique
class EpistemicState(StrEnum):
    """How strongly RedForge trusts this claim — ADR-M51.2-01's Claim
    Hierarchy, distinct from `IocLifecycle` (operational relevance).
    Not a strict linear pipeline: see `EpistemicStatePolicy` for the
    real (non-linear, re-enterable-Disputed) transition table."""

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
class SourceConfidence(StrEnum):
    """Per-source trust judgment (ADR-M51.2-01 §Confidence: source
    confidence is never conflated with attribution or aggregated
    confidence). Own type, deliberately not `redforge.domain.
    threat_intel.fusion_value_objects.FusionConfidence` — that module's
    own docstring explains why sharing a confidence type across bounded
    contexts silently couples their independent recalibration; the same
    reasoning applies here."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"
