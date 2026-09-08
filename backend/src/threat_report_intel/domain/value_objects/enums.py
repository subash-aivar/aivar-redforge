"""Closed enums for threat_report_intel.

`ThreatReportLifecycleStatus` is RedForge's OWN record lifecycle (is
this intelligence RECORD still the one to trust?) — it says nothing
about whether the published report itself has been withdrawn by its
publisher.

Note what is deliberately NOT an enum here: `report_type`
("advisory" / "analysis" / "flash" / "bulletin" / ...) is free text,
non-empty-validated only. Report taxonomies are publisher-specific and
change constantly; a closed vocabulary would go stale the week it
shipped.
"""

from __future__ import annotations

from enum import StrEnum, unique

__all__ = [
    "ThreatReportConfidence",
    "ThreatReportLifecycleStatus",
    "ThreatReportSeverity",
    "TlpMarking",
]


@unique
class ThreatReportLifecycleStatus(StrEnum):
    """RedForge-native RECORD lifecycle for a `ThreatReport` intel
    record. See `LifecycleTransitionPolicy` for the enforced transition
    table."""

    ACTIVE = "active"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"
    SUPERSEDED = "superseded"


@unique
class ThreatReportSeverity(StrEnum):
    """How severe the threat DESCRIBED BY the report is, as asserted by
    the analyst recording it — not a RedForge finding severity."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@unique
class ThreatReportConfidence(StrEnum):
    """Analyst confidence in a claim made about this report."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


@unique
class TlpMarking(StrEnum):
    """Traffic Light Protocol handling marking carried by the report.

    Genuinely closed: TLP is a small, slow-moving, externally
    standardized vocabulary (TLP 2.0 plus the still-widespread
    TLP_GREEN/TLP_AMBER/TLP_RED legacy set), unlike `report_type`."""

    TLP_RED = "tlp_red"
    TLP_AMBER = "tlp_amber"
    TLP_AMBER_STRICT = "tlp_amber_strict"
    TLP_GREEN = "tlp_green"
    TLP_CLEAR = "tlp_clear"
