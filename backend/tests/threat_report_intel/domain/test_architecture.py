from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "threat_report_intel"

_INFRA_IMPORT = re.compile(
    r"^\s*(from|import)\s+(fastapi|sqlalchemy|asyncpg|alembic|redis|celery|kafka)\b", re.M
)
_FORBIDDEN_THREAT_INTEL_IMPORT = re.compile(
    r"^\s*(from|import)\s+redforge\.domain\.threat_intel\b", re.M
)
_FORBIDDEN_IOC_INTEL_IMPORT = re.compile(r"^\s*(from|import)\s+ioc_intelligence\b", re.M)
_FORBIDDEN_THREAT_ACTOR_INTEL_IMPORT = re.compile(r"^\s*(from|import)\s+threat_actor_intel\b", re.M)
_FORBIDDEN_ATTACK_PATTERN_INTEL_IMPORT = re.compile(
    r"^\s*(from|import)\s+attack_pattern_intel\b", re.M
)
_FORBIDDEN_INTELLIGENCE_RELATIONSHIPS_IMPORT = re.compile(
    r"^\s*(from|import)\s+intelligence_relationships\b", re.M
)
_FORBIDDEN_MALWARE_INTEL_IMPORT = re.compile(r"^\s*(from|import)\s+malware_intel\b", re.M)
_FORBIDDEN_CAMPAIGN_INTEL_IMPORT = re.compile(r"^\s*(from|import)\s+campaign_intel\b", re.M)
_FORBIDDEN_TOOL_INTEL_IMPORT = re.compile(r"^\s*(from|import)\s+tool_intel\b", re.M)
_FORBIDDEN_INFRASTRUCTURE_INTEL_IMPORT = re.compile(
    r"^\s*(from|import)\s+infrastructure_intel\b", re.M
)
_FORBIDDEN_THREAT_HUNT_IMPORT = re.compile(r"^\s*(from|import)\s+threat_hunt\b", re.M)
_FORBIDDEN_SECURITY_GRAPH_IMPORT = re.compile(
    r"^\s*(from|import)\s+redforge\.domain\.security_graph\b", re.M
)
_FORBIDDEN_REPORTING_IMPORT = re.compile(
    r"^\s*(from|import)\s+(reporting|redforge\.domain\.reporting)\b", re.M
)
_FORBIDDEN_ANALYTICS_IMPORT = re.compile(
    r"^\s*(from|import)\s+(analytics|redforge\.domain\.analytics)\b", re.M
)
_FORBIDDEN_REGULATORY_IMPORT = re.compile(
    r"^\s*(from|import)\s+(regulatory_notification|redforge\.domain\.regulatory_notification)\b",
    re.M,
)


def _all_files() -> list[Path]:
    return list(ROOT.rglob("*.py"))


def test_domain_layer_exists() -> None:
    assert (ROOT / "domain").is_dir()


def test_no_infrastructure_imports_in_domain_layer() -> None:
    for path in (ROOT / "domain").rglob("*.py"):
        text = path.read_text()
        if _INFRA_IMPORT.search(text):
            raise AssertionError(f"{path} imports infrastructure from the domain layer")


def test_no_legacy_threat_intel_domain_import_anywhere() -> None:
    for path in _all_files():
        if _FORBIDDEN_THREAT_INTEL_IMPORT.search(path.read_text()):
            raise AssertionError(f"{path} imports redforge.domain.threat_intel directly")


def test_no_ioc_intelligence_import_anywhere() -> None:
    """`ioc_intelligence` owns atomic indicator observations. This
    context owns PUBLISHED REPORTS about threats. The two would be
    linked externally via `intelligence_relationships` — never by
    importing each other's domain classes."""
    for path in _all_files():
        if _FORBIDDEN_IOC_INTEL_IMPORT.search(path.read_text()):
            raise AssertionError(f"{path} imports ioc_intelligence directly")


def test_no_threat_actor_intel_import_anywhere() -> None:
    for path in _all_files():
        if _FORBIDDEN_THREAT_ACTOR_INTEL_IMPORT.search(path.read_text()):
            raise AssertionError(f"{path} imports threat_actor_intel directly")


def test_no_attack_pattern_intel_import_anywhere() -> None:
    for path in _all_files():
        if _FORBIDDEN_ATTACK_PATTERN_INTEL_IMPORT.search(path.read_text()):
            raise AssertionError(f"{path} imports attack_pattern_intel directly")


def test_no_malware_intel_import_anywhere() -> None:
    for path in _all_files():
        if _FORBIDDEN_MALWARE_INTEL_IMPORT.search(path.read_text()):
            raise AssertionError(f"{path} imports malware_intel directly")


def test_no_campaign_intel_import_anywhere() -> None:
    """`campaign_intel`'s `normalize_canonical_name` is the CONVENTION
    this context mirrors for `normalize_canonical_title` — mirrored by
    reimplementation locally, never by import."""
    for path in _all_files():
        if _FORBIDDEN_CAMPAIGN_INTEL_IMPORT.search(path.read_text()):
            raise AssertionError(f"{path} imports campaign_intel directly")


def test_no_tool_intel_import_anywhere() -> None:
    for path in _all_files():
        if _FORBIDDEN_TOOL_INTEL_IMPORT.search(path.read_text()):
            raise AssertionError(f"{path} imports tool_intel directly")


def test_no_infrastructure_intel_import_anywhere() -> None:
    """infrastructure_intel is the structural template for this context,
    not a dependency of it — every value object is defined locally."""
    for path in _all_files():
        if _FORBIDDEN_INFRASTRUCTURE_INTEL_IMPORT.search(path.read_text()):
            raise AssertionError(f"{path} imports infrastructure_intel directly")


def test_no_intelligence_relationships_import_anywhere() -> None:
    """Relationships are expressed by CALLING `intelligence_relationships`
    externally — this context never imports its domain classes, and never
    duplicates its capability with a relationship model of its own. That
    external call is fully possible today: see
    `test_the_aggregate_documents_relationship_support_via_intelligence_relationships`.
    """
    for path in _all_files():
        if _FORBIDDEN_INTELLIGENCE_RELATIONSHIPS_IMPORT.search(path.read_text()):
            raise AssertionError(f"{path} imports intelligence_relationships directly")


def test_no_threat_hunt_import_anywhere() -> None:
    for path in _all_files():
        if _FORBIDDEN_THREAT_HUNT_IMPORT.search(path.read_text()):
            raise AssertionError(f"{path} imports threat_hunt directly")


def test_no_security_graph_import_anywhere() -> None:
    for path in _all_files():
        if _FORBIDDEN_SECURITY_GRAPH_IMPORT.search(path.read_text()):
            raise AssertionError(f"{path} imports redforge.domain.security_graph directly")


# ── Guards against the unrelated report-flavoured contexts ───────────────


def test_no_reporting_import_anywhere() -> None:
    """`reporting` models RedForge's OWN generated reports about its own
    findings — a completely different concept from a third-party
    published threat-intelligence report."""
    for path in _all_files():
        if _FORBIDDEN_REPORTING_IMPORT.search(path.read_text()):
            raise AssertionError(f"{path} imports a reporting context directly")


def test_no_analytics_import_anywhere() -> None:
    for path in _all_files():
        if _FORBIDDEN_ANALYTICS_IMPORT.search(path.read_text()):
            raise AssertionError(f"{path} imports an analytics context directly")


def test_no_regulatory_notification_import_anywhere() -> None:
    """`regulatory_notification` is RedForge's OWN outbound regulatory
    filing surface — unrelated to catalogued threat publications."""
    for path in _all_files():
        if _FORBIDDEN_REGULATORY_IMPORT.search(path.read_text()):
            raise AssertionError(f"{path} imports regulatory_notification directly")


# ── Deliberate non-duplication ───────────────────────────────────────────


def test_no_relationship_model_defined_in_this_context() -> None:
    """The deliberate non-duplication decision, enforced:
    threat_report_intel owns no relationship aggregate, VO, port or
    table."""
    for path in _all_files():
        text = path.read_text()
        assert "class RelationshipMetadata" not in text, f"{path} defines a relationship VO"
        assert "threat_report_intel_relationships" not in text, (
            f"{path} defines a relationship table"
        )


def test_lifecycle_status_and_identity_are_dedicated_slots_on_the_aggregate() -> None:
    from threat_report_intel.domain.aggregates.threat_report import ThreatReport

    assert "lifecycle_status" in ThreatReport.__slots__
    assert "canonical_title" in ThreatReport.__slots__
    assert "title" in ThreatReport.__slots__


def test_the_two_summaries_are_distinct_slots_and_never_conflated() -> None:
    """`executive_summary` (leadership-level) and `technical_summary`
    (analyst-level) are two separate required fields by design."""
    from threat_report_intel.domain.aggregates.threat_report import ThreatReport

    assert "executive_summary" in ThreatReport.__slots__
    assert "technical_summary" in ThreatReport.__slots__


def test_the_aggregate_documents_relationship_support_via_intelligence_relationships() -> None:
    """The most important thing this context has to say about itself.

    `intelligence_relationships` defines `THREAT_REPORT` in its closed
    `EntityType` enum, and (as of M51.9 Phase H1) also defines seven
    `THREAT_REPORT_TO_*` `RelationshipType` values — so threat-report-to
    -anything links ARE expressible through the certified Relationship
    Engine today, by calling `intelligence_relationships` directly. This
    context still owns no relationship logic of its own: that capability
    lives, and remains canonical, exclusively in
    `intelligence_relationships` (building it here, or importing its
    domain classes, would duplicate a certified capability — see
    `test_no_intelligence_relationships_import_anywhere`). This test pins
    the aggregate's module docstring so this now-correct state cannot
    silently go stale again the way the old "gap" wording did."""
    from threat_report_intel.domain.aggregates import threat_report

    doc = (threat_report.__doc__ or "").lower()
    assert "intelligence_relationships" in doc
    assert "entitytype" in doc
    assert "threat_report" in doc
    assert "relationshiptype" in doc
    # It must say relationship support now exists, externally...
    assert "now available" in doc
    assert "threat_report_to_" in doc
    # ...that this context still owns no relationship logic of its own...
    assert "owns no relationship logic" in doc
    # ...and is invoked externally, not implemented here.
    assert "not through this context" in doc
    # ...while a ThreatReportId remains a ready-to-use opaque entity_id.
    assert "entity_id" in doc


def test_application_layer_exists() -> None:
    assert (ROOT / "application").is_dir()


def test_infrastructure_layer_exists() -> None:
    assert (ROOT / "infrastructure").is_dir()


def test_api_layer_exists() -> None:
    assert (ROOT / "api").is_dir()
