from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "infrastructure_intel"

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
_FORBIDDEN_THREAT_HUNT_IMPORT = re.compile(r"^\s*(from|import)\s+threat_hunt\b", re.M)
_FORBIDDEN_SECURITY_GRAPH_IMPORT = re.compile(
    r"^\s*(from|import)\s+redforge\.domain\.security_graph\b", re.M
)
_FORBIDDEN_ASM_IMPORT = re.compile(r"^\s*(from|import)\s+attack_surface_management\b", re.M)
_FORBIDDEN_CLOUD_SECURITY_IMPORT = re.compile(
    r"^\s*(from|import)\s+(cloud_security|redforge\.domain\.cloud_security)\b", re.M
)
_FORBIDDEN_INVENTORY_IMPORT = re.compile(r"^\s*(from|import)\s+redforge\.domain\.inventory\b", re.M)


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
    """`ioc_intelligence` owns IP/DOMAIN/URL/HASH as ATOMIC INDICATOR
    OBSERVATIONS. This context owns the hosting/ownership footprint
    ENTITY behind adversary infrastructure. The two are linked
    externally via `intelligence_relationships`' `IOC_TO_INFRASTRUCTURE`
    type — never by importing each other's domain classes."""
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
    for path in _all_files():
        if _FORBIDDEN_CAMPAIGN_INTEL_IMPORT.search(path.read_text()):
            raise AssertionError(f"{path} imports campaign_intel directly")


def test_no_tool_intel_import_anywhere() -> None:
    """tool_intel is the structural template for this context, not a
    dependency of it — every value object is defined locally."""
    for path in _all_files():
        if _FORBIDDEN_TOOL_INTEL_IMPORT.search(path.read_text()):
            raise AssertionError(f"{path} imports tool_intel directly")


def test_no_intelligence_relationships_import_anywhere() -> None:
    """Relationships are expressed by CALLING `intelligence_relationships`
    externally (its `INFRASTRUCTURE` entity type references this
    aggregate by opaque `entity_id` — see `IOC_TO_INFRASTRUCTURE` and
    `INFRASTRUCTURE_TO_CAMPAIGN`) — this context never imports its
    domain classes, and never duplicates its capability with a
    relationship model of its own."""
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


# ── Guards against the unrelated infra-flavoured contexts ────────────────


def test_no_attack_surface_management_import_anywhere() -> None:
    """`attack_surface_management` models RedForge's OWN discovered/
    scanned attack-surface assets (its `ip_address`/`domain_name`/
    `cidr_block` VOs are things RedForge monitors ABOUT ITSELF) — a
    completely different concept from ADVERSARY hosting infrastructure.
    This context defines its own value objects locally instead."""
    for path in _all_files():
        if _FORBIDDEN_ASM_IMPORT.search(path.read_text()):
            raise AssertionError(f"{path} imports attack_surface_management directly")


def test_no_cloud_security_import_anywhere() -> None:
    """`cloud_security` / `redforge.domain.cloud_security` model
    RedForge's OWN cloud account registrations. This context's
    `CloudProvider` enum is defined LOCALLY on purpose — sharing it
    would couple two unrelated contexts' independent evolution."""
    for path in _all_files():
        if _FORBIDDEN_CLOUD_SECURITY_IMPORT.search(path.read_text()):
            raise AssertionError(f"{path} imports a cloud_security context directly")


def test_no_inventory_import_anywhere() -> None:
    """`redforge.domain.inventory` is the AI asset inventory — unrelated
    to adversary hosting footprints."""
    for path in _all_files():
        if _FORBIDDEN_INVENTORY_IMPORT.search(path.read_text()):
            raise AssertionError(f"{path} imports redforge.domain.inventory directly")


# ── Deliberate non-duplication ───────────────────────────────────────────


def test_no_relationship_model_defined_in_this_context() -> None:
    """The deliberate non-duplication decision, enforced:
    infrastructure_intel owns no relationship aggregate, VO, port or
    table."""
    for path in _all_files():
        text = path.read_text()
        assert "class RelationshipMetadata" not in text, f"{path} defines a relationship VO"
        assert "infrastructure_intel_relationships" not in text, (
            f"{path} defines a relationship table"
        )


def test_lifecycle_status_and_identity_are_dedicated_slots_on_the_aggregate() -> None:
    from infrastructure_intel.domain.aggregates.infrastructure import Infrastructure

    assert "lifecycle_status" in Infrastructure.__slots__
    assert "normalized_identifier" in Infrastructure.__slots__
    assert "infrastructure_type" in Infrastructure.__slots__


def test_the_aggregate_documents_the_ioc_versus_infrastructure_split() -> None:
    """The entity-vs-observation distinction is a load-bearing design
    decision — it must be stated in the aggregate's module docstring so
    the next reader cannot merge the two by accident."""
    from infrastructure_intel.domain.aggregates import infrastructure

    doc = (infrastructure.__doc__ or "").lower()
    assert "ioc_intelligence" in doc
    assert "intelligence_relationships" in doc
    assert "ioc_to_infrastructure" in doc


def test_application_layer_exists() -> None:
    assert (ROOT / "application").is_dir()


def test_infrastructure_layer_exists() -> None:
    assert (ROOT / "infrastructure").is_dir()


def test_api_layer_exists() -> None:
    assert (ROOT / "api").is_dir()
