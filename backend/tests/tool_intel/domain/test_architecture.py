from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "tool_intel"

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
_FORBIDDEN_THREAT_HUNT_IMPORT = re.compile(r"^\s*(from|import)\s+threat_hunt\b", re.M)
_FORBIDDEN_SECURITY_GRAPH_IMPORT = re.compile(
    r"^\s*(from|import)\s+redforge\.domain\.security_graph\b", re.M
)
_FORBIDDEN_AGENTS_IMPORT = re.compile(r"^\s*(from|import)\s+redforge\.domain\.agents\b", re.M)


def test_domain_layer_exists() -> None:
    assert (ROOT / "domain").is_dir()


def test_no_infrastructure_imports_in_domain_layer() -> None:
    for path in (ROOT / "domain").rglob("*.py"):
        text = path.read_text()
        if _INFRA_IMPORT.search(text):
            raise AssertionError(f"{path} imports infrastructure from the domain layer")


def test_no_legacy_threat_intel_domain_import_anywhere() -> None:
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        if _FORBIDDEN_THREAT_INTEL_IMPORT.search(text):
            raise AssertionError(f"{path} imports redforge.domain.threat_intel directly")


def test_no_ioc_intelligence_import_anywhere() -> None:
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        if _FORBIDDEN_IOC_INTEL_IMPORT.search(text):
            raise AssertionError(f"{path} imports ioc_intelligence directly")


def test_no_threat_actor_intel_import_anywhere() -> None:
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        if _FORBIDDEN_THREAT_ACTOR_INTEL_IMPORT.search(text):
            raise AssertionError(f"{path} imports threat_actor_intel directly")


def test_no_attack_pattern_intel_import_anywhere() -> None:
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        if _FORBIDDEN_ATTACK_PATTERN_INTEL_IMPORT.search(text):
            raise AssertionError(f"{path} imports attack_pattern_intel directly")


def test_no_malware_intel_import_anywhere() -> None:
    """`ToolPlatform` carries the same eight values as `malware_intel`'s
    `MalwarePlatform` but is defined LOCALLY — sharing the enum across
    contexts would silently couple their independent evolution."""
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        if _FORBIDDEN_MALWARE_INTEL_IMPORT.search(text):
            raise AssertionError(f"{path} imports malware_intel directly")


def test_no_campaign_intel_import_anywhere() -> None:
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        if _FORBIDDEN_CAMPAIGN_INTEL_IMPORT.search(text):
            raise AssertionError(f"{path} imports campaign_intel directly")


def test_no_intelligence_relationships_import_anywhere() -> None:
    """Relationships are expressed by CALLING `intelligence_relationships`
    externally (its `TOOL` entity type references a Tool by opaque
    `entity_id` — see `TOOL_TO_THREAT_ACTOR` and `IOC_TO_TOOL`) — this
    context never imports its domain classes, and never duplicates its
    capability with a relationship model of its own."""
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        if _FORBIDDEN_INTELLIGENCE_RELATIONSHIPS_IMPORT.search(text):
            raise AssertionError(f"{path} imports intelligence_relationships directly")


def test_no_threat_hunt_import_anywhere() -> None:
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        if _FORBIDDEN_THREAT_HUNT_IMPORT.search(text):
            raise AssertionError(f"{path} imports threat_hunt directly")


def test_no_security_graph_import_anywhere() -> None:
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        if _FORBIDDEN_SECURITY_GRAPH_IMPORT.search(text):
            raise AssertionError(f"{path} imports redforge.domain.security_graph directly")


def test_no_agent_tool_calling_import_anywhere() -> None:
    """`redforge.domain.agents` defines `ToolSchema`/`ToolPermission`/
    `ToolInvocationRecord`, which model an LLM agent invoking a declared
    function — a completely different concept that merely shares the
    English word "tool". tool_intel never couples to it."""
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        if _FORBIDDEN_AGENTS_IMPORT.search(text):
            raise AssertionError(f"{path} imports the AI-agent tool-calling context directly")


def test_no_relationship_model_defined_in_this_context() -> None:
    """The deliberate non-duplication decision, enforced: tool_intel owns
    no relationship aggregate, VO, port or table."""
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        assert "class RelationshipMetadata" not in text, f"{path} defines a relationship VO"
        assert "tool_intel_relationships" not in text, f"{path} defines a relationship table"


def test_lifecycle_status_is_a_dedicated_slot_on_the_aggregate() -> None:
    from tool_intel.domain.aggregates.tool import Tool

    assert "lifecycle_status" in Tool.__slots__
    assert "canonical_name" in Tool.__slots__


def test_application_layer_exists() -> None:
    assert (ROOT / "application").is_dir()


def test_infrastructure_layer_exists() -> None:
    assert (ROOT / "infrastructure").is_dir()


def test_api_layer_exists() -> None:
    assert (ROOT / "api").is_dir()
