from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "intelligence_relationships"

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
_FORBIDDEN_THREAT_HUNT_IMPORT = re.compile(r"^\s*(from|import)\s+threat_hunt\b", re.M)
_FORBIDDEN_SECURITY_GRAPH_IMPORT = re.compile(
    r"^\s*(from|import)\s+redforge\.domain\.security_graph\b", re.M
)
_GRAPH_DB_IMPORT = re.compile(r"^\s*(from|import)\s+(neo4j|networkx|igraph)\b", re.M)


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
    """IOC identity is reachable only through `IIocIdentityPort` and its
    read-only Core-SELECT adapter — never `ioc_intelligence`'s own
    modules."""
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


def test_no_graph_database_dependency_anywhere() -> None:
    """Relationships are stored in PostgreSQL only — no graph database
    and no in-process graph library (M51.4 Phase C1 decision)."""
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        if _GRAPH_DB_IMPORT.search(text):
            raise AssertionError(f"{path} imports a graph database/library — forbidden")


def test_application_layer_exists() -> None:
    assert (ROOT / "application").is_dir()


def test_infrastructure_layer_exists() -> None:
    assert (ROOT / "infrastructure").is_dir()


def test_api_layer_exists() -> None:
    assert (ROOT / "api").is_dir()
