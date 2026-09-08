from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "attack_pattern_intel"

_INFRA_IMPORT = re.compile(
    r"^\s*(from|import)\s+(fastapi|sqlalchemy|asyncpg|alembic|redis|celery|kafka)\b", re.M
)
_FORBIDDEN_THREAT_INTEL_IMPORT = re.compile(
    r"^\s*(from|import)\s+redforge\.domain\.threat_intel\b", re.M
)
_FORBIDDEN_IOC_INTEL_IMPORT = re.compile(r"^\s*(from|import)\s+ioc_intelligence\b", re.M)
_FORBIDDEN_THREAT_ACTOR_INTEL_IMPORT = re.compile(r"^\s*(from|import)\s+threat_actor_intel\b", re.M)
_FORBIDDEN_THREAT_HUNT_IMPORT = re.compile(r"^\s*(from|import)\s+threat_hunt\b", re.M)
_FORBIDDEN_SECURITY_GRAPH_IMPORT = re.compile(
    r"^\s*(from|import)\s+redforge\.domain\.security_graph\b", re.M
)


def test_domain_layer_exists() -> None:
    assert (ROOT / "domain").is_dir()


def test_no_infrastructure_imports_in_domain_layer() -> None:
    for path in (ROOT / "domain").rglob("*.py"):
        text = path.read_text()
        if _INFRA_IMPORT.search(text):
            raise AssertionError(f"{path} imports infrastructure from the domain layer")


def test_no_legacy_threat_intel_domain_import_anywhere() -> None:
    """attack_pattern_intel never imports `redforge.domain.threat_intel`'s
    domain classes — the ACL-over-legacy-identity architecture decision
    (M51.3 Phase B1): identity is validated via `IMitreTechniqueIdentityPort`
    only, never a direct import of the canonical aggregate."""
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


def test_application_layer_exists() -> None:
    assert (ROOT / "application").is_dir()


def test_infrastructure_layer_exists() -> None:
    assert (ROOT / "infrastructure").is_dir()


def test_api_layer_exists() -> None:
    assert (ROOT / "api").is_dir()
