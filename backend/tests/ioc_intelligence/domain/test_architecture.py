from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "ioc_intelligence"

_INFRA_IMPORT = re.compile(
    r"^\s*(from|import)\s+(fastapi|sqlalchemy|asyncpg|alembic|redis|celery|kafka)\b", re.M
)
_FORBIDDEN_CONTEXT_IMPORT = re.compile(
    r"^\s*(from|import)\s+redforge\.domain\.threat_intel\b", re.M
)
_FORBIDDEN_SIBLING_CONTEXT_IMPORT = re.compile(r"^\s*(from|import)\s+threat_actor_intel\b", re.M)


def test_domain_layer_exists() -> None:
    assert (ROOT / "domain").is_dir()


def test_no_infrastructure_imports_in_domain_layer() -> None:
    for path in (ROOT / "domain").rglob("*.py"):
        text = path.read_text()
        if _INFRA_IMPORT.search(text):
            raise AssertionError(f"{path} imports infrastructure from the domain layer")


def test_no_legacy_threat_intel_domain_import_in_domain_layer() -> None:
    for path in (ROOT / "domain").rglob("*.py"):
        text = path.read_text()
        if _FORBIDDEN_CONTEXT_IMPORT.search(text):
            raise AssertionError(f"{path} imports redforge.domain.threat_intel directly")


def test_no_sibling_bounded_context_import_in_domain_layer() -> None:
    for path in (ROOT / "domain").rglob("*.py"):
        text = path.read_text()
        if _FORBIDDEN_SIBLING_CONTEXT_IMPORT.search(text):
            raise AssertionError(f"{path} imports threat_actor_intel directly")


def test_api_layer_exists() -> None:
    """M51.2 Phase A4 adds the API layer."""
    assert (ROOT / "api").is_dir()
