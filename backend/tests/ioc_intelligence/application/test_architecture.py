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
_FORBIDDEN_APPLICATION_CONTEXT_IMPORT = re.compile(
    r"^\s*(from|import)\s+redforge\.application\.threat_intel\b", re.M
)
_FORBIDDEN_SIBLING_CONTEXT_IMPORT = re.compile(r"^\s*(from|import)\s+threat_actor_intel\b", re.M)


def test_application_layer_exists() -> None:
    assert (ROOT / "application").is_dir()


def test_no_infrastructure_imports_in_application_layer() -> None:
    for path in (ROOT / "application").rglob("*.py"):
        text = path.read_text()
        if _INFRA_IMPORT.search(text):
            raise AssertionError(f"{path} imports infrastructure from the application layer")


def test_no_legacy_threat_intel_import_in_application_layer() -> None:
    for path in (ROOT / "application").rglob("*.py"):
        text = path.read_text()
        if _FORBIDDEN_CONTEXT_IMPORT.search(text) or _FORBIDDEN_APPLICATION_CONTEXT_IMPORT.search(
            text
        ):
            raise AssertionError(f"{path} imports redforge threat_intel directly")


def test_no_sibling_bounded_context_import_in_application_layer() -> None:
    for path in (ROOT / "application").rglob("*.py"):
        text = path.read_text()
        if _FORBIDDEN_SIBLING_CONTEXT_IMPORT.search(text):
            raise AssertionError(f"{path} imports threat_actor_intel directly")


def test_api_layer_exists() -> None:
    """M51.2 Phase A4 adds the API layer."""
    assert (ROOT / "api").is_dir()


def test_application_service_does_not_import_orm_or_concrete_adapters() -> None:
    service_file = ROOT / "application" / "services" / "ioc_application_service.py"
    text = service_file.read_text()
    import_lines = "\n".join(
        line for line in text.splitlines() if line.strip().startswith(("import ", "from "))
    )
    assert "sqlalchemy" not in import_lines.lower()
    assert "fastapi" not in import_lines.lower()
