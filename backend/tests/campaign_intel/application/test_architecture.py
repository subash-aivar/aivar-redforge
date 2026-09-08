from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "campaign_intel"

_INFRA_IMPORT = re.compile(
    r"^\s*(from|import)\s+(fastapi|sqlalchemy|asyncpg|alembic|redis|celery|kafka)\b", re.M
)


def test_application_layer_exists() -> None:
    assert (ROOT / "application").is_dir()


def test_no_infrastructure_imports_in_application_layer() -> None:
    for path in (ROOT / "application").rglob("*.py"):
        text = path.read_text()
        if _INFRA_IMPORT.search(text):
            raise AssertionError(f"{path} imports infrastructure from the application layer")


def test_application_service_does_not_import_orm_or_concrete_adapters() -> None:
    service_file = ROOT / "application" / "services" / "campaign_application_service.py"
    text = service_file.read_text()
    import_lines = "\n".join(
        line for line in text.splitlines() if line.strip().startswith(("import ", "from "))
    )
    assert "sqlalchemy" not in import_lines.lower()
    assert "fastapi" not in import_lines.lower()


def test_no_acl_identity_port_exists() -> None:
    """A real-world adversary campaign's canonical_name has no upstream
    catalog — no identity ACL port should exist here (same call
    malware_intel made)."""
    ports = {p.name for p in (ROOT / "application" / "ports").rglob("*.py")}
    assert not any("identity_port" in name for name in ports), ports


def test_no_relationship_port_exists() -> None:
    ports = {p.name for p in (ROOT / "application" / "ports").rglob("*.py")}
    assert not any("relationship" in name for name in ports), ports
