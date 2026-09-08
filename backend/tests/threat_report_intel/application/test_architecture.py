from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "threat_report_intel"

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
    service_file = ROOT / "application" / "services" / "threat_report_application_service.py"
    text = service_file.read_text()
    import_lines = "\n".join(
        line for line in text.splitlines() if line.strip().startswith(("import ", "from "))
    )
    assert "sqlalchemy" not in import_lines.lower()
    assert "fastapi" not in import_lines.lower()


def test_no_acl_identity_port_exists() -> None:
    """A published threat report has no upstream canonical catalog RedForge
    defers to — no identity ACL port should exist here (same call
    campaign_intel, malware_intel, tool_intel and infrastructure_intel
    made). `external_report_id` is EVIDENCE, not an identity authority."""
    ports = {p.name for p in (ROOT / "application" / "ports").rglob("*.py")}
    assert not any("identity_port" in name for name in ports), ports


def test_no_relationship_port_exists() -> None:
    """Relationships belong to `intelligence_relationships` — this
    context owns no relationship port, even though relationships
    involving a threat report are fully expressible there today; see
    the aggregate's module docstring."""
    ports = {p.name for p in (ROOT / "application" / "ports").rglob("*.py")}
    assert not any("relationship" in name for name in ports), ports


def test_the_application_service_exposes_no_relationship_method() -> None:
    from threat_report_intel.application.services.threat_report_application_service import (
        ThreatReportApplicationService,
    )

    methods = [m for m in dir(ThreatReportApplicationService) if not m.startswith("_")]
    assert not [m for m in methods if "relationship" in m.lower()], methods
