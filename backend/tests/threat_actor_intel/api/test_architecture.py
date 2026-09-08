"""Architecture/boundary checks for threat_actor_intel's API layer
(M51.1 Phase 4), mirroring `tests/threat_actor_intel/infrastructure/
test_architecture.py`'s style."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "threat_actor_intel"
API_ROOT = ROOT / "api"
FORBIDDEN_CONTEXT_IMPORT = re.compile(
    r"^\s*(from|import)\s+(cloud_security|ai_posture|ai_security|exposure|"
    r"redforge\.domain\.threat_intel|redforge\.application\.threat_intel|"
    r"vulnerability|vulnerability_engine|integration_hub|risk_engine|"
    r"attack_surface_management|credential_vault|detection|siem_detection)\b",
    re.M,
)


def test_layout_has_schemas_and_v1() -> None:
    assert (API_ROOT / "schemas").is_dir()
    assert (API_ROOT / "v1").is_dir()
    assert (API_ROOT / "dependencies.py").is_file()
    assert (API_ROOT / "exception_handlers.py").is_file()


def test_api_does_not_import_forbidden_bounded_contexts() -> None:
    for path in API_ROOT.rglob("*.py"):
        text = path.read_text()
        match = FORBIDDEN_CONTEXT_IMPORT.search(text)
        if match:
            raise AssertionError(
                f"{path} imports a forbidden bounded-context module: {match.group()}"
            )


def test_no_sqlalchemy_import_in_routers_or_schemas() -> None:
    """No repository bypass: route handlers go through the application
    service only, never a session/repository/ORM model directly.
    `dependencies.py` is exempt — it legitimately type-hints the
    request-scoped `AsyncSession` it opens/closes per request (under
    `TYPE_CHECKING` only), the same pattern `risk_engine.api.
    dependencies` already uses — it never issues a query itself."""
    forbidden = re.compile(r"^\s*(from|import)\s+sqlalchemy\b", re.M)
    for path in (*(API_ROOT / "v1").rglob("*.py"), *(API_ROOT / "schemas").rglob("*.py")):
        text = path.read_text()
        if forbidden.search(text):
            raise AssertionError(f"{path} imports SQLAlchemy directly in the API layer")


def test_no_domain_aggregate_import_in_api_layer() -> None:
    """No domain object exposed: routes work with commands/queries/DTOs
    only, never a `ThreatActor`/`ThreatActorAssociation` aggregate."""
    forbidden = re.compile(r"^\s*from\s+threat_actor_intel\.domain\.aggregates\b", re.M)
    for path in API_ROOT.rglob("*.py"):
        text = path.read_text()
        if forbidden.search(text):
            raise AssertionError(f"{path} imports a domain aggregate directly in the API layer")


def test_no_blanket_type_ignore_suppressions() -> None:
    banned = re.compile(r"#\s*type:\s*ignore\s*(?!\[)")
    for path in API_ROOT.rglob("*.py"):
        text = path.read_text()
        match = banned.search(text)
        if match:
            raise AssertionError(f"{path} uses a blanket '# type: ignore': {match.group()}")
