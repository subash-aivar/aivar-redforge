from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "attack_surface_management"
FORBIDDEN_CONTEXT_IMPORT = re.compile(
    r"^\s*(from|import)\s+(cloud_security|ai_posture|ai_security|exposure|"
    r"redforge\.domain\.findings|vulnerability|"
    r"integration_hub|risk_engine|credential_vault)\b",
    re.M,
)


def test_layout_has_domain_layer_only() -> None:
    assert (ROOT / "domain" / "aggregates").is_dir()
    assert (ROOT / "domain" / "entities").is_dir()
    assert (ROOT / "domain" / "value_objects").is_dir()
    assert (ROOT / "domain" / "events").is_dir()
    assert (ROOT / "domain" / "exceptions").is_dir()
    assert (ROOT / "domain" / "specifications").is_dir()
    assert (ROOT / "domain" / "services").is_dir()
    assert (ROOT / "domain" / "policies").is_dir()
    assert (ROOT / "domain" / "factories").is_dir()


def test_application_layer_exists_at_m49b() -> None:
    """As of M49B, `application/` is populated with commands, queries,
    DTOs, ports, and application services over this frozen M49A domain
    layer — see `tests/attack_surface_management/application/` for its
    own boundary/behavior checks. As of M49C, `infrastructure/` is also
    populated (persistence) — see
    `tests/attack_surface_management/infrastructure/` for its own
    checks. As of M49D, `api/` is also populated — see
    `tests/attack_surface_management/api/` for its own checks."""
    assert (ROOT / "application" / "commands").is_dir()
    assert (ROOT / "application" / "queries").is_dir()
    assert (ROOT / "application" / "dtos").is_dir()
    assert (ROOT / "application" / "ports").is_dir()
    assert (ROOT / "application" / "services").is_dir()
    assert (ROOT / "infrastructure" / "persistence").is_dir()
    assert (ROOT / "api").is_dir()


def test_context_does_not_import_forbidden_bounded_contexts() -> None:
    """M49A's explicit boundary: attack_surface_management must never
    import from any other bounded context — only the truly-shared
    `redforge.shared` is legitimate to reuse. This is a brand-new
    context and must have zero cross-context coupling at this phase."""
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        match = FORBIDDEN_CONTEXT_IMPORT.search(text)
        if match:
            raise AssertionError(
                f"{path} imports a forbidden bounded-context module: {match.group()}"
            )


def test_no_infrastructure_imports_in_domain_layer() -> None:
    infra_import = re.compile(
        r"^\s*(from|import)\s+(fastapi|sqlalchemy|asyncpg|alembic|redis|celery|kafka)\b", re.M
    )
    for path in (ROOT / "domain").rglob("*.py"):
        text = path.read_text()
        if infra_import.search(text):
            raise AssertionError(f"{path} imports infrastructure from the domain layer")


def test_no_blanket_type_ignore_suppressions() -> None:
    banned = re.compile(r"#\s*type:\s*ignore\s*(?!\[)")
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        match = banned.search(text)
        if match:
            raise AssertionError(f"{path} uses a blanket '# type: ignore': {match.group()}")
