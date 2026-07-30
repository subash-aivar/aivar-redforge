from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "risk_engine"
FORBIDDEN_CONTEXT_IMPORT = re.compile(
    r"^\s*(from|import)\s+(cloud_security|ai_posture|exposure|redforge\.domain\.findings|"
    r"vulnerability|integration_hub)\b",
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


def test_api_layer_exists_at_m48f() -> None:
    """As of M48F (the final milestone of the Enterprise Risk Engine
    epic), `application/`, `infrastructure/`, and `api/` are all
    populated (see `tests/risk_engine/application/test_architecture.py`,
    `tests/risk_engine/infrastructure/`, and `tests/risk_engine/api/`
    for their own boundary checks) — the domain layer itself is
    unchanged from M48B."""
    assert (ROOT / "api").is_dir()


def test_context_does_not_import_forbidden_bounded_contexts() -> None:
    """M48B's explicit boundary: risk_engine must never import from
    `cloud_security`, `ai_posture`, `exposure`,
    `redforge.domain.findings`, `vulnerability`,
    or `integration_hub` — only the truly-shared `redforge.shared` is
    legitimate to reuse. This context only ever consumes
    already-computed values via `RiskSignalReference`; it never
    recomputes another bounded context's score."""
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
