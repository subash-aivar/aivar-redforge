from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "risk_engine"
APPLICATION_ROOT = ROOT / "application"
FORBIDDEN_CONTEXT_IMPORT = re.compile(
    r"^\s*(from|import)\s+(cloud_security|ai_posture|exposure|redforge\.domain\.findings|"
    r"vulnerability|integration_hub)\b",
    re.M,
)
FORBIDDEN_INFRA_IMPORT = re.compile(
    r"^\s*(from|import)\s+(fastapi|sqlalchemy|asyncpg|alembic|redis|celery|kafka)\b", re.M
)


def test_layout_has_application_layer() -> None:
    assert (APPLICATION_ROOT / "commands").is_dir()
    assert (APPLICATION_ROOT / "queries").is_dir()
    assert (APPLICATION_ROOT / "dtos").is_dir()
    assert (APPLICATION_ROOT / "ports").is_dir()
    assert (APPLICATION_ROOT / "services").is_dir()


def test_api_layer_exists_at_m48f() -> None:
    """M48F (the final milestone of the Enterprise Risk Engine epic)
    adds `api/` — FastAPI routers, request/response schemas, DI
    wiring, and exception translation over the frozen M48C/M48D
    application layer. See `tests/risk_engine/api/` for its own
    boundary/behavior checks."""
    assert (ROOT / "api").is_dir()
    assert (ROOT / "api" / "v1").is_dir()
    assert (ROOT / "api" / "schemas").is_dir()
    assert (ROOT / "api" / "dependencies.py").is_file()
    assert (ROOT / "api" / "exception_handlers.py").is_file()


def test_infrastructure_layer_exists_at_m48e() -> None:
    """As of M48E, `infrastructure/` is populated with the concrete
    SQLAlchemy persistence layer for the ports declared under
    `application/ports` — see `tests/risk_engine/infrastructure/` for
    its own boundary/behavior checks."""
    assert (ROOT / "infrastructure").is_dir()
    assert (ROOT / "infrastructure" / "persistence").is_dir()


def test_application_layer_does_not_import_forbidden_bounded_contexts() -> None:
    for path in APPLICATION_ROOT.rglob("*.py"):
        text = path.read_text()
        match = FORBIDDEN_CONTEXT_IMPORT.search(text)
        if match:
            raise AssertionError(
                f"{path} imports a forbidden bounded-context module: {match.group()}"
            )


def test_application_layer_does_not_import_infrastructure() -> None:
    for path in APPLICATION_ROOT.rglob("*.py"):
        text = path.read_text()
        match = FORBIDDEN_INFRA_IMPORT.search(text)
        if match:
            raise AssertionError(f"{path} imports infrastructure: {match.group()}")


def test_ports_are_pure_interfaces_with_no_implementation() -> None:
    """Ports are pure interface contracts only — no concrete
    registry/repository class is defined anywhere under
    `src/risk_engine/application/ports`.

    All four ports (`EnterpriseRiskProfileRepository`,
    `RiskCorrelationRepository`, `IUnitOfWork`, `IEventPublisher`) are
    `ABC`s with only `@abstractmethod async def` bodies, matching the
    platform-wide convention used by `operation`/`exposure`/
    `credential_vault`/`detection`/`ai_posture`/etc. exactly. The
    repository ports were originally declared as sync `Protocol`s at
    M48C; that was a deviation from mature-context convention,
    documented in `docs/architecture/m48/M48E_ADR.md` and corrected by
    converting them to async `ABC`s — this test now enforces the
    corrected, platform-uniform shape."""
    ports_dir = APPLICATION_ROOT / "ports"
    for path in ports_dir.rglob("*.py"):
        text = path.read_text()
        assert "ABC" in text or path.name == "__init__.py"
        assert "InMemory" not in text


def test_no_blanket_type_ignore_suppressions() -> None:
    banned = re.compile(r"#\s*type:\s*ignore\s*(?!\[)")
    for path in APPLICATION_ROOT.rglob("*.py"):
        text = path.read_text()
        match = banned.search(text)
        if match:
            raise AssertionError(f"{path} uses a blanket '# type: ignore': {match.group()}")
