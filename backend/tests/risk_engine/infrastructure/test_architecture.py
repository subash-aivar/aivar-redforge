"""Architecture/boundary checks for risk_engine's infrastructure
layer (M48E) — mirrors the domain/application `test_architecture.py`
modules' style."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "risk_engine"
INFRA_ROOT = ROOT / "infrastructure"
FORBIDDEN_CONTEXT_IMPORT = re.compile(
    r"^\s*(from|import)\s+(cloud_security|ai_posture|exposure|redforge\.domain\.findings|"
    r"vulnerability|integration_hub)\b",
    re.M,
)


def test_layout_has_persistence_and_events() -> None:
    assert (INFRA_ROOT / "persistence" / "models").is_dir()
    assert (INFRA_ROOT / "persistence" / "repositories").is_dir()
    assert (INFRA_ROOT / "events").is_dir()
    assert (INFRA_ROOT / "persistence" / "unit_of_work.py").is_file()


def test_api_layer_exists_at_m48f() -> None:
    """`api/` is populated as of M48F — see `tests/risk_engine/api/`
    for its own boundary/behavior checks."""
    assert (ROOT / "api").is_dir()


def test_infrastructure_does_not_import_forbidden_bounded_contexts() -> None:
    for path in INFRA_ROOT.rglob("*.py"):
        text = path.read_text()
        match = FORBIDDEN_CONTEXT_IMPORT.search(text)
        if match:
            raise AssertionError(
                f"{path} imports a forbidden bounded-context module: {match.group()}"
            )


def test_repositories_implement_frozen_port_method_names() -> None:
    """Doesn't re-verify Protocol structural typing (mypy's job) —
    just a fast guard that the concrete classes still expose exactly
    the method names the frozen M48C ports declare, so a rename can't
    silently break structural conformance without a visible failure
    here first."""
    from risk_engine.infrastructure.persistence.repositories.pg_risk_correlation_repository import (
        PgRiskCorrelationRepository,
    )
    from risk_engine.infrastructure.persistence.repositories.pg_risk_profile_repository import (
        PgEnterpriseRiskProfileRepository,
    )

    for method in ("save", "get", "list", "score_history"):
        assert hasattr(PgEnterpriseRiskProfileRepository, method)
    for method in ("save", "get", "list"):
        assert hasattr(PgRiskCorrelationRepository, method)


def test_unit_of_work_subclasses_frozen_iunitofwork() -> None:
    from risk_engine.application.ports.i_unit_of_work import IUnitOfWork
    from risk_engine.infrastructure.persistence.unit_of_work import SqlAlchemyUnitOfWork

    assert issubclass(SqlAlchemyUnitOfWork, IUnitOfWork)


def test_event_publisher_subclasses_frozen_ieventpublisher() -> None:
    from risk_engine.application.ports.i_event_publisher import IEventPublisher
    from risk_engine.infrastructure.events.structlog_event_publisher import (
        StructlogEventPublisher,
    )

    assert issubclass(StructlogEventPublisher, IEventPublisher)


def test_no_blanket_type_ignore_suppressions() -> None:
    banned = re.compile(r"#\s*type:\s*ignore\s*(?!\[)")
    for path in INFRA_ROOT.rglob("*.py"):
        text = path.read_text()
        match = banned.search(text)
        if match:
            raise AssertionError(f"{path} uses a blanket '# type: ignore': {match.group()}")
