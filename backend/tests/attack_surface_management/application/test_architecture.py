from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "attack_surface_management"
APPLICATION_ROOT = ROOT / "application"
FORBIDDEN_CONTEXT_IMPORT = re.compile(
    r"^\s*(from|import)\s+(cloud_security|ai_posture|ai_security|exposure|"
    r"redforge\.domain\.findings|vulnerability|"
    r"integration_hub|risk_engine|credential_vault)\b",
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


def test_infrastructure_and_api_layers_exist() -> None:
    """M49B was application-only. As of M49C, `infrastructure/` is
    populated (persistence) — see
    `tests/attack_surface_management/infrastructure/` for its own
    checks. As of M49D, `api/` is also populated — see
    `tests/attack_surface_management/api/` for its own checks."""
    assert (ROOT / "infrastructure" / "persistence").is_dir()
    assert (ROOT / "api").is_dir()


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
    `src/attack_surface_management/application/ports`.

    All four ports (`IAssetRepository`, `INetworkRangeRepository`,
    `IUnitOfWork`, `IEventPublisher`) are `ABC`s with only
    `@abstractmethod async def` bodies, matching the platform-wide
    convention used by `risk_engine`/`operation`/`exposure`/
    `credential_vault`/`detection`/`ai_posture`/etc. exactly."""
    ports_dir = APPLICATION_ROOT / "ports"
    for path in ports_dir.rglob("*.py"):
        text = path.read_text()
        assert "ABC" in text or path.name == "__init__.py"
        assert "InMemory" not in text
        assert "Fake" not in text


def test_dtos_are_frozen_slotted_dataclasses_of_primitives() -> None:
    dtos_dir = APPLICATION_ROOT / "dtos"
    for path in dtos_dir.rglob("*.py"):
        if path.name == "__init__.py":
            continue
        text = path.read_text()
        assert "@dataclass(frozen=True, slots=True)" in text
        # DTOs must never import domain aggregates/entities directly.
        assert "domain.aggregates" not in text
        assert "domain.entities" not in text


def test_commands_and_queries_are_frozen_slotted_dataclasses() -> None:
    for sub in ("commands", "queries"):
        for path in (APPLICATION_ROOT / sub).rglob("*.py"):
            if path.name == "__init__.py":
                continue
            text = path.read_text()
            assert "@dataclass(frozen=True, slots=True)" in text


def test_no_blanket_type_ignore_suppressions() -> None:
    banned = re.compile(r"#\s*type:\s*ignore\s*(?!\[)")
    for path in APPLICATION_ROOT.rglob("*.py"):
        text = path.read_text()
        match = banned.search(text)
        if match:
            raise AssertionError(f"{path} uses a blanket '# type: ignore': {match.group()}")
