"""Architecture/boundary checks for attack_surface_management's
infrastructure layer (M49C) — mirrors
`tests/risk_engine/infrastructure/test_architecture.py`'s style."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "attack_surface_management"
INFRA_ROOT = ROOT / "infrastructure"
FORBIDDEN_CONTEXT_IMPORT = re.compile(
    r"^\s*(from|import)\s+(cloud_security|ai_posture|ai_security|exposure|"
    r"redforge\.domain\.findings|vulnerability|"
    r"integration_hub|risk_engine|credential_vault)\b",
    re.M,
)


def test_layout_has_persistence_and_events() -> None:
    assert (INFRA_ROOT / "persistence" / "models").is_dir()
    assert (INFRA_ROOT / "persistence" / "repositories").is_dir()
    assert (INFRA_ROOT / "events").is_dir()
    assert (INFRA_ROOT / "persistence" / "unit_of_work.py").is_file()


def test_api_layer_exists_at_m49d() -> None:
    """`api/` is populated as of M49D — see `tests/attack_surface_management/api/`."""
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
    """Doesn't re-verify ABC structural typing (mypy's job) — just a
    fast guard that the concrete classes still expose exactly the
    method names the frozen M49B ports declare, so a rename can't
    silently break conformance without a visible failure here first."""
    from attack_surface_management.infrastructure.persistence.repositories.pg_asset_repository import (
        PgAssetRepository,
    )
    from attack_surface_management.infrastructure.persistence.repositories.pg_network_range_repository import (
        PgNetworkRangeRepository,
    )

    for method in ("save", "get", "list"):
        assert hasattr(PgAssetRepository, method)
        assert hasattr(PgNetworkRangeRepository, method)


def test_unit_of_work_subclasses_frozen_iunitofwork() -> None:
    from attack_surface_management.application.ports.i_unit_of_work import IUnitOfWork
    from attack_surface_management.infrastructure.persistence.unit_of_work import (
        SqlAlchemyUnitOfWork,
    )

    assert issubclass(SqlAlchemyUnitOfWork, IUnitOfWork)


def test_asset_repository_subclasses_frozen_port() -> None:
    from attack_surface_management.application.ports.i_asset_repository import IAssetRepository
    from attack_surface_management.infrastructure.persistence.repositories.pg_asset_repository import (
        PgAssetRepository,
    )

    assert issubclass(PgAssetRepository, IAssetRepository)


def test_network_range_repository_subclasses_frozen_port() -> None:
    from attack_surface_management.application.ports.i_network_range_repository import (
        INetworkRangeRepository,
    )
    from attack_surface_management.infrastructure.persistence.repositories.pg_network_range_repository import (
        PgNetworkRangeRepository,
    )

    assert issubclass(PgNetworkRangeRepository, INetworkRangeRepository)


def test_event_publisher_subclasses_frozen_ieventpublisher() -> None:
    from attack_surface_management.application.ports.i_event_publisher import IEventPublisher
    from attack_surface_management.infrastructure.events.structlog_event_publisher import (
        StructlogEventPublisher,
    )

    assert issubclass(StructlogEventPublisher, IEventPublisher)


def test_models_use_selectin_loading_for_asset_child_collections() -> None:
    """Regression guard for the `MissingGreenlet` class of bug: every
    one-to-many (`cascade=...`) relationship on `AssetModel` must
    declare `lazy="selectin"`. The reverse (child -> parent)
    `back_populates` relationships are scalar many-to-one references
    and don't need eager loading here."""
    text = (INFRA_ROOT / "persistence" / "models" / "asset_model.py").read_text()
    relationship_blocks = re.findall(r"relationship\(([^)]*)\)", text, re.S)
    cascading_blocks = [block for block in relationship_blocks if "cascade=" in block]
    assert cascading_blocks, "expected at least one cascading relationship() on AssetModel"
    for block in cascading_blocks:
        assert 'lazy="selectin"' in block


def test_no_blanket_type_ignore_suppressions() -> None:
    banned = re.compile(r"#\s*type:\s*ignore\s*(?!\[)")
    for path in INFRA_ROOT.rglob("*.py"):
        text = path.read_text()
        match = banned.search(text)
        if match:
            raise AssertionError(f"{path} uses a blanket '# type: ignore': {match.group()}")
