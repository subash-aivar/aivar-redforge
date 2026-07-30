"""Integration test asserting raw SQLAlchemy/DBAPI errors never leak
past the repository boundary — they are translated to
`AttackSurfaceIntegrityError`."""

from __future__ import annotations

import pytest
from sqlalchemy.exc import IntegrityError

from attack_surface_management.infrastructure.persistence.exceptions import (
    AttackSurfaceIntegrityError,
)
from attack_surface_management.infrastructure.persistence.repositories.pg_asset_repository import (
    PgAssetRepository,
)
from attack_surface_management.infrastructure.persistence.repositories.pg_network_range_repository import (
    PgNetworkRangeRepository,
)
from tests.attack_surface_management.infrastructure.helpers import (
    make_asset,
    make_network_range,
    make_tenant_id,
)

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_asset_save_translates_integrity_error_via_repository_guard(
    asm_session, monkeypatch
) -> None:
    """Forces the repository's own IntegrityError branch by making the
    session's flush() raise a SQLAlchemy IntegrityError, and asserts
    the caller only ever sees `AttackSurfaceIntegrityError`."""
    tenant_id = make_tenant_id()
    repo = PgAssetRepository(asm_session)
    asset = make_asset(tenant_id)

    def _boom(*args: object, **kwargs: object) -> None:
        raise IntegrityError("INSERT", {}, Exception("duplicate key"))

    monkeypatch.setattr(asm_session, "flush", _boom)

    with pytest.raises(AttackSurfaceIntegrityError):
        await repo.save(asset)


@pytest.mark.asyncio
async def test_network_range_save_translates_integrity_error(asm_session, monkeypatch) -> None:
    tenant_id = make_tenant_id()
    repo = PgNetworkRangeRepository(asm_session)
    network_range = make_network_range(tenant_id)

    def _boom(*args: object, **kwargs: object) -> None:
        raise IntegrityError("INSERT", {}, Exception("duplicate key"))

    monkeypatch.setattr(asm_session, "flush", _boom)

    with pytest.raises(AttackSurfaceIntegrityError):
        await repo.save(network_range)
