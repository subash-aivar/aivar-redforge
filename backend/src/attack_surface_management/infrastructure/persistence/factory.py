"""Repository/UnitOfWork/EventPublisher factories for
attack_surface_management (M49C) — thin construction helpers, not a DI
container, mirroring `risk_engine.infrastructure.persistence.factory`'s
module-level-function convention exactly."""

from __future__ import annotations

from typing import TYPE_CHECKING

from attack_surface_management.infrastructure.events.structlog_event_publisher import (
    StructlogEventPublisher,
)
from attack_surface_management.infrastructure.persistence.repositories.pg_asset_repository import (
    PgAssetRepository,
)
from attack_surface_management.infrastructure.persistence.repositories.pg_network_range_repository import (  # noqa: E501
    PgNetworkRangeRepository,
)
from attack_surface_management.infrastructure.persistence.unit_of_work import (
    SqlAlchemyUnitOfWork,
    make_sqlalchemy_uow_factory,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


def make_asset_repository(session: AsyncSession) -> PgAssetRepository:
    return PgAssetRepository(session)


def make_network_range_repository(session: AsyncSession) -> PgNetworkRangeRepository:
    return PgNetworkRangeRepository(session)


def make_attack_surface_management_uow_factory(
    session_factory: async_sessionmaker[AsyncSession],
) -> Callable[[], SqlAlchemyUnitOfWork]:
    return make_sqlalchemy_uow_factory(session_factory)


def make_attack_surface_management_event_publisher() -> StructlogEventPublisher:
    return StructlogEventPublisher()
