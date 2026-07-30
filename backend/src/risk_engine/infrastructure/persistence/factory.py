"""Repository/UnitOfWork/EventPublisher factories for risk_engine
(M48E) — thin construction helpers, not a DI container (out of scope
per the M48E spec). Mirrors `credential_vault`'s
`make_credential_vault_uow_factory` module-level-function convention
rather than introducing a class-based container."""

from __future__ import annotations

from typing import TYPE_CHECKING

from risk_engine.infrastructure.events.structlog_event_publisher import StructlogEventPublisher
from risk_engine.infrastructure.persistence.repositories.pg_risk_correlation_repository import (
    PgRiskCorrelationRepository,
)
from risk_engine.infrastructure.persistence.repositories.pg_risk_profile_repository import (
    PgEnterpriseRiskProfileRepository,
)
from risk_engine.infrastructure.persistence.unit_of_work import (
    SqlAlchemyUnitOfWork,
    make_sqlalchemy_uow_factory,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


def make_risk_profile_repository(session: AsyncSession) -> PgEnterpriseRiskProfileRepository:
    return PgEnterpriseRiskProfileRepository(session)


def make_risk_correlation_repository(session: AsyncSession) -> PgRiskCorrelationRepository:
    return PgRiskCorrelationRepository(session)


def make_risk_engine_uow_factory(
    session_factory: async_sessionmaker[AsyncSession],
) -> Callable[[], SqlAlchemyUnitOfWork]:
    return make_sqlalchemy_uow_factory(session_factory)


def make_risk_engine_event_publisher() -> StructlogEventPublisher:
    return StructlogEventPublisher()
