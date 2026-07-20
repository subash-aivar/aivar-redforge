"""OperatorContainer — wires application services and adapters."""

from __future__ import annotations

from typing import TYPE_CHECKING

from red_team_operator.application.services.operator_application_service import (
    OperatorApplicationService,
)
from red_team_operator.application.services.operator_query_service import OperatorQueryService
from red_team_operator.infrastructure.events.structlog_event_publisher import (
    StructlogEventPublisher,
)
from red_team_operator.infrastructure.persistence.repositories.pg_red_team_operator_repository import (  # noqa: E501
    PgRedTeamOperatorRepository,
)
from red_team_operator.infrastructure.persistence.unit_of_work import make_operator_uow_factory

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from red_team_operator.application.ports.i_event_publisher import IEventPublisher


class OperatorContainer:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        event_publisher: IEventPublisher | None = None,
    ) -> None:
        self._session_factory = session_factory
        self.event_publisher = event_publisher or StructlogEventPublisher()
        uow_factory = make_operator_uow_factory(session_factory)
        self.operator_service = OperatorApplicationService(
            uow_factory,
            self.event_publisher,
        )

    def make_operator_query_service(self, session: AsyncSession) -> OperatorQueryService:
        return OperatorQueryService(PgRedTeamOperatorRepository(session))
