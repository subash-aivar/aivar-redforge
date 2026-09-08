"""ToolIntelContainer — composition root, mirroring
`campaign_intel.infrastructure.container.CampaignIntelContainer`'s
shape: holds a `session_factory` + `event_publisher`, wired at
application startup. `build_service` constructs a fresh, session-scoped
service per call — a repository instance is bound to one `AsyncSession`
and cannot safely be shared across concurrent requests/tenants."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tool_intel.application.services.tool_application_service import (
    ToolApplicationService,
)
from tool_intel.infrastructure.events.structlog_event_publisher import (
    StructlogEventPublisher,
)
from tool_intel.infrastructure.persistence.unit_of_work import SqlAlchemyUnitOfWork

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from tool_intel.application.ports.i_event_publisher import IEventPublisher


class ToolIntelContainer:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        event_publisher: IEventPublisher | None = None,
    ) -> None:
        self.session_factory = session_factory
        self.event_publisher: IEventPublisher = event_publisher or StructlogEventPublisher()

    def new_session(self) -> AsyncSession:
        return self.session_factory()

    def _uow_for(self, session: AsyncSession) -> SqlAlchemyUnitOfWork:
        return SqlAlchemyUnitOfWork(lambda: session)  # type: ignore[arg-type]

    def build_service(self, session: AsyncSession) -> ToolApplicationService:
        return ToolApplicationService(
            uow_factory=lambda: self._uow_for(session),
            event_publisher=self.event_publisher,
        )
