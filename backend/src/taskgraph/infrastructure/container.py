"""TaskGraphContainer — wires application services and adapters."""

from __future__ import annotations

from typing import TYPE_CHECKING

from taskgraph.application.services.task_graph_application_service import (
    TaskGraphApplicationService,
)
from taskgraph.infrastructure.acl.degraded_adapters import StubTaskGraphGraphWriteAdapter
from taskgraph.infrastructure.events.structlog_event_publisher import (
    StructlogEventPublisher,
)
from taskgraph.infrastructure.persistence.unit_of_work import make_task_graph_uow_factory

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from taskgraph.application.ports.i_event_publisher import IEventPublisher
    from taskgraph.domain.ports.i_security_graph_write_port import ISecurityGraphWritePort


class TaskGraphContainer:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        event_publisher: IEventPublisher | None = None,
        *,
        graph_write_port: ISecurityGraphWritePort | None = None,
    ) -> None:
        self._session_factory = session_factory
        self.event_publisher: IEventPublisher = event_publisher or StructlogEventPublisher()
        self.graph_write_port: ISecurityGraphWritePort = (
            graph_write_port or StubTaskGraphGraphWriteAdapter()
        )
        uow_factory = make_task_graph_uow_factory(session_factory)
        self.task_graph_service = TaskGraphApplicationService(
            uow_factory,
            self.event_publisher,
            graph_write_port=self.graph_write_port,
        )
