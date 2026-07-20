"""OperationContainer — wires application services and adapters."""

from __future__ import annotations

from typing import TYPE_CHECKING

from operation.application.services.operation_application_service import (
    OperationApplicationService,
)
from operation.infrastructure.acl.degraded_adapters import (
    DegradedEngagementQueryAdapter,
    DegradedVulnerabilityQueryAdapter,
)
from operation.infrastructure.events.structlog_event_publisher import StructlogEventPublisher
from operation.infrastructure.persistence.unit_of_work import make_operation_uow_factory

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from operation.application.ports.i_event_publisher import IEventPublisher
    from operation.domain.ports.i_engagement_query_port import IEngagementQueryPort
    from operation.domain.ports.i_vulnerability_query_port import IVulnerabilityQueryPort


class OperationContainer:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        event_publisher: IEventPublisher | None = None,
        *,
        engagement_query: IEngagementQueryPort | None = None,
        vulnerability_query: IVulnerabilityQueryPort | None = None,
    ) -> None:
        self._session_factory = session_factory
        self.event_publisher: IEventPublisher = event_publisher or StructlogEventPublisher()
        self.engagement_query = engagement_query or DegradedEngagementQueryAdapter()
        self.vulnerability_query = vulnerability_query or DegradedVulnerabilityQueryAdapter()
        uow_factory = make_operation_uow_factory(session_factory)
        self.operation_service = OperationApplicationService(
            uow_factory,
            self.event_publisher,
            self.engagement_query,
            self.vulnerability_query,
        )
