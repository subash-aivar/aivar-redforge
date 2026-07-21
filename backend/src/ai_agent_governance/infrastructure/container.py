from __future__ import annotations

from typing import TYPE_CHECKING

from ai_agent_governance.application.queries.governance_query_handlers import (
    GovernanceQueryHandler,
)
from ai_agent_governance.application.services.deviation_app_service import (
    DeviationApplicationService,
)
from ai_agent_governance.application.services.envelope_app_service import (
    EnvelopeApplicationService,
)
from ai_agent_governance.infrastructure.events.structlog_event_publisher import (
    StructlogEventPublisher,
)
from ai_agent_governance.infrastructure.persistence.in_memory_unit_of_work import (
    InMemoryUnitOfWork,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from ai_agent_governance.application.ports.i_unit_of_work import IUnitOfWork


class AgentGovernanceContainer:
    def __init__(self, *, uow_factory: Callable[[], IUnitOfWork] | None = None) -> None:
        shared = InMemoryUnitOfWork()

        def default_factory() -> IUnitOfWork:
            return shared

        self._uow_factory = uow_factory or default_factory
        self.event_publisher = StructlogEventPublisher()
        self.envelope_service = EnvelopeApplicationService(self._uow_factory, self.event_publisher)
        self.deviation_service = DeviationApplicationService(
            self._uow_factory, self.event_publisher
        )
        self.query_handler = GovernanceQueryHandler(self._uow_factory)
