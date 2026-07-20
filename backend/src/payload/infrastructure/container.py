"""PayloadContainer — wires application services and adapters."""

from __future__ import annotations

from typing import TYPE_CHECKING

from payload.application.services.payload_application_service import (
    PayloadApplicationService,
)
from payload.infrastructure.acl.operation_plan_invalidation_adapter import (
    DegradedPlanInvalidationAdapter,
)
from payload.infrastructure.events.structlog_event_publisher import StructlogEventPublisher
from payload.infrastructure.persistence.unit_of_work import make_payload_uow_factory

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from payload.application.ports.i_unit_of_work import IEventPublisher
    from payload.domain.ports.i_plan_invalidation_port import IPlanInvalidationPort


class PayloadContainer:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        event_publisher: IEventPublisher | None = None,
        *,
        plan_invalidation: IPlanInvalidationPort | None = None,
    ) -> None:
        self._session_factory = session_factory
        self.event_publisher: IEventPublisher = event_publisher or StructlogEventPublisher()
        self.plan_invalidation = plan_invalidation or DegradedPlanInvalidationAdapter()
        uow_factory = make_payload_uow_factory(session_factory)
        self.payload_service = PayloadApplicationService(
            uow_factory,
            self.event_publisher,
            self.plan_invalidation,
        )
