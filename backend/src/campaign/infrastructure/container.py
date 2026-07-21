"""CampaignContainer — wires campaign application services and adapters."""

from __future__ import annotations

from typing import TYPE_CHECKING

from campaign.application.services.campaign_application_service import (
    CampaignApplicationService,
)
from campaign.infrastructure.acl.degraded_adapters import (
    AlwaysActiveEngagementAdapter,
    StubInventoryQueryAdapter,
)
from campaign.infrastructure.events.structlog_event_publisher import (
    StructlogEventPublisher,
)
from campaign.infrastructure.persistence.unit_of_work import make_campaign_uow_factory

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from campaign.application.ports.i_event_publisher import IEventPublisher
    from campaign.domain.ports.i_engagement_query_port import IEngagementQueryPort
    from campaign.domain.ports.i_inventory_query_port import IInventoryQueryPort


class CampaignContainer:
    """DI container for the campaign bounded context.

    Pass real M29/M22 adapters in production; defaults to degraded stubs for
    testing and local development.
    """

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        event_publisher: IEventPublisher | None = None,
        *,
        inventory_port: IInventoryQueryPort | None = None,
        engagement_port: IEngagementQueryPort | None = None,
    ) -> None:
        self._session_factory = session_factory
        self.event_publisher: IEventPublisher = (
            event_publisher or StructlogEventPublisher()
        )
        self.inventory_port: IInventoryQueryPort = (
            inventory_port or StubInventoryQueryAdapter()
        )
        self.engagement_port: IEngagementQueryPort = (
            engagement_port or AlwaysActiveEngagementAdapter()
        )
        uow_factory = make_campaign_uow_factory(session_factory)
        self.campaign_service = CampaignApplicationService(
            uow_factory,
            self.event_publisher,
            self.inventory_port,
            self.engagement_port,
        )
