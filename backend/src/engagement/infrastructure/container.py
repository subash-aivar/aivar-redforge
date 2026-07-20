"""EngagementContainer — wires application services and adapters."""

from __future__ import annotations

from typing import TYPE_CHECKING

from engagement.application.services.engagement_application_service import (
    EngagementApplicationService,
)
from engagement.domain.services.engagement_factory import EngagementFactory
from engagement.infrastructure.acl.degraded_adapters import (
    DegradedAssetQueryAdapter,
    HmacDigitalSignatureAdapter,
)
from engagement.infrastructure.events.structlog_event_publisher import (
    StructlogEventPublisher,
)
from engagement.infrastructure.persistence.unit_of_work import make_engagement_uow_factory

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from engagement.application.ports.i_event_publisher import IEventPublisher
    from engagement.domain.ports.i_asset_query_port import IAssetQueryPort
    from engagement.domain.ports.i_digital_signature_port import IDigitalSignaturePort


class EngagementContainer:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        event_publisher: IEventPublisher | None = None,
        *,
        asset_query: IAssetQueryPort | None = None,
        signature_port: IDigitalSignaturePort | None = None,
        hmac_secret: str | None = None,
    ) -> None:
        self._session_factory = session_factory
        self.event_publisher: IEventPublisher = event_publisher or StructlogEventPublisher()
        self.asset_query = asset_query or DegradedAssetQueryAdapter()
        self.signature_port = signature_port or HmacDigitalSignatureAdapter(
            secret=hmac_secret
        )
        self.factory = EngagementFactory()
        uow_factory = make_engagement_uow_factory(session_factory)
        self.engagement_service = EngagementApplicationService(
            uow_factory,
            self.event_publisher,
            self.asset_query,
            self.signature_port,
            self.factory,
        )
