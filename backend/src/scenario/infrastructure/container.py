"""Dependency injection container for scenario context."""

from __future__ import annotations

from typing import TYPE_CHECKING

from scenario.infrastructure.acl.degraded_adapters import (
    StubCampaignDraftPort,
    StubScenarioGraphWriteAdapter,
    StubThreatIntelAdapter,
)
from scenario.infrastructure.events.structlog_event_publisher import (
    StructlogEventPublisher,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from sqlalchemy.ext.asyncio import AsyncSession

    from scenario.application.ports.i_event_publisher import IEventPublisher
    from scenario.application.services.scenario_application_service import (
        ScenarioApplicationService,
    )
    from scenario.domain.ports.i_campaign_draft_port import ICampaignDraftPort
    from scenario.domain.ports.i_security_graph_write_port import ISecurityGraphWritePort
    from scenario.domain.ports.i_threat_intel_query_port import IThreatIntelQueryPort


def build_scenario_application_service(
    session_factory: Callable[[], AsyncSession],
    *,
    event_publisher: IEventPublisher | None = None,
    threat_intel_port: IThreatIntelQueryPort | None = None,
    graph_write_port: ISecurityGraphWritePort | None = None,
    campaign_draft_port: ICampaignDraftPort | None = None,
) -> ScenarioApplicationService:
    from scenario.application.services.scenario_application_service import (
        ScenarioApplicationService,
    )
    from scenario.infrastructure.persistence.unit_of_work import PgUnitOfWork

    def uow_factory() -> PgUnitOfWork:
        return PgUnitOfWork(session_factory())

    return ScenarioApplicationService(
        uow_factory=uow_factory,
        event_publisher=event_publisher or StructlogEventPublisher(),
        threat_intel_port=threat_intel_port or StubThreatIntelAdapter(),
        graph_write_port=graph_write_port or StubScenarioGraphWriteAdapter(),
        campaign_draft_port=campaign_draft_port or StubCampaignDraftPort(),
    )
