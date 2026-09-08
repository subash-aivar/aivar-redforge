"""IocIntelContainer — M51.2 Phase A3 composition root, mirroring
`threat_actor_intel.infrastructure.container.ThreatActorIntelContainer`'s
shape: holds a `session_factory` + `event_publisher`, wired at
application startup. `build_service`/`build_ingestion_orchestrator`
construct fresh, session-scoped objects per call — required because a
repository instance (and the real evidence/legacy-adapter instances)
is bound to one `AsyncSession` and cannot safely be shared across
concurrent requests/tenants/jobs; this is also why no unsafe singleton
database session exists anywhere in this module.

Production DI never uses a seeded allow-list evidence validator or a
stub legacy adapter here — only test doubles do, and only inside
`tests/` (M51.2 Phase A5: `build_ingestion_orchestrator` wires the
real `SqlAlchemyLegacyIocObservationAdapter`/
`SqlAlchemyIocEnrichmentQueryAdapter`/`SqlAlchemyIocCorrelationQueryAdapter`
— all read-only, all against the existing `threat_intel` tables, none
of them makes a network provider call). No API registration happens
in this module."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ioc_intelligence.application.services.ioc_application_service import IOCApplicationService
from ioc_intelligence.application.services.ioc_ingestion_orchestrator import (
    IocIngestionOrchestrator,
)
from ioc_intelligence.infrastructure.acl.infrastructure_evidence_validation_adapter import (
    InfrastructureEvidenceValidationAdapter,
)
from ioc_intelligence.infrastructure.acl.ioc_correlation_query_adapter import (
    SqlAlchemyIocCorrelationQueryAdapter,
)
from ioc_intelligence.infrastructure.acl.ioc_enrichment_query_adapter import (
    SqlAlchemyIocEnrichmentQueryAdapter,
)
from ioc_intelligence.infrastructure.acl.legacy_ioc_observation_adapter import (
    SqlAlchemyLegacyIocObservationAdapter,
)
from ioc_intelligence.infrastructure.events.structlog_event_publisher import (
    StructlogEventPublisher,
)
from ioc_intelligence.infrastructure.persistence.unit_of_work import SqlAlchemyUnitOfWork
from redforge.application.evidence_existence.sqlalchemy_evidence_entity_existence_service import (
    SqlAlchemyEvidenceEntityExistenceService,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from ioc_intelligence.application.ports.i_event_publisher import IEventPublisher


class IocIntelContainer:
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
        # Wraps the already-open, request-scoped `session` in a
        # zero-arg callable so `SqlAlchemyUnitOfWork.__aenter__` reuses
        # it rather than opening a second, disconnected session —
        # matches `ThreatActorIntelContainer._uow_for`'s precedent.
        return SqlAlchemyUnitOfWork(lambda: session)  # type: ignore[arg-type]

    def build_service(self, session: AsyncSession) -> IOCApplicationService:
        evidence_validator = InfrastructureEvidenceValidationAdapter(
            SqlAlchemyEvidenceEntityExistenceService(session)
        )
        return IOCApplicationService(
            uow_factory=lambda: self._uow_for(session),
            event_publisher=self.event_publisher,
            evidence_validator=evidence_validator,
        )

    def build_ingestion_orchestrator(self, session: AsyncSession) -> IocIngestionOrchestrator:
        """Session-scoped per call, same discipline as `build_service` —
        the legacy ACL adapters below all read through this exact
        session, and `IOCApplicationService`'s own `uow_factory`
        (built by `build_service`) reuses the same session too, so a
        single job/request never opens more than one connection."""
        return IocIngestionOrchestrator(
            ioc_service=self.build_service(session),
            legacy_observation_port=SqlAlchemyLegacyIocObservationAdapter(session),
            enrichment_port=SqlAlchemyIocEnrichmentQueryAdapter(session),
            correlation_port=SqlAlchemyIocCorrelationQueryAdapter(session),
        )
