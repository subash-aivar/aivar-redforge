"""ThreatActorIntelContainer — M51.1 composition root, mirroring
`risk_engine.infrastructure.container.RiskEngineContainer`'s shape:
holds a `session_factory` + `event_publisher`, wired at application
startup and stored on `app.state`. `build_service` constructs a
fresh, session-scoped `ThreatActorApplicationService` per call,
matching `RiskEngineContainer.build_profile_service`'s per-request
pattern — required because a repository instance (and, as of Phase
4.5, the real evidence-existence adapter too) is bound to one
`AsyncSession` and cannot safely be shared across concurrent
requests/tenants.

Phase 4.5: `evidence_validator` is no longer a container-level
singleton — `InfrastructureEvidenceValidationAdapter` now depends on
a real, session-bound `SqlAlchemyEvidenceEntityExistenceService`
(from `redforge.application.evidence_existence`), so it must be built
per-request from the same session as everything else, exactly like
`threat_actors`/`associations`. Production DI never uses a seeded
allow-list here — only test doubles do, and only inside `tests/`."""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.application.evidence_existence.sqlalchemy_evidence_entity_existence_service import (
    SqlAlchemyEvidenceEntityExistenceService,
)
from threat_actor_intel.application.services.threat_actor_application_service import (
    ThreatActorApplicationService,
)
from threat_actor_intel.infrastructure.acl.infrastructure_evidence_validation_adapter import (
    InfrastructureEvidenceValidationAdapter,
)
from threat_actor_intel.infrastructure.events.structlog_event_publisher import (
    StructlogEventPublisher,
)
from threat_actor_intel.infrastructure.persistence.unit_of_work import SqlAlchemyUnitOfWork

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from threat_actor_intel.application.ports.i_event_publisher import IEventPublisher


class ThreatActorIntelContainer:
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
        # matches `RiskEngineContainer._uow_for`'s precedent exactly.
        return SqlAlchemyUnitOfWork(lambda: session)  # type: ignore[arg-type]

    def build_service(self, session: AsyncSession) -> ThreatActorApplicationService:
        evidence_validator = InfrastructureEvidenceValidationAdapter(
            SqlAlchemyEvidenceEntityExistenceService(session)
        )
        return ThreatActorApplicationService(
            uow_factory=lambda: self._uow_for(session),
            event_publisher=self.event_publisher,
            evidence_validator=evidence_validator,
        )
