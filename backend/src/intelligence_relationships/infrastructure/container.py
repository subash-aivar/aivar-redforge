"""IntelligenceRelationshipsContainer — M51.4 Phase C1 composition
root, mirroring `attack_pattern_intel.infrastructure.container.
AttackPatternIntelContainer`'s shape: holds a `session_factory` +
`event_publisher`, wired at application startup. `build_service`
constructs a fresh, session-scoped service per call — a repository
instance (and each real ACL adapter instance) is bound to one
`AsyncSession` and cannot safely be shared across concurrent
requests/tenants."""

from __future__ import annotations

from typing import TYPE_CHECKING

from intelligence_relationships.application.services.relationship_application_service import (
    IntelligenceRelationshipApplicationService,
)
from intelligence_relationships.infrastructure.acl.attack_pattern_identity_adapter import (
    SqlAlchemyAttackPatternIdentityAdapter,
)
from intelligence_relationships.infrastructure.acl.ioc_identity_adapter import (
    SqlAlchemyIocIdentityAdapter,
)
from intelligence_relationships.infrastructure.acl.threat_actor_identity_adapter import (
    SqlAlchemyThreatActorIdentityAdapter,
)
from intelligence_relationships.infrastructure.events.structlog_event_publisher import (
    StructlogEventPublisher,
)
from intelligence_relationships.infrastructure.persistence.unit_of_work import (
    SqlAlchemyUnitOfWork,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from intelligence_relationships.application.ports.i_event_publisher import IEventPublisher


class IntelligenceRelationshipsContainer:
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

    def build_service(self, session: AsyncSession) -> IntelligenceRelationshipApplicationService:
        return IntelligenceRelationshipApplicationService(
            uow_factory=lambda: self._uow_for(session),
            event_publisher=self.event_publisher,
            ioc_identity_port=SqlAlchemyIocIdentityAdapter(session),
            threat_actor_identity_port=SqlAlchemyThreatActorIdentityAdapter(session),
            attack_pattern_identity_port=SqlAlchemyAttackPatternIdentityAdapter(session),
        )
