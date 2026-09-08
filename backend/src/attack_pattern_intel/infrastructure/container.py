"""AttackPatternIntelContainer — M51.3 Phase B1 composition root,
mirroring `ioc_intelligence.infrastructure.container.
IocIntelContainer`'s shape: holds a `session_factory` +
`event_publisher`, wired at application startup. `build_service`
constructs a fresh, session-scoped service per call — a repository
instance (and the real ACL adapter instance) is bound to one
`AsyncSession` and cannot safely be shared across concurrent
requests/tenants."""

from __future__ import annotations

from typing import TYPE_CHECKING

from attack_pattern_intel.application.services.attack_pattern_application_service import (
    AttackPatternApplicationService,
)
from attack_pattern_intel.infrastructure.acl.mitre_technique_identity_adapter import (
    SqlAlchemyMitreTechniqueIdentityAdapter,
)
from attack_pattern_intel.infrastructure.events.structlog_event_publisher import (
    StructlogEventPublisher,
)
from attack_pattern_intel.infrastructure.persistence.unit_of_work import SqlAlchemyUnitOfWork

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from attack_pattern_intel.application.ports.i_event_publisher import IEventPublisher


class AttackPatternIntelContainer:
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

    def build_service(self, session: AsyncSession) -> AttackPatternApplicationService:
        mitre_identity_port = SqlAlchemyMitreTechniqueIdentityAdapter(session)
        return AttackPatternApplicationService(
            uow_factory=lambda: self._uow_for(session),
            event_publisher=self.event_publisher,
            mitre_identity_port=mitre_identity_port,
        )
