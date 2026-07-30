"""RiskEngineContainer — M48F composition root for risk_engine's
application services.

Mirrors `operation.infrastructure.container.OperationContainer`'s
shape (holds a `session_factory` + `event_publisher`, wired at
application startup and stored on `app.state`), with one deliberate
per-request difference driven by the already-frozen (M48C)
application-service constructors: every risk_engine service takes an
already-bound *repository instance* (e.g.
``EnterpriseRiskProfileApplicationService(repository, unit_of_work)``)
rather than a repository *factory*, unlike `operation`'s services
which take a `uow_factory` and open a fresh session per call
internally. Because a repository instance is bound to one
`AsyncSession`, a single process-lifetime service instance cannot
safely be shared across concurrent requests/tenants the way
`OperationContainer.operation_service` is. This container therefore
exposes ``build_*`` methods that construct fresh, session-scoped
service instances per call, invoked once per HTTP request by
`risk_engine.api.dependencies` — the container itself remains the one
long-lived, `app.state`-held composition root, matching every mature
context's registration pattern; only the granularity of what it hands
out differs, and only because the frozen service contracts require it.
This is a DI-wiring judgment call, not an architecture change: no
aggregate boundary, ownership, or domain model is touched.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from risk_engine.application.services.enterprise_risk_profile_service import (
    EnterpriseRiskProfileApplicationService,
)
from risk_engine.application.services.risk_correlation_application_service import (
    RiskCorrelationApplicationService,
)
from risk_engine.application.services.risk_query_service import RiskQueryService
from risk_engine.application.services.risk_timeline_service import RiskTimelineApplicationService
from risk_engine.infrastructure.events.structlog_event_publisher import StructlogEventPublisher
from risk_engine.infrastructure.persistence.repositories.pg_risk_correlation_repository import (
    PgRiskCorrelationRepository,
)
from risk_engine.infrastructure.persistence.repositories.pg_risk_profile_repository import (
    PgEnterpriseRiskProfileRepository,
)
from risk_engine.infrastructure.persistence.unit_of_work import SqlAlchemyUnitOfWork

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from risk_engine.application.ports.i_event_publisher import IEventPublisher


class RiskEngineContainer:
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
        # required so that a service's directly-injected `repository`
        # and its `unit_of_work.risk_profiles`/`.correlation_sets`
        # operate against the same transaction, exactly as the fake
        # test doubles in `tests/risk_engine/application/conftest.py`
        # share one in-memory store between the two.
        # `SqlAlchemyUnitOfWork.__init__` is typed to accept an
        # `async_sessionmaker[AsyncSession]` (its normal, production
        # entry point), but only ever calls it as a zero-arg callable
        # returning an `AsyncSession` — a plain closure satisfies that
        # at runtime. Frozen infrastructure file; not modified here.
        return SqlAlchemyUnitOfWork(lambda: session)  # type: ignore[arg-type]

    def build_profile_service(
        self, session: AsyncSession
    ) -> EnterpriseRiskProfileApplicationService:
        repository = PgEnterpriseRiskProfileRepository(session)
        return EnterpriseRiskProfileApplicationService(repository, self._uow_for(session))

    def build_query_service(self, session: AsyncSession) -> RiskQueryService:
        return RiskQueryService(
            PgEnterpriseRiskProfileRepository(session),
            PgRiskCorrelationRepository(session),
        )

    def build_timeline_service(self, session: AsyncSession) -> RiskTimelineApplicationService:
        return RiskTimelineApplicationService(PgEnterpriseRiskProfileRepository(session))

    def build_correlation_service(self, session: AsyncSession) -> RiskCorrelationApplicationService:
        return RiskCorrelationApplicationService(
            PgRiskCorrelationRepository(session),
            PgEnterpriseRiskProfileRepository(session),
            self._uow_for(session),
            self.build_profile_service(session),
            self.build_timeline_service(session),
        )
