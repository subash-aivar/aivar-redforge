"""AttackSurfaceManagementContainer — M49D composition root for
attack_surface_management's application services.

Mirrors `risk_engine.infrastructure.container.RiskEngineContainer`
exactly, including its per-request wiring judgment call: the M49B
application services (`AssetApplicationService`,
`NetworkRangeApplicationService`) are constructed with an already-bound
*repository instance* + a session-scoped `SqlAlchemyUnitOfWork`, rather
than a repository/uow *factory*. Because a repository instance is bound
to one `AsyncSession`, a single process-lifetime service instance
cannot safely be shared across concurrent requests/tenants. This
container therefore exposes ``build_*`` methods that construct fresh,
session-scoped service instances per call, invoked once per HTTP
request by `attack_surface_management.api.dependencies` — the
container itself remains the one long-lived, `app.state`-held
composition root, matching every mature context's registration
pattern; only the granularity of what it hands out differs, and only
because the frozen (M49B) service contracts require it. This is a
DI-wiring judgment call, not an architecture change."""

from __future__ import annotations

from typing import TYPE_CHECKING

from attack_surface_management.application.services.asset_application_service import (
    AssetApplicationService,
)
from attack_surface_management.application.services.attack_surface_query_service import (
    AttackSurfaceQueryService,
)
from attack_surface_management.application.services.network_range_application_service import (
    NetworkRangeApplicationService,
)
from attack_surface_management.infrastructure.events.structlog_event_publisher import (
    StructlogEventPublisher,
)
from attack_surface_management.infrastructure.persistence.repositories.pg_asset_repository import (
    PgAssetRepository,
)
from attack_surface_management.infrastructure.persistence.repositories.pg_network_range_repository import (  # noqa: E501
    PgNetworkRangeRepository,
)
from attack_surface_management.infrastructure.persistence.unit_of_work import (
    SqlAlchemyUnitOfWork,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from attack_surface_management.application.ports.i_event_publisher import IEventPublisher


class AttackSurfaceManagementContainer:
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
        # Wraps the already-open, request-scoped `session` in a zero-arg
        # callable so `SqlAlchemyUnitOfWork.__aenter__` reuses it rather
        # than opening a second, disconnected session — required so a
        # service's directly-injected `repository` and its
        # `unit_of_work.assets`/`.network_ranges` operate against the
        # same transaction. `SqlAlchemyUnitOfWork.__init__` is typed to
        # accept an `async_sessionmaker[AsyncSession]` (its normal,
        # production entry point) but only ever calls it as a zero-arg
        # callable returning an `AsyncSession` — a plain closure
        # satisfies that at runtime. Frozen infrastructure file; not
        # modified here. Matches
        # `RiskEngineContainer._uow_for` exactly.
        return SqlAlchemyUnitOfWork(lambda: session)  # type: ignore[arg-type]

    def build_asset_service(self, session: AsyncSession) -> AssetApplicationService:
        repository = PgAssetRepository(session)
        return AssetApplicationService(repository, self._uow_for(session))

    def build_network_range_service(self, session: AsyncSession) -> NetworkRangeApplicationService:
        repository = PgNetworkRangeRepository(session)
        return NetworkRangeApplicationService(repository, self._uow_for(session))

    def build_query_service(self, session: AsyncSession) -> AttackSurfaceQueryService:
        return AttackSurfaceQueryService(
            PgAssetRepository(session),
            PgNetworkRangeRepository(session),
        )
