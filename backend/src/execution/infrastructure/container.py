"""ExecutionContainer — wires application services and adapters."""

from __future__ import annotations

from typing import TYPE_CHECKING

from execution.application.services.execution_application_service import (
    ExecutionApplicationService,
)
from execution.domain.repositories.i_repositories import IExecutionWorkerRepository
from execution.domain.services.execution_authorization_service import (
    ExecutionAuthorizationService,
)
from execution.domain.services.execution_window_service import ExecutionWindowService
from execution.domain.services.kill_switch_evaluation_service import (
    KillSwitchEvaluationService,
)
from execution.domain.services.rate_limit_evaluation_service import (
    RateLimitEvaluationService,
)
from execution.domain.services.scope_verification_service import ScopeVerificationService
from execution.domain.services.worker_assignment_service import WorkerAssignmentService
from execution.domain.services.worker_capability_verification_service import (
    WorkerCapabilityVerificationService,
)
from execution.infrastructure.acl.degraded_adapters import (
    DegradedEngagementScopeAdapter,
    DegradedPayloadQueryAdapter,
)
from execution.infrastructure.events.structlog_event_publisher import StructlogEventPublisher
from execution.infrastructure.persistence.unit_of_work import make_execution_uow_factory
from execution.infrastructure.redis.in_memory_kill_switch_store import InMemoryKillSwitchStore
from execution.infrastructure.redis.in_memory_rate_limit_store import InMemoryRateLimitStore
from execution.infrastructure.technique.in_memory_dispatcher import InMemoryTechniqueDispatcher

if TYPE_CHECKING:
    from collections.abc import Callable

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from execution.application.ports.i_unit_of_work import IEventPublisher, IUnitOfWork
    from execution.domain.aggregates.execution_worker import ExecutionWorker
    from execution.domain.aggregates.kill_switch_state import KillSwitchState
    from execution.domain.ports.i_engagement_scope_port import IEngagementScopePort
    from execution.domain.ports.i_kill_switch_store import IKillSwitchStore
    from execution.domain.ports.i_payload_query_port import IPayloadQueryPort
    from execution.domain.ports.i_rate_limit_store import IRateLimitStore
    from execution.domain.ports.i_technique_execution_port import ITechniqueExecutionPort
    from execution.domain.value_objects.identifiers import (
        ExecutionWorkerId,
        TenantId,
    )


class _LazyWorkerRepository(IExecutionWorkerRepository):
    """Opens a short-lived UoW to query workers without holding an outer session."""

    def __init__(self, uow_factory: Callable[[], IUnitOfWork]) -> None:
        self._uow_factory = uow_factory

    async def save(self, worker: ExecutionWorker) -> None:
        async with self._uow_factory() as uow:
            await uow.workers.save(worker)
            await uow.commit()

    async def find_by_id(
        self, worker_id: ExecutionWorkerId, tenant_id: TenantId
    ) -> ExecutionWorker | None:
        async with self._uow_factory() as uow:
            return await uow.workers.find_by_id(worker_id, tenant_id)

    async def find_available_by_capability(
        self,
        tenant_id: TenantId,
        technique_id: str,
        network_zone: str | None = None,
    ) -> list[ExecutionWorker]:
        async with self._uow_factory() as uow:
            return await uow.workers.find_available_by_capability(
                tenant_id, technique_id, network_zone
            )

    async def list_available(
        self,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ExecutionWorker]:
        async with self._uow_factory() as uow:
            return await uow.workers.list_available(tenant_id, limit=limit, offset=offset)


class ExecutionContainer:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        event_publisher: IEventPublisher | None = None,
        *,
        engagement_scope: IEngagementScopePort | None = None,
        kill_switch_store: IKillSwitchStore | None = None,
        rate_limit_store: IRateLimitStore | None = None,
        technique_port: ITechniqueExecutionPort | None = None,
        payload_query: IPayloadQueryPort | None = None,
    ) -> None:
        self._session_factory = session_factory
        self.event_publisher: IEventPublisher = event_publisher or StructlogEventPublisher()
        self.engagement_scope = engagement_scope or DegradedEngagementScopeAdapter()
        self.kill_switch_store = kill_switch_store or InMemoryKillSwitchStore()
        self.rate_limit_store = rate_limit_store or InMemoryRateLimitStore()
        self.technique_port = technique_port or InMemoryTechniqueDispatcher()
        self.payload_query = payload_query or DegradedPayloadQueryAdapter()

        kill_eval = KillSwitchEvaluationService(self.kill_switch_store)
        scope_svc = ScopeVerificationService(self.engagement_scope)
        rate_svc = RateLimitEvaluationService(self.rate_limit_store)
        capability = WorkerCapabilityVerificationService()
        authorization = ExecutionAuthorizationService(
            kill_eval,
            scope_svc,
            rate_svc,
            ExecutionWindowService(),
            capability,
        )
        uow_factory = make_execution_uow_factory(session_factory)
        worker_assignment = WorkerAssignmentService(
            _LazyWorkerRepository(uow_factory),
            capability,
        )

        async def _sync_ks(ks: KillSwitchState) -> None:
            await self.kill_switch_store.set_state(ks)

        self.execution_service = ExecutionApplicationService(
            uow_factory,
            self.event_publisher,
            authorization,
            worker_assignment,
            self.technique_port,
            kill_switch_store_sync=_sync_ks,
            payload_query=self.payload_query,
        )

        # M29 Phase 6 — projections, detection correlation, journal replay.
        from engagement.infrastructure.graph import (
            InMemorySecurityGraphWriteAdapter as EngagementGraphAdapter,
        )
        from execution.application.projections.projection_coordinator import (
            ProjectionCoordinator,
        )
        from execution.application.projections.projection_publisher import (
            ProjectionPublisher,
        )
        from execution.application.projections.read_model_store import (
            InMemoryReadModelStore,
        )
        from execution.application.projections.red_team_projection_service import (
            RedTeamProjectionService,
        )
        from execution.application.services.detection_correlation_service import (
            DetectionCorrelationService,
        )
        from execution.application.services.projection_application_service import (
            ProjectionApplicationService,
        )
        from execution.application.services.replay_application_service import (
            ReplayApplicationService,
        )
        from execution.infrastructure.graph import InMemorySecurityGraphWriteAdapter
        from operation.infrastructure.graph import (
            InMemorySecurityGraphWriteAdapter as OperationGraphAdapter,
        )

        self.read_model_store = InMemoryReadModelStore()
        self.projection_publisher = ProjectionPublisher()
        self.graph_port = InMemorySecurityGraphWriteAdapter()
        self.engagement_graph_port = EngagementGraphAdapter()
        self.operation_graph_port = OperationGraphAdapter()
        self.projection_coordinator = ProjectionCoordinator(
            self.projection_publisher,
            RedTeamProjectionService(self.read_model_store),
            self.graph_port,
            engagement_graph=self.engagement_graph_port,
            operation_graph=self.operation_graph_port,
        )
        self.correlation_service = DetectionCorrelationService(
            self.projection_coordinator, self.graph_port
        )
        self.replay_service = ReplayApplicationService(uow_factory)
        self.projection_service = ProjectionApplicationService(
            self.projection_coordinator,
            self.read_model_store,
            correlation=self.correlation_service,
            replay=self.replay_service,
        )
