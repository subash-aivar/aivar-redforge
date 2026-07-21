"""Dependency injection container for campaignexecution context."""

from __future__ import annotations

from typing import TYPE_CHECKING

from campaignexecution.infrastructure.acl.degraded_adapters import (
    StubAttackActionQueryAdapter,
    StubOperationCreationAdapter,
)
from campaignexecution.infrastructure.events.structlog_event_publisher import (
    StructlogEventPublisher,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from sqlalchemy.ext.asyncio import AsyncSession

    from campaignexecution.application.services.execution_application_service import (
        ExecutionApplicationService,
    )
    from campaignexecution.domain.ports.i_attack_action_query_port import (
        IAttackActionQueryPort,
    )
    from campaignexecution.domain.ports.i_operation_creation_port import (
        IOperationCreationPort,
    )
    from campaignexecution.infrastructure.persistence.unit_of_work import PgUnitOfWork


def build_execution_application_service(
    session_factory: Callable[[], AsyncSession],
    operation_creation_port: IOperationCreationPort | None = None,
    attack_action_query_port: IAttackActionQueryPort | None = None,
) -> ExecutionApplicationService:
    """Build the ExecutionApplicationService with production or stub adapters.

    In production, pass real M29-backed ports.
    In development/testing, stub adapters are used.
    """
    from campaignexecution.application.services.execution_application_service import (
        ExecutionApplicationService,
    )
    from campaignexecution.infrastructure.persistence.unit_of_work import PgUnitOfWork

    op_port: IOperationCreationPort = (
        operation_creation_port or StubOperationCreationAdapter()
    )
    action_port: IAttackActionQueryPort = (
        attack_action_query_port or StubAttackActionQueryAdapter()
    )
    publisher = StructlogEventPublisher()

    def uow_factory() -> PgUnitOfWork:
        session: AsyncSession = session_factory()
        return PgUnitOfWork(session)

    return ExecutionApplicationService(
        uow_factory=uow_factory,
        event_publisher=publisher,
        operation_creation_port=op_port,
        attack_action_query_port=action_port,
    )
