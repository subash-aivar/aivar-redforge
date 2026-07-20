"""OperatorApplicationService tests with in-memory fake UoW."""

from __future__ import annotations

from uuid import uuid4

import pytest
from tests.red_team_operator.fakes.repos import (
    FakeEventPublisher,
    FakeOperatorUnitOfWork,
    InMemoryOperatorRepository,
)

from red_team_operator.application.commands.operator_commands import (
    ActivateOperatorCommand,
    GrantApprovalAuthorityCommand,
    SuspendOperatorCommand,
)
from red_team_operator.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from red_team_operator.application.services.operator_application_service import (
    OperatorApplicationService,
)
from red_team_operator.domain.exceptions.domain_exceptions import OperatorNotAuthorized
from red_team_operator.domain.value_objects.enums import (
    ImpactCeiling,
    OperatorClearanceLevel,
    OperatorState,
)
from red_team_operator.domain.value_objects.identifiers import TenantId


@pytest.fixture
def repo() -> InMemoryOperatorRepository:
    return InMemoryOperatorRepository()


@pytest.fixture
def publisher() -> FakeEventPublisher:
    return FakeEventPublisher()


@pytest.fixture
def service(
    repo: InMemoryOperatorRepository, publisher: FakeEventPublisher
) -> OperatorApplicationService:
    def uow_factory() -> FakeOperatorUnitOfWork:
        return FakeOperatorUnitOfWork(repo)

    return OperatorApplicationService(uow_factory=uow_factory, event_publisher=publisher)


@pytest.mark.asyncio
async def test_activate_operator(service: OperatorApplicationService) -> None:
    tenant = uuid4()
    dto = await service.activate_operator(
        ActivateOperatorCommand(
            tenant_id=tenant,
            identity_ref="bob@aivar.io",
            clearance_level="L3",
            approval_scopes=["EngagementApproval"],
        )
    )
    assert dto.state == OperatorState.ACTIVE.value
    assert dto.clearance_level == OperatorClearanceLevel.L3.value
    assert dto.max_impact_ceiling == ImpactCeiling.EXPLOIT.value


@pytest.mark.asyncio
async def test_suspended_operator_cannot_grant_authority(
    service: OperatorApplicationService,
) -> None:
    tenant = uuid4()
    dto = await service.activate_operator(
        ActivateOperatorCommand(
            tenant_id=tenant,
            identity_ref="carol@aivar.io",
            clearance_level="L3",
            approval_scopes=[],
        )
    )
    await service.suspend_operator(
        SuspendOperatorCommand(
            tenant_id=tenant,
            operator_id=dto.operator_id,
            reason="policy hold",
            authority="ciso",
        )
    )
    with pytest.raises(OperatorNotAuthorized):
        await service.grant_approval_authority(
            GrantApprovalAuthorityCommand(
                tenant_id=tenant,
                operator_id=dto.operator_id,
                scope="EngagementApproval",
            )
        )


@pytest.mark.asyncio
async def test_cross_tenant_load_not_found(
    service: OperatorApplicationService,
) -> None:
    tenant = uuid4()
    dto = await service.activate_operator(
        ActivateOperatorCommand(
            tenant_id=tenant,
            identity_ref="dave@aivar.io",
            clearance_level="L2",
        )
    )
    with pytest.raises(ApplicationNotFoundError):
        await service.suspend_operator(
            SuspendOperatorCommand(
                tenant_id=uuid4(),
                operator_id=dto.operator_id,
                reason="x",
                authority="y",
            )
        )


@pytest.mark.asyncio
async def test_l1_cannot_activate_with_approval_scope(
    service: OperatorApplicationService,
) -> None:
    with pytest.raises(ApplicationValidationError):
        await service.activate_operator(
            ActivateOperatorCommand(
                tenant_id=uuid4(),
                identity_ref="l1@aivar.io",
                clearance_level="L1",
                approval_scopes=["OperationApproval"],
            )
        )


@pytest.mark.asyncio
async def test_repo_find_authorized_approvers(repo: InMemoryOperatorRepository) -> None:
    from datetime import UTC, datetime

    from tests.red_team_operator.conftest import make_operator

    from red_team_operator.domain.value_objects.enums import ApprovalScope

    tenant = TenantId(uuid4())
    now = datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC)
    op = make_operator(tenant_id=tenant, now=now, pop_events=True)
    await repo.save(op)
    found = await repo.find_authorized_approvers(ApprovalScope.ENGAGEMENT_APPROVAL, tenant)
    assert len(found) == 1
    assert found[0].operator_id == op.operator_id
