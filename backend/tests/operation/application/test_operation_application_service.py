"""OperationApplicationService tests with fake UoW and engagement port."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from tests.operation.fakes.repos import (
    FakeEngagementQueryPort,
    FakeEventPublisher,
    FakeOperationUnitOfWork,
    FakeVulnerabilityQueryPort,
    InMemoryOperationRepository,
    InMemoryPlanVersionRepository,
)

from operation.application.commands.operation_commands import (
    AddExecutionStep,
    AddStepDependency,
    ApproveOperation,
    CreateOperation,
    QueueOperation,
    SignExecutionPlan,
    SubmitOperationForApproval,
    ValidateExecutionPlan,
)
from operation.application.services.operation_application_service import (
    OperationApplicationService,
)
from operation.domain.aggregates.execution_plan_version import ExecutionPlanVersion
from operation.domain.exceptions.domain_exceptions import (
    ConcurrentExecutingPlanError,
    EngagementNotActive,
    PlanValidationError,
)
from operation.domain.value_objects.enums import (
    ExecutionPlanVersionState,
    OperationState,
)
from operation.domain.value_objects.identifiers import OperationId, TenantId
from operation.domain.value_objects.plan_vos import PlanSnapshot


@pytest.fixture
def asset_id() -> UUID:
    return uuid4()


@pytest.fixture
def ops_repo() -> InMemoryOperationRepository:
    return InMemoryOperationRepository()


@pytest.fixture
def plans_repo() -> InMemoryPlanVersionRepository:
    return InMemoryPlanVersionRepository()


@pytest.fixture
def engagement_port(asset_id: UUID) -> FakeEngagementQueryPort:
    return FakeEngagementQueryPort(
        state="Active",
        active=True,
        targets={asset_id},
        techniques={"T1059"},
    )


@pytest.fixture
def service(
    ops_repo: InMemoryOperationRepository,
    plans_repo: InMemoryPlanVersionRepository,
    engagement_port: FakeEngagementQueryPort,
) -> OperationApplicationService:
    publisher = FakeEventPublisher()

    def uow_factory() -> FakeOperationUnitOfWork:
        return FakeOperationUnitOfWork(ops_repo, plans_repo)

    return OperationApplicationService(
        uow_factory=uow_factory,
        event_publisher=publisher,
        engagement_query=engagement_port,
        vulnerability_query=FakeVulnerabilityQueryPort(),
    )


async def _create_simple_probe_plan(
    service: OperationApplicationService,
    *,
    tenant_id: UUID,
    asset_id: UUID,
) -> UUID:
    created = await service.create_operation(
        CreateOperation(
            tenant_id=tenant_id,
            engagement_id=uuid4(),
            name="Plan Op",
            classification="InitialAccess",
        )
    )
    oid = UUID(created.id)
    await service.add_execution_step(
        AddExecutionStep(
            tenant_id=tenant_id,
            operation_id=oid,
            name="attack-1",
            step_type="AttackStep",
            max_duration_seconds=120,
            technique_payload_id="p1",
            technique_id="T1059",
            target_asset_id=asset_id,
            impact_ceiling="Probe",
        )
    )
    return oid


@pytest.mark.asyncio
async def test_create_operation(service: OperationApplicationService) -> None:
    dto = await service.create_operation(
        CreateOperation(
            tenant_id=uuid4(),
            engagement_id=uuid4(),
            name="Recon",
            classification="Reconnaissance",
        )
    )
    assert dto.state == OperationState.PLANNING.value
    assert dto.name == "Recon"


@pytest.mark.asyncio
async def test_out_of_scope_blocks_validate(
    service: OperationApplicationService, asset_id: UUID
) -> None:
    tenant = uuid4()
    created = await service.create_operation(
        CreateOperation(
            tenant_id=tenant,
            engagement_id=uuid4(),
            name="Bad Scope",
            classification="Execution",
        )
    )
    oid = UUID(created.id)
    await service.add_execution_step(
        AddExecutionStep(
            tenant_id=tenant,
            operation_id=oid,
            name="attack",
            step_type="AttackStep",
            max_duration_seconds=60,
            technique_payload_id="p1",
            technique_id="T1059",
            target_asset_id=uuid4(),
            impact_ceiling="Probe",
        )
    )
    with pytest.raises(PlanValidationError):
        await service.validate_execution_plan(
            ValidateExecutionPlan(tenant_id=tenant, operation_id=oid)
        )


@pytest.mark.asyncio
async def test_unauthorized_technique_blocks_sign(
    service: OperationApplicationService,
    engagement_port: FakeEngagementQueryPort,
    asset_id: UUID,
) -> None:
    tenant = uuid4()
    oid = await _create_simple_probe_plan(service, tenant_id=tenant, asset_id=asset_id)
    engagement_port.techniques = {"T1021"}
    with pytest.raises(PlanValidationError, match="not authorized"):
        await service.sign_execution_plan(
            SignExecutionPlan(
                tenant_id=tenant,
                operation_id=oid,
                operator_id=uuid4(),
                signature="sig",
            )
        )


@pytest.mark.asyncio
async def test_sign_computes_plan_hash(
    service: OperationApplicationService, asset_id: UUID
) -> None:
    tenant = uuid4()
    oid = await _create_simple_probe_plan(service, tenant_id=tenant, asset_id=asset_id)
    signed = await service.sign_execution_plan(
        SignExecutionPlan(
            tenant_id=tenant,
            operation_id=oid,
            operator_id=uuid4(),
            signature="plan-sig",
        )
    )
    assert signed.state == ExecutionPlanVersionState.SIGNED.value
    assert signed.plan_hash is not None
    assert len(signed.plan_hash) == 64


@pytest.mark.asyncio
async def test_queue_requires_active_engagement(
    service: OperationApplicationService,
    engagement_port: FakeEngagementQueryPort,
    asset_id: UUID,
) -> None:
    tenant = uuid4()
    oid = await _create_simple_probe_plan(service, tenant_id=tenant, asset_id=asset_id)
    await service.submit_for_approval(
        SubmitOperationForApproval(tenant_id=tenant, operation_id=oid)
    )
    await service.approve_operation(
        ApproveOperation(
            tenant_id=tenant,
            operation_id=oid,
            operator_id=uuid4(),
            authority="Lead",
            signature="ok",
        )
    )
    engagement_port.active = False
    engagement_port.state = "Suspended"
    with pytest.raises(EngagementNotActive):
        await service.queue_operation(QueueOperation(tenant_id=tenant, operation_id=oid))


@pytest.mark.asyncio
async def test_only_one_executing_plan_per_operation(
    service: OperationApplicationService,
    plans_repo: InMemoryPlanVersionRepository,
    asset_id: UUID,
) -> None:
    tenant = uuid4()
    oid = await _create_simple_probe_plan(service, tenant_id=tenant, asset_id=asset_id)
    signed = await service.sign_execution_plan(
        SignExecutionPlan(
            tenant_id=tenant,
            operation_id=oid,
            operator_id=uuid4(),
            signature="sig-1",
        )
    )
    await service.mark_plan_executing(
        tenant_id=tenant, plan_version_id=UUID(signed.id)
    )

    now = datetime.now(UTC)
    other = ExecutionPlanVersion.create_draft(
        tenant_id=TenantId(tenant),
        operation_id=OperationId(oid),
        version_number=99,
        snapshot=PlanSnapshot('{"steps":[]}'),
        now=now,
    )
    other.sign(tenant_id=TenantId(tenant), operator_id=uuid4(), signature="x", now=now)
    other.pop_events()
    await plans_repo.save(other)

    with pytest.raises(ConcurrentExecutingPlanError):
        await service.mark_plan_executing(
            tenant_id=tenant, plan_version_id=other.plan_version_id.value
        )


@pytest.mark.asyncio
async def test_critical_two_party_via_app_service(
    service: OperationApplicationService,
) -> None:
    tenant = uuid4()
    created = await service.create_operation(
        CreateOperation(
            tenant_id=tenant,
            engagement_id=uuid4(),
            name="Critical Op",
            classification="Impact",
        )
    )
    oid = UUID(created.id)
    await service.add_execution_step(
        AddExecutionStep(
            tenant_id=tenant,
            operation_id=oid,
            name="destruct",
            step_type="AttackStep",
            max_duration_seconds=60,
            impact_ceiling="Destruct",
        )
    )
    await service.submit_for_approval(
        SubmitOperationForApproval(tenant_id=tenant, operation_id=oid)
    )
    mid = await service.approve_operation(
        ApproveOperation(
            tenant_id=tenant,
            operation_id=oid,
            operator_id=uuid4(),
            authority="CISO",
            signature="a",
        )
    )
    assert mid.state == OperationState.PENDING_OPERATION_APPROVAL.value
    done = await service.approve_operation(
        ApproveOperation(
            tenant_id=tenant,
            operation_id=oid,
            operator_id=uuid4(),
            authority="CISO",
            signature="b",
        )
    )
    assert done.state == OperationState.APPROVED.value


@pytest.mark.asyncio
async def test_mutating_plan_with_verification_validates(
    service: OperationApplicationService, asset_id: UUID
) -> None:
    tenant = uuid4()
    created = await service.create_operation(
        CreateOperation(
            tenant_id=tenant,
            engagement_id=uuid4(),
            name="Mutate Op",
            classification="Persistence",
        )
    )
    oid = UUID(created.id)
    attack = await service.add_execution_step(
        AddExecutionStep(
            tenant_id=tenant,
            operation_id=oid,
            name="persist",
            step_type="AttackStep",
            max_duration_seconds=60,
            technique_payload_id="p1",
            technique_id="T1059",
            target_asset_id=asset_id,
            impact_ceiling="Probe",
            modifies_persistent_state=True,
        )
    )
    attack_id = UUID(next(s.id for s in attack.steps if s.name == "persist"))
    verified = await service.add_execution_step(
        AddExecutionStep(
            tenant_id=tenant,
            operation_id=oid,
            name="verify",
            step_type="VerificationStep",
            max_duration_seconds=60,
        )
    )
    verify_id = UUID(next(s.id for s in verified.steps if s.name == "verify"))
    await service.add_step_dependency(
        AddStepDependency(
            tenant_id=tenant,
            operation_id=oid,
            from_step_id=attack_id,
            to_step_id=verify_id,
        )
    )
    result = await service.validate_execution_plan(
        ValidateExecutionPlan(tenant_id=tenant, operation_id=oid)
    )
    assert result.valid is True
