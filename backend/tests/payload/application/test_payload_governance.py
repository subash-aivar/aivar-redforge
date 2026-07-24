"""Payload application tests — approve, revoke, CISO, hash, plan invalidation."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid7

import pytest

from payload.application.commands.payload_commands import (
    ApprovePayload,
    PublishPayloadVersion,
    RegisterPayload,
    RevokePayload,
    VerifyPayloadHash,
)
from payload.application.exceptions import (
    ApplicationConflictError,
    ApplicationIntegrityError,
)
from payload.application.ports.i_unit_of_work import IEventPublisher, IUnitOfWork
from payload.application.services.payload_application_service import (
    PayloadApplicationService,
)
from payload.domain.aggregates.payload import Payload
from payload.domain.aggregates.plugin_registration import PluginRegistration
from payload.domain.ports.i_plan_invalidation_port import IPlanInvalidationPort
from payload.domain.value_objects.identifiers import PayloadId, PluginId, TenantId
from payload.domain.value_objects.payload_vos import PayloadKey
from payload.infrastructure.acl.operation_plan_invalidation_adapter import (
    DegradedPlanInvalidationAdapter,
)

if TYPE_CHECKING:
    from payload.domain.events.base import BaseDomainEvent


class InMemoryPayloadRepository:
    def __init__(self) -> None:
        self.by_id: dict[str, Payload] = {}
        self.by_key: dict[str, Payload] = {}

    async def save(self, payload: Payload) -> None:
        self.by_id[str(payload.payload_id)] = payload
        self.by_key[f"{payload.tenant_id}:{payload.payload_key.value}"] = payload

    async def find_by_id(
        self, payload_id: PayloadId, tenant_id: TenantId
    ) -> Payload | None:
        p = self.by_id.get(str(payload_id))
        if p is None or p.tenant_id != tenant_id:
            return None
        return p

    async def find_by_key(
        self, payload_key: PayloadKey, tenant_id: TenantId
    ) -> Payload | None:
        return self.by_key.get(f"{tenant_id}:{payload_key.value}")

    async def list_by_tenant(
        self, tenant_id: TenantId, *, limit: int = 100, offset: int = 0
    ) -> list[Payload]:
        items = [p for p in self.by_id.values() if p.tenant_id == tenant_id]
        return items[offset : offset + limit]


class InMemoryPluginRepository:
    def __init__(self) -> None:
        self.by_id: dict[str, PluginRegistration] = {}

    async def save(self, plugin: PluginRegistration) -> None:
        self.by_id[str(plugin.plugin_id)] = plugin

    async def find_by_id(
        self, plugin_id: PluginId, tenant_id: TenantId
    ) -> PluginRegistration | None:
        p = self.by_id.get(str(plugin_id))
        if p is None or p.tenant_id != tenant_id:
            return None
        return p

    async def list_by_tenant(
        self, tenant_id: TenantId, *, limit: int = 100, offset: int = 0
    ) -> list[PluginRegistration]:
        items = [p for p in self.by_id.values() if p.tenant_id == tenant_id]
        return items[offset : offset + limit]


class FakePayloadUnitOfWork(IUnitOfWork):
    def __init__(
        self,
        payloads: InMemoryPayloadRepository | None = None,
        plugins: InMemoryPluginRepository | None = None,
    ) -> None:
        super().__init__()
        self.payloads = payloads or InMemoryPayloadRepository()
        self.plugins = plugins or InMemoryPluginRepository()

    async def commit(self) -> None:
        self._committed = True

    async def rollback(self) -> None:
        self._committed = False


class FakeEventPublisher(IEventPublisher):
    def __init__(self) -> None:
        self.published: list[BaseDomainEvent] = []

    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        self.published.extend(events)


def _hash(data: bytes = b"artifact") -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def _build_service(
    invalidation: IPlanInvalidationPort | None = None,
) -> tuple[PayloadApplicationService, FakePayloadUnitOfWork, DegradedPlanInvalidationAdapter]:
    uow = FakePayloadUnitOfWork()
    inv = invalidation or DegradedPlanInvalidationAdapter()
    assert isinstance(inv, DegradedPlanInvalidationAdapter) or True

    def factory() -> FakePayloadUnitOfWork:
        return FakePayloadUnitOfWork(payloads=uow.payloads, plugins=uow.plugins)

    svc = PayloadApplicationService(factory, FakeEventPublisher(), inv)
    return svc, uow, inv  # type: ignore[return-value]


@pytest.mark.asyncio
async def test_destruct_requires_ciso_approval() -> None:
    svc, _uow, _inv = _build_service()
    tenant = uuid7()
    registered = await svc.register_payload(
        RegisterPayload(
            tenant_id=tenant,
            payload_key="tool.destruct",
            payload_type="Binary",
            impact_ceiling="Destruct",
        )
    )
    pid = UUID(registered.payload_id)
    await svc.publish_payload_version(
        PublishPayloadVersion(
            tenant_id=tenant,
            payload_id=pid,
            version="1.0.0",
            payload_hash=_hash(),
            storage_ref="blob://p1",
            technique_ids=("T1059",),
        )
    )
    with pytest.raises(ApplicationConflictError):
        await svc.approve_payload(
            ApprovePayload(
                tenant_id=tenant,
                payload_id=pid,
                approved_by=uuid7(),
                signature="sig",
                ciso_approved=False,
            )
        )
    approved = await svc.approve_payload(
        ApprovePayload(
            tenant_id=tenant,
            payload_id=pid,
            approved_by=uuid7(),
            signature="sig",
            ciso_approved=True,
        )
    )
    assert approved.approval_state == "Approved"


@pytest.mark.asyncio
async def test_revoke_calls_plan_invalidation() -> None:
    inv = DegradedPlanInvalidationAdapter()
    svc, _uow, _ = _build_service(inv)
    tenant = uuid7()
    registered = await svc.register_payload(
        RegisterPayload(
            tenant_id=tenant,
            payload_key="tool.probe",
            payload_type="Script",
            impact_ceiling="Probe",
        )
    )
    pid = UUID(registered.payload_id)
    await svc.publish_payload_version(
        PublishPayloadVersion(
            tenant_id=tenant,
            payload_id=pid,
            version="1.0.0",
            payload_hash=_hash(),
            storage_ref="blob://p2",
            technique_ids=("T1003",),
        )
    )
    await svc.approve_payload(
        ApprovePayload(
            tenant_id=tenant,
            payload_id=pid,
            approved_by=uuid7(),
            signature="sig",
        )
    )
    await svc.revoke_payload(
        RevokePayload(
            tenant_id=tenant,
            payload_id=pid,
            reason="compromise",
            revoked_by=uuid7(),
        )
    )
    assert inv.calls == [(tenant, pid)]


@pytest.mark.asyncio
async def test_hash_mismatch_raises() -> None:
    svc, _uow, _inv = _build_service()
    tenant = uuid7()
    registered = await svc.register_payload(
        RegisterPayload(
            tenant_id=tenant,
            payload_key="tool.hash",
            payload_type="Script",
            impact_ceiling="Observe",
        )
    )
    pid = UUID(registered.payload_id)
    good = _hash(b"good")
    await svc.publish_payload_version(
        PublishPayloadVersion(
            tenant_id=tenant,
            payload_id=pid,
            version="1.0.0",
            payload_hash=good,
            storage_ref="blob://p3",
            technique_ids=("T1046",),
        )
    )
    await svc.approve_payload(
        ApprovePayload(
            tenant_id=tenant,
            payload_id=pid,
            approved_by=uuid7(),
            signature="sig",
        )
    )
    with pytest.raises(ApplicationIntegrityError):
        await svc.verify_payload_hash(
            VerifyPayloadHash(
                tenant_id=tenant,
                payload_id=pid,
                computed_hash=_hash(b"bad"),
            )
        )


@pytest.mark.asyncio
async def test_invalidate_plans_referencing_payload() -> None:
    from tests.operation.fakes.repos import (
        FakeEngagementQueryPort,
        FakeOperationUnitOfWork,
        FakeVulnerabilityQueryPort,
    )
    from tests.operation.fakes.repos import FakeEventPublisher as OpEvents

    from operation.application.services.operation_application_service import (
        OperationApplicationService,
    )
    from operation.domain.aggregates.execution_plan_version import ExecutionPlanVersion
    from operation.domain.value_objects.enums import ExecutionPlanVersionState
    from operation.domain.value_objects.identifiers import (
        ExecutionPlanVersionId,
        OperationId,
    )
    from operation.domain.value_objects.plan_vos import PlanHash, PlanSnapshot, SignedBy

    tenant = TenantId.generate()
    payload_id = uuid7()
    uow = FakeOperationUnitOfWork()
    now = datetime.now(UTC)
    snapshot = PlanSnapshot(
        f'{{"steps":[{{"payload_id":"{payload_id}"}}]}}'
    )
    pv = ExecutionPlanVersion(
        plan_version_id=ExecutionPlanVersionId(uuid7()),
        tenant_id=tenant,
        operation_id=OperationId(uuid7()),
        version_number=1,
        snapshot=snapshot,
        plan_hash=PlanHash.from_snapshot(snapshot),
        signed_by=SignedBy(operator_id=uuid7(), signed_at=now, signature="s"),
        state=ExecutionPlanVersionState.SIGNED,
        created_at=now,
        updated_at=now,
        version=1,
    )
    await uow.plan_versions.save(pv)

    def factory() -> FakeOperationUnitOfWork:
        return FakeOperationUnitOfWork(
            operations=uow.operations, plan_versions=uow.plan_versions
        )

    op_svc = OperationApplicationService(
        uow_factory=factory,
        event_publisher=OpEvents(),
        engagement_query=FakeEngagementQueryPort(),
        vulnerability_query=FakeVulnerabilityQueryPort(),
    )
    count = await op_svc.invalidate_plans_referencing_payload(
        tenant_id=tenant, payload_id=payload_id
    )
    assert count == 1
    refreshed = await uow.plan_versions.find_by_id(pv.plan_version_id, tenant)
    assert refreshed is not None
    assert refreshed.state == ExecutionPlanVersionState.SUPERSEDED
