from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from ai_agent_governance.application.commands.governance_commands import (
    AddAuthorizedActionCommand,
    ApproveEnvelopeCommand,
    DraftEnvelopeCommand,
    ReportAgentActionCommand,
    ReviewDeviationCommand,
    ReviseEnvelopeCommand,
)
from ai_agent_governance.application.exceptions import ApplicationValidationError
from ai_agent_governance.domain.value_objects.identifiers import TenantId
from ai_agent_governance.infrastructure.container import AgentGovernanceContainer
from ai_agent_governance.infrastructure.persistence.in_memory_unit_of_work import (
    InMemoryUnitOfWork,
)
from tests.ai_agent_governance.conftest import ADMIN, ANALYST, APPROVER, ENGINEER


@pytest.mark.asyncio
async def test_full_envelope_deviation_flow(
    container: AgentGovernanceContainer, tenant_id: TenantId
) -> None:
    asset_id = uuid4()
    env = await container.envelope_service.draft(
        DraftEnvelopeCommand(
            tenant_id=tenant_id,
            asset_id=asset_id,
            max_data_sensitivity="Internal",
            requires_human_approval_for=("FinancialTransaction",),
            actor_roles=ENGINEER,
        )
    )
    envelope_id = UUID(env.envelope_id)
    await container.envelope_service.add_action(
        AddAuthorizedActionCommand(
            tenant_id=tenant_id,
            envelope_id=envelope_id,
            category="DataRead",
            actor_roles=ENGINEER,
        )
    )
    await container.envelope_service.approve(
        ApproveEnvelopeCommand(
            tenant_id=tenant_id,
            envelope_id=envelope_id,
            approver_id="approver-1",
            actor_roles=APPROVER,
        )
    )
    occurred_at = datetime.now(UTC)
    ok = await container.deviation_service.report_action(
        ReportAgentActionCommand(
            tenant_id=tenant_id,
            asset_id=asset_id,
            action_category="DataRead",
            resource="crm",
            data_sensitivity="Internal",
            human_approval_present=False,
            occurred_at=occurred_at,
            idempotency_key="idem-ok",
            actor_roles=ENGINEER,
        )
    )
    assert ok.status == "compliant"
    bad = await container.deviation_service.report_action(
        ReportAgentActionCommand(
            tenant_id=tenant_id,
            asset_id=asset_id,
            action_category="CodeExecution",
            resource="shell",
            data_sensitivity="Internal",
            human_approval_present=False,
            occurred_at=occurred_at,
            idempotency_key="idem-bad",
            actor_roles=ENGINEER,
        )
    )
    assert bad.status == "deviation"
    assert bad.deviation is not None
    # idempotent
    dup = await container.deviation_service.report_action(
        ReportAgentActionCommand(
            tenant_id=tenant_id,
            asset_id=asset_id,
            action_category="CodeExecution",
            resource="shell",
            data_sensitivity="Internal",
            human_approval_present=False,
            occurred_at=occurred_at,
            idempotency_key="idem-bad",
            actor_roles=ENGINEER,
        )
    )
    assert dup.status == "duplicate"
    reviewed = await container.deviation_service.review(
        ReviewDeviationCommand(
            tenant_id=tenant_id,
            deviation_id=UUID(bad.deviation.deviation_id),
            decision="benign",
            notes="known maintenance",
            actor_roles=ANALYST,
        )
    )
    assert reviewed.review_state == "ConfirmedBenign"


@pytest.mark.asyncio
async def test_version_pinning_across_revision(
    container: AgentGovernanceContainer, tenant_id: TenantId, uow: InMemoryUnitOfWork
) -> None:
    asset_id = uuid4()
    t0 = datetime(2026, 7, 21, 10, 0, 0, tzinfo=UTC)
    env = await container.envelope_service.draft(
        DraftEnvelopeCommand(
            tenant_id=tenant_id,
            asset_id=asset_id,
            max_data_sensitivity="Internal",
            actor_roles=ENGINEER,
        )
    )
    eid = UUID(env.envelope_id)
    await container.envelope_service.add_action(
        AddAuthorizedActionCommand(
            tenant_id=tenant_id,
            envelope_id=eid,
            category="DataRead",
            actor_roles=ENGINEER,
        )
    )
    await container.envelope_service.approve(
        ApproveEnvelopeCommand(
            tenant_id=tenant_id,
            envelope_id=eid,
            approver_id="a",
            actor_roles=APPROVER,
        )
    )
    # freeze effective_from of current as t0 by rewriting snapshot times for test
    current = await uow.envelopes.find_by_id(
        __import__(
            "ai_agent_governance.domain.value_objects.identifiers",
            fromlist=["AgentOperationalEnvelopeId"],
        ).AgentOperationalEnvelopeId(eid),
        tenant_id,
    )
    assert current is not None
    current.effective_from = t0
    await uow.envelopes.save(current)
    await uow.envelopes.save_version_snapshot(current)

    t1 = t0 + timedelta(hours=3)
    await container.envelope_service.revise(
        ReviseEnvelopeCommand(
            tenant_id=tenant_id,
            envelope_id=eid,
            new_actions=(("DataRead", "r"), ("CodeExecution", "x")),
            actor_roles=ENGINEER,
        )
    )
    revised = await uow.envelopes.find_by_id(
        __import__(
            "ai_agent_governance.domain.value_objects.identifiers",
            fromlist=["AgentOperationalEnvelopeId"],
        ).AgentOperationalEnvelopeId(eid),
        tenant_id,
    )
    assert revised is not None
    revised.effective_from = t1
    await uow.envelopes.save(revised)
    await uow.envelopes.save_version_snapshot(revised)

    pinned = await uow.envelopes.find_active_version_at(
        __import__(
            "ai_agent_governance.domain.value_objects.identifiers", fromlist=["AISystemAssetId"]
        ).AISystemAssetId(asset_id),
        t0 + timedelta(hours=1),
        tenant_id,
    )
    assert pinned is not None
    assert pinned.envelope_version == 1
    assert "CodeExecution" not in {a.category.value for a in pinned.actions}


@pytest.mark.asyncio
async def test_remove_human_approval_admin_only(
    container: AgentGovernanceContainer, tenant_id: TenantId
) -> None:
    asset_id = uuid4()
    env = await container.envelope_service.draft(
        DraftEnvelopeCommand(
            tenant_id=tenant_id,
            asset_id=asset_id,
            max_data_sensitivity="Internal",
            requires_human_approval_for=("FinancialTransaction",),
            actor_roles=ENGINEER,
        )
    )
    eid = UUID(env.envelope_id)
    await container.envelope_service.add_action(
        AddAuthorizedActionCommand(
            tenant_id=tenant_id,
            envelope_id=eid,
            category="FinancialTransaction",
            actor_roles=ENGINEER,
        )
    )
    await container.envelope_service.approve(
        ApproveEnvelopeCommand(
            tenant_id=tenant_id,
            envelope_id=eid,
            approver_id="a",
            actor_roles=APPROVER,
        )
    )
    with pytest.raises(ApplicationValidationError):
        await container.envelope_service.revise(
            ReviseEnvelopeCommand(
                tenant_id=tenant_id,
                envelope_id=eid,
                remove_human_approval_for=("FinancialTransaction",),
                actor_roles=ENGINEER,
            )
        )
    ok = await container.envelope_service.revise(
        ReviseEnvelopeCommand(
            tenant_id=tenant_id,
            envelope_id=eid,
            remove_human_approval_for=("FinancialTransaction",),
            actor_roles=ADMIN,
        )
    )
    assert "FinancialTransaction" not in ok.requires_human_approval_for
