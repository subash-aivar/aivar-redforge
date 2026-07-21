from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from ai_agent_governance.domain.aggregates.agent_operational_envelope import (
    AgentOperationalEnvelope,
)
from ai_agent_governance.domain.exceptions.domain_exceptions import (
    EnvelopeActivationRequirements,
    HumanApprovalCategoryLocked,
    ReviewNotesRequired,
)
from ai_agent_governance.domain.services.envelope_compliance_evaluation_service import (
    EnvelopeComplianceEvaluationService,
)
from ai_agent_governance.domain.value_objects.enums import (
    AuthorizedActionCategory,
    DataSensitivityClassification,
    DeviationType,
)
from ai_agent_governance.domain.value_objects.governance_vos import ObservedAction
from ai_agent_governance.domain.value_objects.identifiers import (
    AgentOperationalEnvelopeId,
    AISystemAssetId,
    TenantId,
)


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)


def test_cannot_activate_without_actions(now: datetime) -> None:
    tenant = TenantId(uuid4())
    env = AgentOperationalEnvelope.draft(
        AgentOperationalEnvelopeId.generate(),
        tenant,
        AISystemAssetId(uuid4()),
        DataSensitivityClassification.INTERNAL,
        now,
    )
    with pytest.raises(EnvelopeActivationRequirements):
        env.approve(tenant, "approver", now)


def test_human_approval_removal_requires_admin(now: datetime) -> None:
    tenant = TenantId(uuid4())
    env = AgentOperationalEnvelope.draft(
        AgentOperationalEnvelopeId.generate(),
        tenant,
        AISystemAssetId(uuid4()),
        DataSensitivityClassification.INTERNAL,
        now,
        requires_human_approval_for={AuthorizedActionCategory.FINANCIAL_TRANSACTION},
    )
    env.add_action(tenant, AuthorizedActionCategory.DATA_READ, "read")
    env.approve(tenant, "a1", now)
    with pytest.raises(HumanApprovalCategoryLocked):
        env.revise(
            tenant,
            now,
            remove_human_approval={AuthorizedActionCategory.FINANCIAL_TRANSACTION},
            actor_is_admin=False,
        )


def test_required_approval_bypassed_is_high(now: datetime) -> None:
    tenant = TenantId(uuid4())
    env = AgentOperationalEnvelope.draft(
        AgentOperationalEnvelopeId.generate(),
        tenant,
        AISystemAssetId(uuid4()),
        DataSensitivityClassification.INTERNAL,
        now,
        requires_human_approval_for={AuthorizedActionCategory.FINANCIAL_TRANSACTION},
    )
    env.add_action(tenant, AuthorizedActionCategory.FINANCIAL_TRANSACTION, "pay")
    env.approve(tenant, "a1", now)
    action = ObservedAction(
        AuthorizedActionCategory.FINANCIAL_TRANSACTION,
        "payments",
        DataSensitivityClassification.INTERNAL,
        False,
        now,
        "k1",
        {},
    )
    deviation = EnvelopeComplianceEvaluationService().evaluate(env, action, tenant, now)
    assert deviation is not None
    assert deviation.deviation_type == DeviationType.REQUIRED_APPROVAL_BYPASSED
    assert deviation.severity.value in {"High", "Critical"}


def test_benign_requires_notes(now: datetime) -> None:
    tenant = TenantId(uuid4())
    env = AgentOperationalEnvelope.draft(
        AgentOperationalEnvelopeId.generate(),
        tenant,
        AISystemAssetId(uuid4()),
        DataSensitivityClassification.INTERNAL,
        now,
    )
    env.add_action(tenant, AuthorizedActionCategory.DATA_READ, "r")
    env.approve(tenant, "a", now)
    action = ObservedAction(
        AuthorizedActionCategory.CODE_EXECUTION,
        "shell",
        DataSensitivityClassification.INTERNAL,
        False,
        now,
        "k2",
        {},
    )
    deviation = EnvelopeComplianceEvaluationService().evaluate(env, action, tenant, now)
    assert deviation is not None
    deviation.begin_review(tenant, now)
    with pytest.raises(ReviewNotesRequired):
        deviation.dismiss_benign(tenant, "  ", now)


def test_evaluation_pins_version_at_action_time(now: datetime) -> None:
    tenant = TenantId(uuid4())
    asset = AISystemAssetId(uuid4())
    env = AgentOperationalEnvelope.draft(
        AgentOperationalEnvelopeId.generate(),
        tenant,
        asset,
        DataSensitivityClassification.INTERNAL,
        now,
    )
    env.add_action(tenant, AuthorizedActionCategory.DATA_READ, "r")
    env.approve(tenant, "a", now)
    # revise to allow code execution later
    later = now + timedelta(hours=2)
    env.revise(
        tenant,
        later,
        new_actions=[
            (AuthorizedActionCategory.DATA_READ, "r"),
            (AuthorizedActionCategory.CODE_EXECUTION, "exec"),
        ],
        actor_is_admin=True,
    )
    env.reactivate_after_revision(tenant, later)
    # Action during v1 window should still fail for code execution if evaluated on v1 snapshot
    v1 = AgentOperationalEnvelope.draft(
        env.envelope_id,
        tenant,
        asset,
        DataSensitivityClassification.INTERNAL,
        now,
    )
    v1.add_action(tenant, AuthorizedActionCategory.DATA_READ, "r")
    v1.approve(tenant, "a", now)
    v1.envelope_version = 1
    v1.effective_until = later
    action = ObservedAction(
        AuthorizedActionCategory.CODE_EXECUTION,
        "shell",
        DataSensitivityClassification.INTERNAL,
        False,
        now + timedelta(minutes=30),
        "k3",
        {},
    )
    deviation = EnvelopeComplianceEvaluationService().evaluate(
        v1, action, tenant, now + timedelta(minutes=30)
    )
    assert deviation is not None
    assert deviation.envelope_ref.envelope_version == 1
