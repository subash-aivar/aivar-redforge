"""Shared fixtures for Campaign domain and application tests."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from campaign.domain.aggregates.campaign import Campaign
from campaign.domain.entities.campaign_entities import CampaignObjective
from campaign.domain.value_objects.campaign_vos import (
    ApprovalPolicy,
    CampaignSafetyPolicyVO,
    EngagementRef,
    ObjectiveEvaluationCriteria,
    TargetRef,
    TargetSelectionRule,
)
from campaign.domain.value_objects.enums import (
    CampaignClassification,
    CampaignKind,
    ObjectiveState,
    ObjectiveType,
)
from campaign.domain.value_objects.identifiers import (
    CampaignId,
    CampaignObjectiveId,
    TenantId,
)


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "integration: marks tests requiring PostgreSQL",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if os.environ.get("TEST_DATABASE_URL"):
        return
    skip_integration = pytest.mark.skip(
        reason="TEST_DATABASE_URL not set — skipping integration tests"
    )
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def tenant_id() -> TenantId:
    return TenantId(uuid4())


@pytest.fixture
def engagement_ref(tenant_id: TenantId) -> EngagementRef:
    return EngagementRef(
        engagement_id=uuid4(),
        tenant_id=tenant_id.value,
    )


@pytest.fixture
def default_safety_policy() -> CampaignSafetyPolicyVO:
    return CampaignSafetyPolicyVO(
        max_concurrent_actions=10,
        auto_abort_on_detection=False,
        auto_abort_on_objective_failure=False,
        blast_radius_ceiling="Probe",
    )


@pytest.fixture
def default_approval_policy() -> ApprovalPolicy:
    return ApprovalPolicy(required_approver_count=1, quorum_type="Unanimous")


def advance(now: datetime, **kwargs: int) -> datetime:
    return now + timedelta(**kwargs)


def make_campaign(
    *,
    tenant_id: TenantId,
    now: datetime,
    kind: CampaignKind = CampaignKind.ONE_SHOT,
    engagement_ref: EngagementRef | None = None,
    max_concurrent_actions: int = 10,
    auto_abort_on_detection: bool = False,
    required_approver_count: int = 1,
    pop_events: bool = False,
) -> Campaign:
    if engagement_ref is None:
        engagement_ref = EngagementRef(engagement_id=uuid4(), tenant_id=tenant_id.value)
    campaign = Campaign.create(
        campaign_id=CampaignId.generate(),
        tenant_id=tenant_id,
        name="Test Campaign",
        classification=CampaignClassification.FULL_KILL_CHAIN,
        kind=kind,
        owner_id="owner-1",
        safety_policy=CampaignSafetyPolicyVO(
            max_concurrent_actions=max_concurrent_actions,
            auto_abort_on_detection=auto_abort_on_detection,
            auto_abort_on_objective_failure=False,
            blast_radius_ceiling="Probe",
        ),
        approval_policy=ApprovalPolicy(required_approver_count=required_approver_count),
        engagement_ref=engagement_ref,
        now=now,
    )
    if pop_events:
        campaign.pop_events()
    return campaign


def make_objective(
    objective_type: ObjectiveType = ObjectiveType.ACCESS_ACHIEVED,
    description: str = "Achieve access",
    condition_type: str = "AttackActionCompleted",
    sealed: bool = False,
) -> CampaignObjective:
    return CampaignObjective(
        id=CampaignObjectiveId.generate(),
        objective_type=objective_type,
        description=description,
        evaluation_criteria=ObjectiveEvaluationCriteria(
            condition_type=condition_type,
            parameters={},
        ),
        state=ObjectiveState.PENDING,
        sealed=sealed,
    )


def make_target_ref(asset_type: str = "Server") -> TargetRef:
    return TargetRef(asset_id=uuid4(), asset_type=asset_type)


def add_target_rule(campaign: Campaign, tenant_id: TenantId, now: datetime) -> None:
    rule = TargetSelectionRule(
        attribute="environment",
        operator="eq",
        value="staging",
    )
    campaign.add_target_selection_rule(tenant_id=tenant_id, rule=rule, now=now)
