"""Shared fixtures for Engagement domain and unit tests."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from engagement.domain.aggregates.engagement import Engagement
from engagement.domain.value_objects.engagement_vos import (
    ApprovalPolicy,
    EngagementWindow,
    RoeConstraint,
    TargetRef,
)
from engagement.domain.value_objects.enums import (
    EngagementClassification,
    QuorumType,
)
from engagement.domain.value_objects.identifiers import EngagementId, TenantId


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
    return TenantId.generate()


@pytest.fixture
def other_tenant_id() -> TenantId:
    return TenantId.generate()


def advance(now: datetime, **kwargs: int) -> datetime:
    return now + timedelta(**kwargs)


def make_policy(*, required: int = 2, quorum: QuorumType = QuorumType.MAJORITY) -> ApprovalPolicy:
    return ApprovalPolicy(
        required_approver_count=required,
        required_approver_roles=["redteam:approver", "redteam:ciso"],
        quorum_type=quorum,
    )


def make_engagement(
    *,
    tenant_id: TenantId,
    now: datetime,
    name: str = "Q3 Adversarial Sim",
    owner_id: str = "owner-1",
    classification: EngagementClassification = EngagementClassification.FULL_SIMULATION,
    required_approvers: int = 2,
    engagement_id: EngagementId | None = None,
    pop_events: bool = False,
) -> Engagement:
    eng = Engagement.create(
        engagement_id=engagement_id or EngagementId.generate(),
        tenant_id=tenant_id,
        name=name,
        classification=classification,
        owner_id=owner_id,
        approval_policy=make_policy(required=required_approvers),
        now=now,
    )
    if pop_events:
        eng.pop_events()
    return eng


def make_target(*, asset_id=None, display_name: str | None = "asset-a") -> TargetRef:
    return TargetRef(asset_id=asset_id or uuid4(), display_name=display_name)


def make_window(now: datetime, *, days: int = 30) -> EngagementWindow:
    return EngagementWindow(
        authorized_start=now - timedelta(hours=1),
        authorized_end=now + timedelta(days=days),
    )


def make_roe(
    *,
    techniques: list[str] | None = None,
) -> RoeConstraint:
    return RoeConstraint(
        allowed_techniques=techniques or ["T1059", "T1021"],
        forbidden_targets=[],
        rate_limits={},
        escalation_contacts=["ciso@example.com"],
    )


def prepare_ready_for_submit(
    engagement: Engagement,
    *,
    tenant_id: TenantId,
    now: datetime,
    targets: list[TargetRef] | None = None,
    techniques: list[str] | None = None,
    sign_roe: bool = True,
) -> list[TargetRef]:
    """Define scope, RoE, window — optionally sign RoE. Leaves engagement in Draft."""
    resolved = targets or [make_target(), make_target(display_name="asset-b")]
    engagement.define_scope(tenant_id, resolved, now)
    engagement.set_roe(tenant_id, make_roe(techniques=techniques), advance(now, minutes=1))
    if sign_roe:
        engagement.sign_roe(
            tenant_id,
            engagement.owner_id,
            "sig-roe-owner",
            advance(now, minutes=2),
        )
    engagement.set_window(tenant_id, make_window(now), advance(now, minutes=3))
    return resolved


def approve_to_quorum(
    engagement: Engagement,
    *,
    tenant_id: TenantId,
    now: datetime,
    approvers: list[str] | None = None,
) -> datetime:
    """Grant enough approvals to meet quorum. Returns last approval timestamp."""
    needed = engagement.approval_policy.required_approver_count
    ids = approvers or [f"approver-{i}" for i in range(needed)]
    ts = now
    for i, approver in enumerate(ids[:needed]):
        ts = advance(now, minutes=10 + i)
        engagement.grant_approval(tenant_id, approver, f"sig-{approver}", ts)
    return ts


def activate_engagement(
    engagement: Engagement,
    *,
    tenant_id: TenantId,
    now: datetime,
) -> Engagement:
    """Full path Draft → Active with default two-approver quorum."""
    prepare_ready_for_submit(engagement, tenant_id=tenant_id, now=now)
    engagement.submit_for_approval(tenant_id, advance(now, minutes=5))
    approve_to_quorum(engagement, tenant_id=tenant_id, now=now)
    engagement.activate(tenant_id, advance(now, minutes=30))
    return engagement
