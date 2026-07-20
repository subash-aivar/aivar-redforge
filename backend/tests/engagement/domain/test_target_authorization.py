"""TargetAuthorization aggregate — grant, suspend, revoke immutability."""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from tests.engagement.conftest import advance

from engagement.domain.aggregates.target_authorization import TargetAuthorization
from engagement.domain.events.authorization_events import (
    TargetAuthorizationExpired,
    TargetAuthorizationGranted,
    TargetAuthorizationRevoked,
    TargetAuthorizationSuspended,
)
from engagement.domain.exceptions.domain_exceptions import (
    AuthorizationReinstatementForbidden,
    InvalidArgument,
    InvalidStateTransition,
)
from engagement.domain.value_objects.engagement_vos import (
    AttackTechniqueRef,
    AuthorizationConstraints,
    AuthorizedTechniqueSet,
    TargetRef,
)
from engagement.domain.value_objects.enums import AuthorizationState, ImpactCeiling
from engagement.domain.value_objects.identifiers import (
    EngagementId,
    TargetAuthorizationId,
)


def _grant(
    *,
    tenant_id,
    now,
    impact: ImpactCeiling = ImpactCeiling.PROBE,
    techniques: list[str] | None = None,
    allowed: frozenset[str] | None = None,
    destruct_approval: bool = False,
    valid_until=None,
) -> TargetAuthorization:
    tech_ids = techniques or ["T1059"]
    return TargetAuthorization.grant(
        authorization_id=TargetAuthorizationId.generate(),
        tenant_id=tenant_id,
        engagement_id=EngagementId.generate(),
        target_ref=TargetRef(asset_id=uuid4(), display_name="t1"),
        techniques=AuthorizedTechniqueSet(
            techniques=[AttackTechniqueRef(technique_id=t) for t in tech_ids]
        ),
        constraints=AuthorizationConstraints(
            max_execution_count=5,
            impact_ceiling=impact,
        ),
        granted_by="grantor-1",
        valid_until=valid_until or (now + timedelta(days=7)),
        now=now,
        allowed_roe_techniques=allowed or frozenset(["T1059", "T1021"]),
        destruct_approval_granted=destruct_approval,
    )


class TestGrant:
    def test_grant_starts_active_and_emits(self, tenant_id, now) -> None:
        auth = _grant(tenant_id=tenant_id, now=now)
        assert auth.state == AuthorizationState.ACTIVE
        events = auth.pop_events()
        assert isinstance(events[0], TargetAuthorizationGranted)

    def test_techniques_must_be_subset_of_roe(self, tenant_id, now) -> None:
        with pytest.raises(InvalidArgument, match="techniques"):
            _grant(
                tenant_id=tenant_id,
                now=now,
                techniques=["T9999"],
                allowed=frozenset(["T1059"]),
            )

    def test_destruct_requires_ciso_gate(self, tenant_id, now) -> None:
        with pytest.raises(InvalidArgument, match="Destruct"):
            _grant(
                tenant_id=tenant_id,
                now=now,
                impact=ImpactCeiling.DESTRUCT,
                destruct_approval=False,
            )
        auth = _grant(
            tenant_id=tenant_id,
            now=now,
            impact=ImpactCeiling.DESTRUCT,
            destruct_approval=True,
        )
        assert auth.destruct_approval_granted is True


class TestRevokeCannotReinstate:
    def test_revoked_cannot_be_reinstated(self, tenant_id, now) -> None:
        auth = _grant(tenant_id=tenant_id, now=now)
        auth.pop_events()
        auth.revoke(tenant_id, "policy", "ciso", advance(now, minutes=1))
        assert auth.state == AuthorizationState.REVOKED
        events = auth.pop_events()
        assert isinstance(events[0], TargetAuthorizationRevoked)

        with pytest.raises(AuthorizationReinstatementForbidden):
            auth.resume(tenant_id, advance(now, minutes=2))

        with pytest.raises(AuthorizationReinstatementForbidden):
            auth.suspend(tenant_id, "again", advance(now, minutes=3))

    def test_suspend_resume_allowed(self, tenant_id, now) -> None:
        auth = _grant(tenant_id=tenant_id, now=now)
        auth.pop_events()
        auth.suspend(tenant_id, "pause", advance(now, minutes=1))
        assert isinstance(auth.pop_events()[0], TargetAuthorizationSuspended)
        auth.resume(tenant_id, advance(now, minutes=2))
        assert auth.state == AuthorizationState.ACTIVE

    def test_expire_emits_event(self, tenant_id, now) -> None:
        auth = _grant(
            tenant_id=tenant_id,
            now=now,
            valid_until=now + timedelta(minutes=5),
        )
        auth.pop_events()
        auth.expire(tenant_id, advance(now, minutes=10))
        assert auth.state == AuthorizationState.EXPIRED
        assert isinstance(auth.pop_events()[0], TargetAuthorizationExpired)

    def test_invalid_transition_from_expired(self, tenant_id, now) -> None:
        auth = _grant(tenant_id=tenant_id, now=now)
        auth.expire(tenant_id, advance(now, days=8))
        with pytest.raises(InvalidStateTransition):
            auth.resume(tenant_id, advance(now, days=9))
