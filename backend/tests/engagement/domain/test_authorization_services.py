"""EngagementAuthorizationService and ScopeVerificationService tests."""

from __future__ import annotations

from uuid import uuid4

from tests.engagement.conftest import (
    activate_engagement,
    advance,
    make_engagement,
    make_target,
)

from engagement.domain.services.authorization_services import (
    EngagementAuthorizationService,
    ScopeVerificationService,
)
from engagement.domain.value_objects.engagement_vos import (
    AttackTechniqueRef,
    TargetRef,
)
from engagement.domain.value_objects.enums import AuthorizationDecision


class TestEngagementAuthorizationService:
    def test_authorized_when_active_in_scope_and_technique_allowed(
        self, tenant_id, now
    ) -> None:
        eng = make_engagement(tenant_id=tenant_id, now=now, required_approvers=1, pop_events=True)
        activate_engagement(eng, tenant_id=tenant_id, now=now)
        target = eng.scope.targets[0]
        technique = AttackTechniqueRef(technique_id="T1059")
        result = EngagementAuthorizationService().evaluate(
            eng, target, technique, advance(now, hours=1)
        )
        assert result.decision == AuthorizationDecision.AUTHORIZED

    def test_forbidden_when_out_of_scope(self, tenant_id, now) -> None:
        eng = make_engagement(tenant_id=tenant_id, now=now, required_approvers=1, pop_events=True)
        activate_engagement(eng, tenant_id=tenant_id, now=now)
        other = TargetRef(asset_id=uuid4(), display_name="outsider")
        result = EngagementAuthorizationService().evaluate(
            eng,
            other,
            AttackTechniqueRef(technique_id="T1059"),
            advance(now, hours=1),
        )
        assert result.decision == AuthorizationDecision.FORBIDDEN
        assert "outside" in result.reason.lower() or "scope" in result.reason.lower()

    def test_forbidden_when_technique_not_in_roe(self, tenant_id, now) -> None:
        eng = make_engagement(tenant_id=tenant_id, now=now, required_approvers=1, pop_events=True)
        activate_engagement(eng, tenant_id=tenant_id, now=now)
        result = EngagementAuthorizationService().evaluate(
            eng,
            eng.scope.targets[0],
            AttackTechniqueRef(technique_id="T9999"),
            advance(now, hours=1),
        )
        assert result.decision == AuthorizationDecision.FORBIDDEN

    def test_forbidden_when_not_active(self, tenant_id, now) -> None:
        eng = make_engagement(tenant_id=tenant_id, now=now, pop_events=True)
        result = EngagementAuthorizationService().evaluate(
            eng,
            make_target(),
            AttackTechniqueRef(technique_id="T1059"),
            now,
        )
        assert result.decision == AuthorizationDecision.FORBIDDEN


class TestScopeVerificationService:
    def test_verify_target_in_scope(self, tenant_id, now) -> None:
        eng = make_engagement(tenant_id=tenant_id, now=now, required_approvers=1, pop_events=True)
        activate_engagement(eng, tenant_id=tenant_id, now=now)
        svc = ScopeVerificationService()
        assert svc.verify_target_in_scope(eng, eng.scope.targets[0]) is True
        assert svc.verify_target_in_scope(eng, make_target()) is False

    def test_verify_scope_hash_matches(self, tenant_id, now) -> None:
        eng = make_engagement(tenant_id=tenant_id, now=now, required_approvers=1, pop_events=True)
        from tests.engagement.conftest import prepare_ready_for_submit

        prepare_ready_for_submit(eng, tenant_id=tenant_id, now=now)
        eng.submit_for_approval(tenant_id, advance(now, minutes=5))
        approval_ts = advance(now, minutes=10)
        eng.grant_approval(tenant_id, "a1", "sig", approval_ts)
        svc = ScopeVerificationService()
        assert eng.scope_hash is not None
        assert svc.verify_scope_hash(eng, eng.scope_hash, approval_ts) is True
        wrong_ts = advance(now, minutes=11)
        assert svc.verify_scope_hash(eng, eng.scope_hash, wrong_ts) is False
