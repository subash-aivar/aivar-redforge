"""ScopeHash hardening — engagement_version + approval_timestamp (HARDENING §3)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from tests.engagement.conftest import (
    advance,
    make_engagement,
    prepare_ready_for_submit,
)

from engagement.domain.value_objects.engagement_vos import (
    TargetRef,
    compute_scope_hash,
    serialize_target_scope,
)


class TestComputeScopeHash:
    def test_hash_includes_version_and_timestamp(self) -> None:
        targets = [TargetRef(asset_id=uuid4(), display_name="a")]
        serialized = serialize_target_scope(targets)
        ts = datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC)
        h1 = compute_scope_hash(serialized, 1, ts)
        h2 = compute_scope_hash(serialized, 2, ts)
        h3 = compute_scope_hash(serialized, 1, ts + timedelta(seconds=1))
        assert h1.value != h2.value
        assert h1.value != h3.value
        assert len(h1.value) == 64

    def test_canonical_serialization_is_order_independent(self) -> None:
        a = TargetRef(asset_id=uuid4(), display_name="a")
        b = TargetRef(asset_id=uuid4(), display_name="b")
        s1 = serialize_target_scope([a, b])
        s2 = serialize_target_scope([b, a])
        assert s1 == s2

    def test_quorum_completion_computes_hash_with_version_and_approval_ts(
        self, tenant_id, now
    ) -> None:
        eng = make_engagement(tenant_id=tenant_id, now=now, required_approvers=1, pop_events=True)
        targets = prepare_ready_for_submit(eng, tenant_id=tenant_id, now=now)
        eng.submit_for_approval(tenant_id, advance(now, minutes=5))
        approval_ts = advance(now, minutes=10)
        eng.grant_approval(tenant_id, "approver-1", "sig", approval_ts)

        assert eng.scope_hash is not None
        expected = compute_scope_hash(
            serialize_target_scope(targets),
            eng.engagement_version,
            approval_ts,
        )
        assert eng.scope_hash.value == expected.value

    def test_scope_expansion_bumps_version_and_rehashes(self, tenant_id, now) -> None:
        eng = make_engagement(tenant_id=tenant_id, now=now, required_approvers=1, pop_events=True)
        prepare_ready_for_submit(eng, tenant_id=tenant_id, now=now)
        eng.submit_for_approval(tenant_id, advance(now, minutes=5))
        eng.grant_approval(tenant_id, "a1", "sig", advance(now, minutes=10))
        eng.activate(tenant_id, advance(now, minutes=20))
        old_hash = eng.scope_hash
        old_version = eng.engagement_version

        extra = TargetRef(asset_id=uuid4(), display_name="extra")
        eng.request_scope_expansion(tenant_id, [extra], advance(now, hours=1))
        # Re-approve after expansion cycle
        eng.grant_approval(tenant_id, "a2", "sig2", advance(now, hours=2))
        assert eng.state.value == "Approved"
        eng.approve_scope_expansion(tenant_id, advance(now, hours=3))

        assert eng.engagement_version == old_version + 1
        assert eng.scope_hash is not None
        assert eng.scope_hash.value != (old_hash.value if old_hash else "")
        expected = compute_scope_hash(
            serialize_target_scope(eng.scope.targets),
            eng.engagement_version,
            advance(now, hours=3),
        )
        assert eng.scope_hash.value == expected.value
