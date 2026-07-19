"""Tests for RotationPolicy aggregate."""

from __future__ import annotations

import pytest

from credential_vault.domain.aggregates.rotation_policy import RotationPolicy
from credential_vault.domain.events.policy_events import (
    RotationPolicyCreated,
    RotationPolicyDeleted,
    RotationPolicyUpdated,
)
from credential_vault.domain.exceptions.domain_exceptions import InvalidArgument, TenantMismatch


class TestRotationPolicy:
    def test_create(self, rotation_policy_id, tenant_id, now, principal_id) -> None:
        policy = RotationPolicy.create(
            policy_id=rotation_policy_id,
            tenant_id=tenant_id,
            name="  monthly  ",
            interval_days=30,
            max_versions_kept=5,
            notify_days_before=7,
            auto_rotate=True,
            now=now,
        )
        assert policy.name == "monthly"
        assert policy.version == 0
        events = policy.pop_events()
        assert isinstance(events[0], RotationPolicyCreated)

    def test_update(self, rotation_policy_id, tenant_id, now, principal_id) -> None:
        policy = RotationPolicy.create(
            policy_id=rotation_policy_id,
            tenant_id=tenant_id,
            name="monthly",
            interval_days=30,
            max_versions_kept=5,
            notify_days_before=7,
            auto_rotate=True,
            now=now,
        )
        policy.pop_events()
        policy.update(tenant_id, 60, 10, 14, False, principal_id, now)
        assert policy.interval_days == 60
        assert policy.version == 1
        events = policy.pop_events()
        assert isinstance(events[0], RotationPolicyUpdated)

    def test_delete(self, rotation_policy_id, tenant_id, now, principal_id) -> None:
        policy = RotationPolicy.create(
            policy_id=rotation_policy_id,
            tenant_id=tenant_id,
            name="monthly",
            interval_days=30,
            max_versions_kept=5,
            notify_days_before=7,
            auto_rotate=True,
            now=now,
        )
        policy.pop_events()
        policy.delete(tenant_id, principal_id, now)
        events = policy.pop_events()
        assert isinstance(events[0], RotationPolicyDeleted)

    def test_invalid_interval(self, rotation_policy_id, tenant_id, now) -> None:
        with pytest.raises(InvalidArgument, match="interval_days"):
            RotationPolicy.create(
                policy_id=rotation_policy_id,
                tenant_id=tenant_id,
                name="bad",
                interval_days=0,
                max_versions_kept=5,
                notify_days_before=7,
                auto_rotate=True,
                now=now,
            )

    def test_tenant_mismatch(self, rotation_policy_id, tenant_id, other_tenant_id, now, principal_id) -> None:
        policy = RotationPolicy.create(
            policy_id=rotation_policy_id,
            tenant_id=tenant_id,
            name="monthly",
            interval_days=30,
            max_versions_kept=5,
            notify_days_before=7,
            auto_rotate=True,
            now=now,
        )
        with pytest.raises(TenantMismatch):
            policy.update(other_tenant_id, 30, 5, 7, True, principal_id, now)
