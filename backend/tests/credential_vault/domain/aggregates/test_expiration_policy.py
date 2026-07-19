"""Tests for ExpirationPolicy aggregate."""

from __future__ import annotations

import pytest

from credential_vault.domain.aggregates.expiration_policy import ExpirationPolicy
from credential_vault.domain.events.policy_events import (
    ExpirationPolicyCreated,
    ExpirationPolicyDeleted,
    ExpirationPolicyUpdated,
)
from credential_vault.domain.exceptions.domain_exceptions import InvalidArgument, TenantMismatch


class TestExpirationPolicy:
    def test_create(self, expiration_policy_id, tenant_id, now) -> None:
        policy = ExpirationPolicy.create(
            policy_id=expiration_policy_id,
            tenant_id=tenant_id,
            name="  ttl-policy  ",
            ttl_days=90,
            warn_days_before=7,
            hard_expire=True,
            now=now,
        )
        assert policy.name == "ttl-policy"
        events = policy.pop_events()
        assert isinstance(events[0], ExpirationPolicyCreated)

    def test_update(self, expiration_policy_id, tenant_id, now, principal_id) -> None:
        policy = ExpirationPolicy.create(
            policy_id=expiration_policy_id,
            tenant_id=tenant_id,
            name="ttl-policy",
            ttl_days=90,
            warn_days_before=7,
            hard_expire=True,
            now=now,
        )
        policy.pop_events()
        policy.update(tenant_id, 180, 14, False, principal_id, now)
        assert policy.ttl_days == 180
        events = policy.pop_events()
        assert isinstance(events[0], ExpirationPolicyUpdated)

    def test_delete(self, expiration_policy_id, tenant_id, now, principal_id) -> None:
        policy = ExpirationPolicy.create(
            policy_id=expiration_policy_id,
            tenant_id=tenant_id,
            name="ttl-policy",
            ttl_days=90,
            warn_days_before=7,
            hard_expire=True,
            now=now,
        )
        policy.pop_events()
        policy.delete(tenant_id, principal_id, now)
        events = policy.pop_events()
        assert isinstance(events[0], ExpirationPolicyDeleted)

    def test_warn_days_must_be_less_than_ttl(self, expiration_policy_id, tenant_id, now) -> None:
        with pytest.raises(InvalidArgument, match="warn_days_before"):
            ExpirationPolicy.create(
                policy_id=expiration_policy_id,
                tenant_id=tenant_id,
                name="bad",
                ttl_days=30,
                warn_days_before=30,
                hard_expire=True,
                now=now,
            )

    def test_tenant_mismatch(
        self, expiration_policy_id, tenant_id, other_tenant_id, now, principal_id
    ) -> None:
        policy = ExpirationPolicy.create(
            policy_id=expiration_policy_id,
            tenant_id=tenant_id,
            name="ttl-policy",
            ttl_days=90,
            warn_days_before=7,
            hard_expire=True,
            now=now,
        )
        with pytest.raises(TenantMismatch):
            policy.update(other_tenant_id, 90, 7, True, principal_id, now)
