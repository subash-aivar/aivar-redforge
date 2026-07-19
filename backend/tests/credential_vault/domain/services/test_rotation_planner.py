"""Tests for RotationPlannerService."""

from __future__ import annotations

from datetime import timedelta

import pytest

from credential_vault.domain.aggregates.rotation_policy import RotationPolicy
from credential_vault.domain.exceptions.domain_exceptions import NoPolicyAttached
from credential_vault.domain.services.rotation_planner import RotationPlannerService
from tests.credential_vault.conftest import make_active_credential


class TestRotationPlannerService:
    def test_is_rotation_due(
        self,
        credential_id,
        tenant_id,
        version_id,
        principal_id,
        vault_backend_id,
        rotation_policy_id,
        now,
    ) -> None:
        credential = make_active_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            version_id=version_id,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
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
        planner = RotationPlannerService()
        created_at = now - timedelta(days=31)
        assert planner.is_rotation_due(credential, policy, created_at, now) is True

    def test_is_rotation_due_false_when_disabled(
        self,
        credential_id,
        tenant_id,
        version_id,
        principal_id,
        vault_backend_id,
        rotation_policy_id,
        now,
    ) -> None:
        credential = make_active_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            version_id=version_id,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
        credential.disable(tenant_id, principal_id, "test", now)
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
        planner = RotationPlannerService()
        assert planner.is_rotation_due(credential, policy, now, now) is False

    def test_next_rotation_at(
        self, rotation_policy_id, tenant_id, now
    ) -> None:
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
        planner = RotationPlannerService()
        next_at = planner.next_rotation_at(now, policy)
        assert next_at == now + timedelta(days=30)

    def test_next_rotation_at_raises_without_interval(
        self, rotation_policy_id, tenant_id, now
    ) -> None:
        policy = RotationPolicy.create(
            policy_id=rotation_policy_id,
            tenant_id=tenant_id,
            name="manual-only",
            interval_days=None,
            max_versions_kept=5,
            notify_days_before=7,
            auto_rotate=False,
            now=now,
        )
        planner = RotationPlannerService()
        with pytest.raises(NoPolicyAttached):
            planner.next_rotation_at(now, policy)

    def test_should_warn(
        self,
        credential_id,
        tenant_id,
        version_id,
        principal_id,
        vault_backend_id,
        rotation_policy_id,
        now,
    ) -> None:
        credential = make_active_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            version_id=version_id,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
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
        planner = RotationPlannerService()
        created_at = now - timedelta(days=25)
        assert planner.should_warn(credential, policy, created_at, now) is True
