"""Tests for Credential aggregate root."""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest

from credential_vault.domain.events.credential_events import (
    CredentialCreated,
    CredentialDeleted,
    CredentialDisabled,
    CredentialEnabled,
    CredentialExpired,
    CredentialMetadataUpdated,
    CredentialRecovered,
    CredentialRenewed,
    CredentialRevoked,
    CredentialRotated,
    CredentialRotationStarted,
    CredentialVersionCreated,
    EmergencyRevoked,
    ExpirationPolicyAttached,
    ExpirationPolicyDetached,
    RotationAborted,
    RotationPolicyAttached,
    RotationPolicyDetached,
    VersionRolledBack,
)
from credential_vault.domain.exceptions.domain_exceptions import (
    InvalidArgument,
    InvalidStateTransition,
    NoPolicyAttached,
    TenantMismatch,
)
from credential_vault.domain.value_objects.audit_types import RotationTrigger
from credential_vault.domain.value_objects.credential_name import CredentialName
from credential_vault.domain.value_objects.identifiers import VersionId
from credential_vault.domain.value_objects.rotation_context import RotationContext
from credential_vault.domain.value_objects.states import CredentialState
from tests.credential_vault.conftest import advance, make_active_credential, make_credential


class TestCredentialCreate:
    def test_create_starts_at_version_zero(
        self,
        credential_id,
        tenant_id,
        credential_name,
        credential_type,
        principal_id,
        vault_backend_id,
        now,
    ) -> None:
        credential = make_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            name=credential_name,
            credential_type=credential_type,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
        assert credential.state == CredentialState.PENDING
        assert credential.version == 0
        events = credential.pop_events()
        assert len(events) == 1
        assert isinstance(events[0], CredentialCreated)


class TestCredentialHappyPaths:
    def test_activate(
        self, credential_id, tenant_id, version_id, principal_id, vault_backend_id, now
    ) -> None:
        credential = make_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
        credential.pop_events()
        credential.activate(tenant_id, version_id, now)
        assert credential.state == CredentialState.ACTIVE
        assert credential.active_version_id == version_id
        assert credential.version == 1
        events = credential.pop_events()
        assert len(events) == 1
        assert isinstance(events[0], CredentialVersionCreated)

    def test_rotation_cycle(
        self,
        credential_id,
        tenant_id,
        version_id,
        new_version_id,
        principal_id,
        vault_backend_id,
        rotation_context,
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
        credential.pop_events()
        t1 = advance(now, seconds=1)
        credential.begin_rotation(tenant_id, new_version_id, rotation_context, t1)
        assert credential.state == CredentialState.ROTATING
        t2 = advance(t1, seconds=1)
        credential.commit_rotation(tenant_id, new_version_id, version_id, t2)
        assert credential.state == CredentialState.ACTIVE
        assert credential.active_version_id == new_version_id
        events = credential.pop_events()
        assert isinstance(events[0], CredentialRotationStarted)
        assert isinstance(events[1], CredentialRotated)

    def test_abort_rotation(
        self,
        credential_id,
        tenant_id,
        version_id,
        new_version_id,
        principal_id,
        vault_backend_id,
        rotation_context,
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
        credential.begin_rotation(tenant_id, new_version_id, rotation_context, now)
        credential.pop_events()
        credential.abort_rotation(tenant_id, "failed validation", principal_id, now)
        assert credential.state == CredentialState.ACTIVE
        assert credential.active_version_id == version_id
        events = credential.pop_events()
        assert len(events) == 1
        assert isinstance(events[0], RotationAborted)

    def test_disable_and_enable(
        self, credential_id, tenant_id, version_id, principal_id, vault_backend_id, now
    ) -> None:
        credential = make_active_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            version_id=version_id,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
        credential.pop_events()
        credential.disable(tenant_id, principal_id, "maintenance", now)
        assert credential.state == CredentialState.DISABLED
        events = credential.pop_events()
        assert isinstance(events[0], CredentialDisabled)
        credential.enable(tenant_id, principal_id, now)
        assert credential.state == CredentialState.ACTIVE
        events = credential.pop_events()
        assert isinstance(events[0], CredentialEnabled)

    def test_revoke_from_active(
        self, credential_id, tenant_id, version_id, principal_id, vault_backend_id, now
    ) -> None:
        credential = make_active_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            version_id=version_id,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
        credential.pop_events()
        credential.revoke(tenant_id, principal_id, "compromised", now)
        assert credential.state == CredentialState.REVOKED
        events = credential.pop_events()
        assert isinstance(events[0], CredentialRevoked)

    def test_expire_and_renew(
        self, credential_id, tenant_id, version_id, principal_id, vault_backend_id, now
    ) -> None:
        credential = make_active_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            version_id=version_id,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
        credential.pop_events()
        credential.expire(tenant_id, now)
        assert credential.state == CredentialState.EXPIRED
        events = credential.pop_events()
        assert isinstance(events[0], CredentialExpired)
        new_expiry = now + timedelta(days=30)
        credential.renew(tenant_id, version_id, new_expiry, now)
        assert credential.state == CredentialState.ACTIVE
        events = credential.pop_events()
        assert isinstance(events[0], CredentialRenewed)

    def test_recover(
        self, credential_id, tenant_id, version_id, principal_id, vault_backend_id, now
    ) -> None:
        credential = make_active_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            version_id=version_id,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
        credential.revoke(tenant_id, principal_id, "test", now)
        credential.pop_events()
        credential.recover(tenant_id, principal_id, version_id, now)
        assert credential.state == CredentialState.ACTIVE
        events = credential.pop_events()
        assert isinstance(events[0], CredentialRecovered)

    def test_hard_delete_from_revoked(
        self, credential_id, tenant_id, version_id, principal_id, vault_backend_id, now
    ) -> None:
        credential = make_active_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            version_id=version_id,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
        credential.revoke(tenant_id, principal_id, "test", now)
        credential.pop_events()
        credential.hard_delete(tenant_id, principal_id, now)
        assert credential.state == CredentialState.DELETED
        events = credential.pop_events()
        assert isinstance(events[0], CredentialDeleted)

    def test_policy_attach_and_detach(
        self,
        credential_id,
        tenant_id,
        version_id,
        principal_id,
        vault_backend_id,
        rotation_policy_id,
        expiration_policy_id,
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
        credential.pop_events()
        credential.attach_rotation_policy(tenant_id, rotation_policy_id, principal_id, now)
        events = credential.pop_events()
        assert isinstance(events[0], RotationPolicyAttached)
        credential.detach_rotation_policy(tenant_id, principal_id, now)
        events = credential.pop_events()
        assert isinstance(events[0], RotationPolicyDetached)
        credential.attach_expiration_policy(tenant_id, expiration_policy_id, principal_id, now)
        events = credential.pop_events()
        assert isinstance(events[0], ExpirationPolicyAttached)
        credential.detach_expiration_policy(tenant_id, principal_id, now)
        events = credential.pop_events()
        assert isinstance(events[0], ExpirationPolicyDetached)

    def test_update_metadata(
        self, credential_id, tenant_id, version_id, principal_id, vault_backend_id, now
    ) -> None:
        credential = make_active_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            version_id=version_id,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
        credential.pop_events()
        credential.update_metadata(
            tenant_id, "updated description", {"env": "prod"}, principal_id, now
        )
        assert credential.description == "updated description"
        events = credential.pop_events()
        assert isinstance(events[0], CredentialMetadataUpdated)

    def test_rollback_version(
        self, credential_id, tenant_id, version_id, principal_id, vault_backend_id, now
    ) -> None:
        old_version = VersionId(uuid4())
        credential = make_active_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            version_id=version_id,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
        credential.pop_events()
        credential.rollback_version(tenant_id, old_version, principal_id, now)
        assert credential.active_version_id == old_version
        events = credential.pop_events()
        assert isinstance(events[0], VersionRolledBack)


class TestCredentialInvalidTransitions:
    def test_pending_cannot_begin_rotation(
        self, credential_id, tenant_id, version_id, principal_id, vault_backend_id, now
    ) -> None:
        credential = make_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
        ctx = RotationContext(
            trigger=RotationTrigger.MANUAL,
            initiated_by=principal_id,
            previous_version_id=version_id,
            policy_id=None,
            notes=None,
        )
        with pytest.raises(InvalidStateTransition):
            credential.begin_rotation(tenant_id, version_id, ctx, now)

    def test_deleted_cannot_enable(
        self, credential_id, tenant_id, version_id, principal_id, vault_backend_id, now
    ) -> None:
        credential = make_active_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            version_id=version_id,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
        credential.revoke(tenant_id, principal_id, "test", now)
        credential.hard_delete(tenant_id, principal_id, now)
        with pytest.raises(InvalidStateTransition):
            credential.enable(tenant_id, principal_id, now)

    def test_revoked_cannot_enable(
        self, credential_id, tenant_id, version_id, principal_id, vault_backend_id, now
    ) -> None:
        credential = make_active_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            version_id=version_id,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
        credential.revoke(tenant_id, principal_id, "test", now)
        with pytest.raises(InvalidStateTransition):
            credential.enable(tenant_id, principal_id, now)


class TestEmergencyRevoke:
    @pytest.mark.parametrize(
        "setup_state",
        [
            "pending",
            "active",
            "rotating",
            "disabled",
            "revoked",
            "expired",
        ],
    )
    def test_emergency_revoke_from_non_deleted(
        self,
        setup_state: str,
        credential_id,
        tenant_id,
        version_id,
        new_version_id,
        principal_id,
        vault_backend_id,
        rotation_context,
        now,
    ) -> None:
        credential = make_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
        if setup_state == "pending":
            pass
        elif setup_state == "active":
            credential.activate(tenant_id, version_id, now)
        elif setup_state == "rotating":
            credential.activate(tenant_id, version_id, now)
            credential.begin_rotation(tenant_id, new_version_id, rotation_context, now)
        elif setup_state == "disabled":
            credential.activate(tenant_id, version_id, now)
            credential.disable(tenant_id, principal_id, "test", now)
        elif setup_state == "revoked":
            credential.activate(tenant_id, version_id, now)
            credential.revoke(tenant_id, principal_id, "test", now)
        elif setup_state == "expired":
            credential.activate(tenant_id, version_id, now)
            credential.expire(tenant_id, now)

        credential.pop_events()
        credential.emergency_revoke(tenant_id, principal_id, "incident", now)
        assert credential.state == CredentialState.REVOKED
        events = credential.pop_events()
        assert len(events) == 1
        assert isinstance(events[0], EmergencyRevoked)


class TestCredentialEventsAndVersioning:
    def test_pop_events_idempotent(
        self, credential_id, tenant_id, version_id, principal_id, vault_backend_id, now
    ) -> None:
        credential = make_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
        first = credential.pop_events()
        second = credential.pop_events()
        assert len(first) == 1
        assert second == []

    def test_version_increments_per_mutation(
        self, credential_id, tenant_id, version_id, principal_id, vault_backend_id, now
    ) -> None:
        credential = make_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
        assert credential.version == 0
        credential.activate(tenant_id, version_id, now)
        assert credential.version == 1
        credential.disable(tenant_id, principal_id, "test", now)
        assert credential.version == 2
        credential.enable(tenant_id, principal_id, now)
        assert credential.version == 3


class TestCredentialGuards:
    def test_tenant_mismatch(
        self, credential_id, tenant_id, other_tenant_id, principal_id, vault_backend_id, now
    ) -> None:
        credential = make_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
        with pytest.raises(TenantMismatch):
            credential.activate(other_tenant_id, VersionId(uuid4()), now)

    def test_too_many_tags(
        self, credential_id, tenant_id, principal_id, vault_backend_id, now
    ) -> None:
        tags = {f"key{i}": "value" for i in range(51)}
        with pytest.raises(InvalidArgument, match="max 50 tags"):
            make_credential(
                credential_id=credential_id,
                tenant_id=tenant_id,
                owner_principal=principal_id,
                vault_backend_id=vault_backend_id,
                now=now,
                tags=tags,
            )

    def test_tag_key_too_long(
        self, credential_id, tenant_id, principal_id, vault_backend_id, now
    ) -> None:
        with pytest.raises(InvalidArgument, match="tag key max"):
            make_credential(
                credential_id=credential_id,
                tenant_id=tenant_id,
                owner_principal=principal_id,
                vault_backend_id=vault_backend_id,
                now=now,
                tags={"x" * 101: "value"},
            )

    def test_detach_rotation_policy_without_attachment(
        self, credential_id, tenant_id, version_id, principal_id, vault_backend_id, now
    ) -> None:
        credential = make_active_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            version_id=version_id,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
        with pytest.raises(NoPolicyAttached):
            credential.detach_rotation_policy(tenant_id, principal_id, now)

    def test_credential_name_strips_whitespace(self) -> None:
        name = CredentialName("  my-credential  ")
        assert name.value == "my-credential"

    def test_credential_name_invalid_chars(self) -> None:
        with pytest.raises(ValueError, match="invalid characters"):
            CredentialName("bad@name")

    def test_is_resolvable_only_when_active(
        self, credential_id, tenant_id, version_id, principal_id, vault_backend_id, now
    ) -> None:
        credential = make_active_credential(
            credential_id=credential_id,
            tenant_id=tenant_id,
            version_id=version_id,
            owner_principal=principal_id,
            vault_backend_id=vault_backend_id,
            now=now,
        )
        assert credential.is_resolvable() is True
        credential.disable(tenant_id, principal_id, "test", now)
        assert credential.is_resolvable() is False
