"""Tests for PolicyEvaluatorService."""

from __future__ import annotations

from datetime import timedelta

from credential_vault.domain.aggregates.expiration_policy import ExpirationPolicy
from credential_vault.domain.services.policy_evaluator import PolicyEvaluatorService
from tests.credential_vault.conftest import make_credential_version


class TestPolicyEvaluatorService:
    def test_is_version_expired_by_expires_at(
        self,
        version_id,
        credential_id,
        tenant_id,
        principal_id,
        encrypted_payload,
        key_envelope,
        expiration_policy_id,
        now,
    ) -> None:
        version = make_credential_version(
            version_id=version_id,
            credential_id=credential_id,
            tenant_id=tenant_id,
            owner_principal=principal_id,
            encrypted_payload=encrypted_payload,
            key_envelope=key_envelope,
            now=now,
            expires_at=now - timedelta(seconds=1),
        )
        evaluator = PolicyEvaluatorService()
        assert evaluator.is_version_expired(version, None, now) is True

    def test_is_version_expired_by_hard_expire_policy(
        self,
        version_id,
        credential_id,
        tenant_id,
        principal_id,
        encrypted_payload,
        key_envelope,
        expiration_policy_id,
        now,
    ) -> None:
        policy = ExpirationPolicy.create(
            policy_id=expiration_policy_id,
            tenant_id=tenant_id,
            name="ttl",
            ttl_days=30,
            warn_days_before=7,
            hard_expire=True,
            now=now,
        )
        version = make_credential_version(
            version_id=version_id,
            credential_id=credential_id,
            tenant_id=tenant_id,
            owner_principal=principal_id,
            encrypted_payload=encrypted_payload,
            key_envelope=key_envelope,
            now=now - timedelta(days=31),
        )
        evaluator = PolicyEvaluatorService()
        assert evaluator.is_version_expired(version, policy, now) is True

    def test_should_warn_expiration(
        self,
        version_id,
        credential_id,
        tenant_id,
        principal_id,
        encrypted_payload,
        key_envelope,
        expiration_policy_id,
        now,
    ) -> None:
        policy = ExpirationPolicy.create(
            policy_id=expiration_policy_id,
            tenant_id=tenant_id,
            name="ttl",
            ttl_days=90,
            warn_days_before=14,
            hard_expire=True,
            now=now,
        )
        version = make_credential_version(
            version_id=version_id,
            credential_id=credential_id,
            tenant_id=tenant_id,
            owner_principal=principal_id,
            encrypted_payload=encrypted_payload,
            key_envelope=key_envelope,
            now=now - timedelta(days=80),
        )
        evaluator = PolicyEvaluatorService()
        assert evaluator.should_warn_expiration(version, policy, now) is True

    def test_compute_version_expiry(
        self, expiration_policy_id, tenant_id, now
    ) -> None:
        policy = ExpirationPolicy.create(
            policy_id=expiration_policy_id,
            tenant_id=tenant_id,
            name="ttl",
            ttl_days=90,
            warn_days_before=7,
            hard_expire=True,
            now=now,
        )
        evaluator = PolicyEvaluatorService()
        expiry = evaluator.compute_version_expiry(now, policy)
        assert expiry == now + timedelta(days=90)
