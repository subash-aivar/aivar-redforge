from __future__ import annotations

from datetime import UTC, datetime

import pytest

from cloud_security.application.exceptions import DuplicateCredentialAttachmentError
from cloud_security.application.registry.in_memory_credential_reference_registry import (
    InMemoryCredentialReferenceRegistry,
)
from cloud_security.domain.aggregates.credential_association import CredentialAssociation
from cloud_security.domain.value_objects.cloud_credential_reference import (
    CloudCredentialReference,
)
from cloud_security.domain.value_objects.identifiers import (
    AccountId,
    CredentialAssociationId,
    ProviderId,
    TenantId,
)

NOW = datetime.now(UTC)


def _ref(credential_id: str = "cred-1") -> CloudCredentialReference:
    return CloudCredentialReference(credential_id=credential_id, credential_type="role_arn")


def _attach(tenant_id, account_id=None, provider_id=None, **overrides) -> CredentialAssociation:
    defaults = {
        "association_id": CredentialAssociationId.generate(),
        "tenant_id": tenant_id,
        "account_id": account_id or AccountId.generate(),
        "provider_id": provider_id or ProviderId.generate(),
        "reference": _ref(),
        "now": NOW,
    }
    defaults.update(overrides)
    return CredentialAssociation.attach(**defaults)


def test_register_then_get_returns_same_association() -> None:
    registry = InMemoryCredentialReferenceRegistry()
    tenant_id = TenantId.generate()
    association = _attach(tenant_id)
    registry.register(association)

    assert registry.get(tenant_id, association.association_id) is association


def test_get_wrong_tenant_returns_none() -> None:
    registry = InMemoryCredentialReferenceRegistry()
    association = _attach(TenantId.generate())
    registry.register(association)

    assert registry.get(TenantId.generate(), association.association_id) is None


def test_get_unknown_id_returns_none() -> None:
    registry = InMemoryCredentialReferenceRegistry()
    assert registry.get(TenantId.generate(), CredentialAssociationId.generate()) is None


def test_duplicate_attachment_for_same_account_provider_raises() -> None:
    registry = InMemoryCredentialReferenceRegistry()
    tenant_id = TenantId.generate()
    account_id = AccountId.generate()
    provider_id = ProviderId.generate()
    registry.register(_attach(tenant_id, account_id, provider_id))

    with pytest.raises(DuplicateCredentialAttachmentError):
        registry.register(_attach(tenant_id, account_id, provider_id))


def test_different_providers_same_account_do_not_conflict() -> None:
    registry = InMemoryCredentialReferenceRegistry()
    tenant_id = TenantId.generate()
    account_id = AccountId.generate()
    registry.register(_attach(tenant_id, account_id, ProviderId.generate()))
    registry.register(_attach(tenant_id, account_id, ProviderId.generate()))  # no raise


def test_is_attached() -> None:
    registry = InMemoryCredentialReferenceRegistry()
    tenant_id = TenantId.generate()
    account_id = AccountId.generate()
    provider_id = ProviderId.generate()
    registry.register(_attach(tenant_id, account_id, provider_id))

    assert registry.is_attached(tenant_id, account_id, provider_id) is True
    assert registry.is_attached(tenant_id, account_id, ProviderId.generate()) is False


def test_get_active_for_account_provider() -> None:
    registry = InMemoryCredentialReferenceRegistry()
    tenant_id = TenantId.generate()
    account_id = AccountId.generate()
    provider_id = ProviderId.generate()
    association = _attach(tenant_id, account_id, provider_id)
    registry.register(association)

    assert registry.get_active_for_account_provider(tenant_id, account_id, provider_id) is association
    assert (
        registry.get_active_for_account_provider(tenant_id, account_id, ProviderId.generate())
        is None
    )


def test_list_scoped_to_tenant_and_account() -> None:
    registry = InMemoryCredentialReferenceRegistry()
    tenant_a, tenant_b = TenantId.generate(), TenantId.generate()
    account_x = AccountId.generate()
    assoc_a = _attach(tenant_a, account_x)
    assoc_b = _attach(tenant_b)
    registry.register(assoc_a)
    registry.register(assoc_b)

    assert registry.list(tenant_a) == (assoc_a,)
    assert registry.list(tenant_a, account_id=account_x) == (assoc_a,)
    assert registry.list(tenant_a, account_id=AccountId.generate()) == ()


def test_release_frees_slot_for_reattachment() -> None:
    registry = InMemoryCredentialReferenceRegistry()
    tenant_id = TenantId.generate()
    account_id = AccountId.generate()
    provider_id = ProviderId.generate()
    association = _attach(tenant_id, account_id, provider_id)
    registry.register(association)

    association.detach(tenant_id, NOW)
    registry.release(association)

    assert registry.is_attached(tenant_id, account_id, provider_id) is False
    registry.register(_attach(tenant_id, account_id, provider_id))  # no raise


def test_release_is_noop_when_not_detached() -> None:
    registry = InMemoryCredentialReferenceRegistry()
    tenant_id = TenantId.generate()
    account_id = AccountId.generate()
    provider_id = ProviderId.generate()
    association = _attach(tenant_id, account_id, provider_id)
    registry.register(association)

    registry.release(association)  # still ACTIVE, must not free the slot

    assert registry.is_attached(tenant_id, account_id, provider_id) is True
