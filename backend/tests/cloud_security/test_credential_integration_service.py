from __future__ import annotations

import dataclasses
from datetime import UTC, datetime
from uuid import UUID

import pytest

from cloud_security.application.commands.credential_commands import (
    AttachCredentialCommand,
    BatchCredentialCommand,
    DetachCredentialCommand,
    ReplaceCredentialCommand,
    RotateCredentialReferenceCommand,
    ValidateCredentialReferenceCommand,
)
from cloud_security.application.dtos.credential_outcomes import (
    BatchCredentialStatus,
    CredentialValidationStatus,
)
from cloud_security.application.exceptions import (
    AccountMismatchError,
    CredentialAssociationNotFoundError,
    DuplicateCredentialAttachmentError,
    EmptyBatchCredentialError,
    ProviderMismatchError,
)
from cloud_security.application.registry.in_memory_credential_reference_registry import (
    InMemoryCredentialReferenceRegistry,
)
from cloud_security.application.services.credential_integration_service import (
    CredentialIntegrationService,
)
from cloud_security.domain.aggregates.cloud_account import CloudAccount
from cloud_security.domain.aggregates.cloud_provider_registration import (
    CloudProviderRegistration,
)
from cloud_security.domain.exceptions.domain_exceptions import (
    RedundantCredentialReferenceError,
    TenantMismatch,
)
from cloud_security.domain.value_objects.cloud_credential_reference import (
    CloudCredentialReference,
)
from cloud_security.domain.value_objects.cloud_tag import CloudTagSet
from cloud_security.domain.value_objects.enums import CloudPlatformType
from cloud_security.domain.value_objects.identifiers import (
    AccountId,
    CredentialAssociationId,
    ProviderId,
    TenantId,
)
from cloud_security.domain.value_objects.provider_capability_set import ProviderCapabilitySet

NOW = datetime.now(UTC)


def _ref(credential_id: str = "cred-1") -> CloudCredentialReference:
    return CloudCredentialReference(credential_id=credential_id, credential_type="role_arn")


def _account(tenant_id: TenantId, account_id: AccountId | None = None) -> CloudAccount:
    return CloudAccount.register(
        account_id=account_id or AccountId.generate(),
        tenant_id=tenant_id,
        provider_id=ProviderId.generate(),
        platform_type=CloudPlatformType.AWS,
        display_name="prod-account",
        tags=CloudTagSet(),
        now=NOW,
    )


def _provider(tenant_id: TenantId, provider_id: ProviderId | None = None) -> CloudProviderRegistration:
    return CloudProviderRegistration.register(
        provider_id=provider_id or ProviderId.generate(),
        tenant_id=tenant_id,
        platform_type=CloudPlatformType.AWS,
        display_name="aws-primary",
        capabilities=ProviderCapabilitySet(),
        now=NOW,
    )


def _association_id(outcome) -> CredentialAssociationId:
    return CredentialAssociationId(UUID(outcome.record.association_id))


def _service(registry=None, credential_provider=None):
    return CredentialIntegrationService(
        registry=registry or InMemoryCredentialReferenceRegistry(),
        credential_provider=credential_provider,
    )


def _attach_cmd(tenant_id, account_id, provider_id, **overrides) -> AttachCredentialCommand:
    defaults = {
        "tenant_id": tenant_id,
        "account_id": account_id,
        "provider_id": provider_id,
        "reference": _ref(),
    }
    defaults.update(overrides)
    return AttachCredentialCommand(**defaults)


# ---------------------------------------------------------------------------
# attach
# ---------------------------------------------------------------------------


def test_attach_credential_returns_dto() -> None:
    service = _service()
    tenant_id = TenantId.generate()
    account = _account(tenant_id)
    provider = _provider(tenant_id)

    outcome = service.attach_credential(
        _attach_cmd(tenant_id, account.account_id, provider.provider_id), account, provider
    )

    assert outcome.record.active_credential_id == "cred-1"
    assert outcome.record.status.value == "active"


def test_attach_rejects_account_mismatch() -> None:
    service = _service()
    tenant_id = TenantId.generate()
    account = _account(tenant_id)
    provider = _provider(tenant_id)
    other_account_id = AccountId.generate()

    with pytest.raises(AccountMismatchError):
        service.attach_credential(
            _attach_cmd(tenant_id, other_account_id, provider.provider_id), account, provider
        )


def test_attach_rejects_provider_mismatch() -> None:
    service = _service()
    tenant_id = TenantId.generate()
    account = _account(tenant_id)
    provider = _provider(tenant_id)
    other_provider_id = ProviderId.generate()

    with pytest.raises(ProviderMismatchError):
        service.attach_credential(
            _attach_cmd(tenant_id, account.account_id, other_provider_id), account, provider
        )


def test_attach_duplicate_raises() -> None:
    registry = InMemoryCredentialReferenceRegistry()
    service = _service(registry)
    tenant_id = TenantId.generate()
    account = _account(tenant_id)
    provider = _provider(tenant_id)
    cmd = _attach_cmd(tenant_id, account.account_id, provider.provider_id)
    service.attach_credential(cmd, account, provider)

    with pytest.raises(DuplicateCredentialAttachmentError):
        service.attach_credential(cmd, account, provider)


# ---------------------------------------------------------------------------
# replace / rotate
# ---------------------------------------------------------------------------


def test_replace_credential_tracks_rotation_metadata() -> None:
    registry = InMemoryCredentialReferenceRegistry()
    service = _service(registry)
    tenant_id = TenantId.generate()
    account = _account(tenant_id)
    provider = _provider(tenant_id)
    outcome = service.attach_credential(
        _attach_cmd(tenant_id, account.account_id, provider.provider_id), account, provider
    )
    association_id = _association_id(outcome)

    replaced = service.replace_credential(
        tenant_id,
        association_id,
        ReplaceCredentialCommand(tenant_id=tenant_id, reference=_ref("cred-2")),
    )

    assert replaced.record.active_credential_id == "cred-2"
    assert replaced.record.previous_credential_id == "cred-1"
    assert replaced.record.rotated_at is not None


def test_replace_unknown_association_raises() -> None:
    service = _service()
    tenant_id = TenantId.generate()
    with pytest.raises(CredentialAssociationNotFoundError):
        service.replace_credential(
            tenant_id,
            CredentialAssociationId.generate(),
            ReplaceCredentialCommand(tenant_id=tenant_id, reference=_ref()),
        )


def test_replace_with_same_reference_raises() -> None:
    registry = InMemoryCredentialReferenceRegistry()
    service = _service(registry)
    tenant_id = TenantId.generate()
    account = _account(tenant_id)
    provider = _provider(tenant_id)
    outcome = service.attach_credential(
        _attach_cmd(tenant_id, account.account_id, provider.provider_id), account, provider
    )
    association_id = _association_id(outcome)

    with pytest.raises(RedundantCredentialReferenceError):
        service.replace_credential(
            tenant_id,
            association_id,
            ReplaceCredentialCommand(tenant_id=tenant_id, reference=_ref("cred-1")),
        )


def test_rotate_credential_reference_behaves_like_replace() -> None:
    registry = InMemoryCredentialReferenceRegistry()
    service = _service(registry)
    tenant_id = TenantId.generate()
    account = _account(tenant_id)
    provider = _provider(tenant_id)
    outcome = service.attach_credential(
        _attach_cmd(tenant_id, account.account_id, provider.provider_id), account, provider
    )
    association_id = _association_id(outcome)

    rotated = service.rotate_credential_reference(
        tenant_id,
        association_id,
        RotateCredentialReferenceCommand(tenant_id=tenant_id, reference=_ref("cred-2")),
    )

    assert rotated.record.active_credential_id == "cred-2"


# ---------------------------------------------------------------------------
# detach
# ---------------------------------------------------------------------------


def test_detach_credential_releases_registry_slot() -> None:
    registry = InMemoryCredentialReferenceRegistry()
    service = _service(registry)
    tenant_id = TenantId.generate()
    account = _account(tenant_id)
    provider = _provider(tenant_id)
    cmd = _attach_cmd(tenant_id, account.account_id, provider.provider_id)
    outcome = service.attach_credential(cmd, account, provider)
    association_id = _association_id(outcome)

    detached = service.detach_credential(
        tenant_id, association_id, DetachCredentialCommand(tenant_id=tenant_id)
    )

    assert detached.association_id == outcome.record.association_id
    assert registry.is_attached(tenant_id, account.account_id, provider.provider_id) is False

    # a fresh attach for the same (account, provider) now succeeds
    service.attach_credential(cmd, account, provider)


def test_detach_unknown_association_raises() -> None:
    service = _service()
    tenant_id = TenantId.generate()
    with pytest.raises(CredentialAssociationNotFoundError):
        service.detach_credential(
            tenant_id, CredentialAssociationId.generate(), DetachCredentialCommand(tenant_id=tenant_id)
        )


def test_detach_wrong_tenant_raises() -> None:
    registry = InMemoryCredentialReferenceRegistry()
    service = _service(registry)
    tenant_id = TenantId.generate()
    account = _account(tenant_id)
    provider = _provider(tenant_id)
    outcome = service.attach_credential(
        _attach_cmd(tenant_id, account.account_id, provider.provider_id), account, provider
    )
    association_id = _association_id(outcome)

    with pytest.raises(TenantMismatch):
        service.detach_credential(
            tenant_id, association_id, DetachCredentialCommand(tenant_id=TenantId.generate())
        )


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------


def test_validate_without_provider_is_unverifiable() -> None:
    registry = InMemoryCredentialReferenceRegistry()
    service = _service(registry)
    tenant_id = TenantId.generate()
    account = _account(tenant_id)
    provider = _provider(tenant_id)
    outcome = service.attach_credential(
        _attach_cmd(tenant_id, account.account_id, provider.provider_id), account, provider
    )
    association_id = _association_id(outcome)

    validated = service.validate_credential_reference(
        tenant_id, association_id, ValidateCredentialReferenceCommand(tenant_id=tenant_id)
    )

    assert validated.status == CredentialValidationStatus.UNVERIFIABLE


def test_validate_with_provider_returns_valid_or_invalid() -> None:
    class FakeCredentialProvider:
        def validate(self, reference):
            return reference.credential_id == "cred-1"

    registry = InMemoryCredentialReferenceRegistry()
    service = _service(registry, credential_provider=FakeCredentialProvider())
    tenant_id = TenantId.generate()
    account = _account(tenant_id)
    provider = _provider(tenant_id)
    outcome = service.attach_credential(
        _attach_cmd(tenant_id, account.account_id, provider.provider_id), account, provider
    )
    association_id = _association_id(outcome)

    validated = service.validate_credential_reference(
        tenant_id, association_id, ValidateCredentialReferenceCommand(tenant_id=tenant_id)
    )
    assert validated.status == CredentialValidationStatus.VALID


def test_validate_provider_exception_yields_invalid() -> None:
    class ExplodingProvider:
        def validate(self, reference):
            raise RuntimeError("vault unavailable")

    registry = InMemoryCredentialReferenceRegistry()
    service = _service(registry, credential_provider=ExplodingProvider())
    tenant_id = TenantId.generate()
    account = _account(tenant_id)
    provider = _provider(tenant_id)
    outcome = service.attach_credential(
        _attach_cmd(tenant_id, account.account_id, provider.provider_id), account, provider
    )
    association_id = _association_id(outcome)

    validated = service.validate_credential_reference(
        tenant_id, association_id, ValidateCredentialReferenceCommand(tenant_id=tenant_id)
    )
    assert validated.status == CredentialValidationStatus.INVALID


# ---------------------------------------------------------------------------
# batch
# ---------------------------------------------------------------------------


def test_batch_attach_all_succeed() -> None:
    service = _service()
    tenant_id = TenantId.generate()
    account1, account2 = _account(tenant_id), _account(tenant_id)
    provider = _provider(tenant_id)
    commands = (
        _attach_cmd(tenant_id, account1.account_id, provider.provider_id),
        _attach_cmd(tenant_id, account2.account_id, provider.provider_id),
    )
    accounts = {str(account1.account_id): account1, str(account2.account_id): account2}
    providers = {str(provider.provider_id): provider}

    result = service.register_batch(
        BatchCredentialCommand(tenant_id=tenant_id, commands=commands), accounts, providers
    )

    assert result.status == BatchCredentialStatus.SUCCEEDED
    assert result.succeeded_count == 2
    assert result.failed_count == 0


def test_batch_attach_empty_raises() -> None:
    service = _service()
    with pytest.raises(EmptyBatchCredentialError):
        service.register_batch(BatchCredentialCommand(tenant_id=TenantId.generate(), commands=()), {}, {})


def test_batch_attach_partial_failure_on_duplicate() -> None:
    service = _service()
    tenant_id = TenantId.generate()
    account = _account(tenant_id)
    provider = _provider(tenant_id)
    cmd = _attach_cmd(tenant_id, account.account_id, provider.provider_id)
    commands = (cmd, cmd)
    accounts = {str(account.account_id): account}
    providers = {str(provider.provider_id): provider}

    result = service.register_batch(
        BatchCredentialCommand(tenant_id=tenant_id, commands=commands), accounts, providers
    )

    assert result.status == BatchCredentialStatus.PARTIALLY_SUCCEEDED
    assert result.succeeded_count == 1
    assert result.failed_count == 1


# ---------------------------------------------------------------------------
# queries
# ---------------------------------------------------------------------------


def test_get_credential_reference_returns_none_when_missing() -> None:
    from cloud_security.application.queries.credential_queries import GetCredentialReferenceQuery

    service = _service()
    result = service.get_credential_reference(
        GetCredentialReferenceQuery(
            tenant_id=TenantId.generate(), association_id=CredentialAssociationId.generate()
        )
    )
    assert result is None


def test_list_credential_references() -> None:
    from cloud_security.application.queries.credential_queries import ListCredentialReferencesQuery

    registry = InMemoryCredentialReferenceRegistry()
    service = _service(registry)
    tenant_id = TenantId.generate()
    account = _account(tenant_id)
    provider = _provider(tenant_id)
    service.attach_credential(
        _attach_cmd(tenant_id, account.account_id, provider.provider_id), account, provider
    )

    results = service.list_credential_references(ListCredentialReferencesQuery(tenant_id=tenant_id))
    assert len(results) == 1


def test_list_accounts_without_credentials() -> None:
    from cloud_security.application.queries.credential_queries import (
        ListAccountsWithoutCredentialsQuery,
    )

    registry = InMemoryCredentialReferenceRegistry()
    service = _service(registry)
    tenant_id = TenantId.generate()
    account_with = _account(tenant_id)
    account_without = _account(tenant_id)
    provider = _provider(tenant_id)
    service.attach_credential(
        _attach_cmd(tenant_id, account_with.account_id, provider.provider_id),
        account_with,
        provider,
    )

    without = service.list_accounts_without_credentials(
        ListAccountsWithoutCredentialsQuery(
            tenant_id=tenant_id,
            account_ids=(account_with.account_id, account_without.account_id),
        )
    )

    assert without == (account_without.account_id,)


def test_list_accounts_without_credentials_after_detach() -> None:
    from cloud_security.application.queries.credential_queries import (
        ListAccountsWithoutCredentialsQuery,
    )

    registry = InMemoryCredentialReferenceRegistry()
    service = _service(registry)
    tenant_id = TenantId.generate()
    account = _account(tenant_id)
    provider = _provider(tenant_id)
    outcome = service.attach_credential(
        _attach_cmd(tenant_id, account.account_id, provider.provider_id), account, provider
    )
    association_id = _association_id(outcome)
    service.detach_credential(tenant_id, association_id, DetachCredentialCommand(tenant_id=tenant_id))

    without = service.list_accounts_without_credentials(
        ListAccountsWithoutCredentialsQuery(tenant_id=tenant_id, account_ids=(account.account_id,))
    )

    assert without == (account.account_id,)


# ---------------------------------------------------------------------------
# immutability
# ---------------------------------------------------------------------------


def test_credential_attached_outcome_is_frozen() -> None:
    service = _service()
    tenant_id = TenantId.generate()
    account = _account(tenant_id)
    provider = _provider(tenant_id)
    outcome = service.attach_credential(
        _attach_cmd(tenant_id, account.account_id, provider.provider_id), account, provider
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        outcome.record = None  # type: ignore[misc]


def test_batch_credential_result_is_frozen() -> None:
    service = _service()
    tenant_id = TenantId.generate()
    account = _account(tenant_id)
    provider = _provider(tenant_id)
    result = service.register_batch(
        BatchCredentialCommand(
            tenant_id=tenant_id,
            commands=(_attach_cmd(tenant_id, account.account_id, provider.provider_id),),
        ),
        {str(account.account_id): account},
        {str(provider.provider_id): provider},
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.status = BatchCredentialStatus.FAILED  # type: ignore[misc]
