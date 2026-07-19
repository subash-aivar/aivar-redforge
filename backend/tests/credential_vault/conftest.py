"""Shared fixtures for Credential Vault domain tests."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from credential_vault.domain.aggregates.credential import Credential
from credential_vault.domain.entities.credential_version import CredentialVersion
from credential_vault.domain.value_objects.audit_types import RotationTrigger
from credential_vault.domain.value_objects.credential_name import CredentialName
from credential_vault.domain.value_objects.credential_type import CredentialCategory, CredentialType
from credential_vault.domain.value_objects.identifiers import (
    CredentialId,
    ExpirationPolicyId,
    PrincipalId,
    RotationPolicyId,
    TenantId,
    VaultBackendId,
    VersionId,
)
from credential_vault.domain.value_objects.payloads import EncryptedPayload, KeyEnvelope
from credential_vault.domain.value_objects.rotation_context import RotationContext
from credential_vault.domain.value_objects.states import VersionState

pytest_plugins = ["tests.credential_vault.infrastructure.conftest"]


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "integration: marks tests requiring PostgreSQL",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if os.environ.get("TEST_DATABASE_URL"):
        return
    skip_integration = pytest.mark.skip(
        reason="TEST_DATABASE_URL not set — skipping integration tests"
    )
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 7, 19, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def tenant_id() -> TenantId:
    return TenantId(uuid4())


@pytest.fixture
def other_tenant_id() -> TenantId:
    return TenantId(uuid4())


@pytest.fixture
def credential_id() -> CredentialId:
    return CredentialId(uuid4())


@pytest.fixture
def version_id() -> VersionId:
    return VersionId(uuid4())


@pytest.fixture
def new_version_id() -> VersionId:
    return VersionId(uuid4())


@pytest.fixture
def principal_id() -> PrincipalId:
    return PrincipalId(uuid4())


@pytest.fixture
def vault_backend_id() -> VaultBackendId:
    return VaultBackendId(uuid4())


@pytest.fixture
def rotation_policy_id() -> RotationPolicyId:
    return RotationPolicyId(uuid4())


@pytest.fixture
def expiration_policy_id() -> ExpirationPolicyId:
    return ExpirationPolicyId(uuid4())


@pytest.fixture
def credential_name() -> CredentialName:
    return CredentialName("test-credential")


@pytest.fixture
def credential_type() -> CredentialType:
    return CredentialType(category=CredentialCategory.PASSWORD, subtype="DEFAULT", schema_id=None)


@pytest.fixture
def encrypted_payload() -> EncryptedPayload:
    return EncryptedPayload(
        ciphertext=b"ciphertext-bytes",
        algorithm="AES-256-GCM",
        iv=b"0123456789abcdef",
        tag=b"0123456789abcdef",
        payload_size=16,
    )


@pytest.fixture
def key_envelope(now: datetime) -> KeyEnvelope:
    return KeyEnvelope(
        wrapped_dek=b"wrapped-dek-bytes",
        master_key_id="master-key-1",
        wrapping_algorithm="RSA-OAEP",
        created_at=now,
    )


@pytest.fixture
def rotation_context(
    principal_id: PrincipalId,
    version_id: VersionId,
) -> RotationContext:
    return RotationContext(
        trigger=RotationTrigger.MANUAL,
        initiated_by=principal_id,
        previous_version_id=version_id,
        policy_id=None,
        notes=None,
    )


def make_credential(
    *,
    credential_id: CredentialId,
    tenant_id: TenantId,
    name: CredentialName | None = None,
    credential_type: CredentialType | None = None,
    owner_principal: PrincipalId,
    vault_backend_id: VaultBackendId,
    now: datetime,
    description: str | None = None,
    tags: dict[str, str] | None = None,
) -> Credential:
    return Credential.create(
        credential_id=credential_id,
        tenant_id=tenant_id,
        name=name or CredentialName("test-credential"),
        credential_type=credential_type
        or CredentialType(category=CredentialCategory.PASSWORD, subtype="DEFAULT", schema_id=None),
        owner_principal=owner_principal,
        vault_backend_id=vault_backend_id,
        description=description,
        tags=tags or {},
        now=now,
    )


def make_active_credential(
    *,
    credential_id: CredentialId,
    tenant_id: TenantId,
    version_id: VersionId,
    owner_principal: PrincipalId,
    vault_backend_id: VaultBackendId,
    now: datetime,
) -> Credential:
    credential = make_credential(
        credential_id=credential_id,
        tenant_id=tenant_id,
        owner_principal=owner_principal,
        vault_backend_id=vault_backend_id,
        now=now,
    )
    credential.pop_events()
    credential.activate(tenant_id, version_id, now)
    return credential


def make_credential_version(
    *,
    version_id: VersionId,
    credential_id: CredentialId,
    tenant_id: TenantId,
    owner_principal: PrincipalId,
    encrypted_payload: EncryptedPayload,
    key_envelope: KeyEnvelope,
    now: datetime,
    version_number: int = 1,
    version_state: VersionState = VersionState.ACTIVE,
    expires_at: datetime | None = None,
) -> CredentialVersion:
    return CredentialVersion(
        version_id=version_id,
        credential_id=credential_id,
        tenant_id=tenant_id,
        version_number=version_number,
        encrypted_payload=encrypted_payload,
        key_envelope=key_envelope,
        version_state=version_state,
        rotation_context=None,
        created_at=now,
        created_by=owner_principal,
        expires_at=expires_at,
    )


def advance(now: datetime, **kwargs: int) -> datetime:
    return now + timedelta(**kwargs)
