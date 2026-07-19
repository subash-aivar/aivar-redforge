"""Shared helpers for credential vault repository integration tests."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import uuid4, uuid7

from credential_vault.domain.aggregates.credential import Credential
from credential_vault.domain.aggregates.rotation_policy import RotationPolicy
from credential_vault.domain.aggregates.vault_backend import VaultBackend
from credential_vault.domain.entities.credential_version import CredentialVersion
from credential_vault.domain.value_objects.audit_types import VaultBackendType
from credential_vault.domain.value_objects.credential_name import CredentialName
from credential_vault.domain.value_objects.credential_type import (
    CredentialCategory,
    CredentialType,
)
from credential_vault.domain.value_objects.identifiers import (
    CredentialId,
    PrincipalId,
    RotationPolicyId,
    TenantId,
    VaultBackendId,
    VersionId,
)
from credential_vault.domain.value_objects.payloads import EncryptedPayload, KeyEnvelope
from credential_vault.domain.value_objects.states import CredentialState, VersionState

if TYPE_CHECKING:
    from credential_vault.infrastructure.persistence.unit_of_work import CredentialVaultUnitOfWork


async def register_backend(
    uow: CredentialVaultUnitOfWork,
    tenant_id: TenantId,
    now: datetime,
) -> VaultBackend:
    backend = VaultBackend.create(
        VaultBackendId(uuid7()),
        tenant_id,
        f"backend-{uuid4().hex[:8]}",
        VaultBackendType.LOCAL_ENCRYPTED,
        {"region": "us-east-1"},
        True,
        now,
    )
    await uow.vault_backends.save(backend)
    return backend


def make_credential(
    tenant_id: TenantId,
    backend_id: VaultBackendId,
    now: datetime,
    name: str | None = None,
    *,
    state: CredentialState = CredentialState.ACTIVE,
    rotation_policy_id: RotationPolicyId | None = None,
    description: str | None = "test description",
    tags: dict[str, str] | None = None,
) -> Credential:
    return Credential(
        CredentialId(uuid7()),
        tenant_id,
        CredentialName(name or f"cred-{uuid4().hex[:8]}"),
        CredentialType(CredentialCategory.API_KEY, "OPENAI", None),
        state,
        PrincipalId(uuid7()),
        None,
        rotation_policy_id,
        None,
        backend_id,
        description,
        tags or {"env": "test"},
        now,
        now,
        0,
    )


def make_version(
    credential: Credential,
    now: datetime,
    *,
    state: VersionState = VersionState.ACTIVE,
    number: int = 1,
) -> CredentialVersion:
    return CredentialVersion(
        VersionId(uuid7()),
        credential.credential_id,
        credential.tenant_id,
        number,
        EncryptedPayload(b"ct", "AES-256-GCM", b"iviviviviviv", b"tagtagtagtagtagt", 4),
        KeyEnvelope(b"wrapped", "local-master-v1", "AES-KW-256", now),
        state,
        None,
        now,
        credential.owner_principal,
        None,
    )


async def register_rotation_policy(
    uow: CredentialVaultUnitOfWork,
    tenant_id: TenantId,
    now: datetime,
    name: str | None = None,
) -> RotationPolicy:
    policy = RotationPolicy.create(
        RotationPolicyId(uuid7()),
        tenant_id,
        name or f"policy-{uuid4().hex[:8]}",
        interval_days=30,
        max_versions_kept=5,
        notify_days_before=7,
        auto_rotate=True,
        now=now,
    )
    await uow.rotation_policies.save(policy)
    return policy
