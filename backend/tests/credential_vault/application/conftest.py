"""Shared fixtures for Credential Vault application-layer tests."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4, uuid7

import pytest

from credential_vault.application.ports.i_event_publisher import IEventPublisher
from credential_vault.application.services.credential_application_service import (
    CredentialApplicationService,
)
from credential_vault.domain.aggregates.audit_log import AuditLog
from credential_vault.domain.aggregates.credential import Credential
from credential_vault.domain.aggregates.expiration_policy import ExpirationPolicy
from credential_vault.domain.aggregates.rotation_policy import RotationPolicy
from credential_vault.domain.aggregates.vault_backend import VaultBackend
from credential_vault.domain.entities.credential_version import CredentialVersion
from credential_vault.domain.ports.i_approval_port import IApprovalPort
from credential_vault.domain.ports.i_encryption_port import IEncryptionPort
from credential_vault.domain.ports.i_key_management_port import IKeyManagementPort
from credential_vault.domain.ports.i_permission_port import IPermissionPort
from credential_vault.domain.repositories.i_audit_log_repository import IAuditLogRepository
from credential_vault.domain.repositories.i_credential_repository import (
    ICredentialRepository,
)
from credential_vault.domain.repositories.i_credential_version_repository import (
    ICredentialVersionRepository,
)
from credential_vault.domain.repositories.i_expiration_policy_repository import (
    IExpirationPolicyRepository,
)
from credential_vault.domain.repositories.i_rotation_policy_repository import (
    IRotationPolicyRepository,
)
from credential_vault.domain.repositories.i_vault_backend_repository import (
    IVaultBackendRepository,
)
from credential_vault.domain.services.access_control_policy import AccessControlPolicyService
from credential_vault.domain.services.break_glass_service import BreakGlassService
from credential_vault.domain.services.credential_resolver import CredentialResolverService
from credential_vault.domain.services.recovery_service import RecoveryService
from credential_vault.domain.value_objects.audit_types import VaultBackendType
from credential_vault.domain.value_objects.credential_name import CredentialName
from credential_vault.domain.value_objects.credential_type import (
    CredentialCategory,
    CredentialType,
)
from credential_vault.domain.value_objects.identifiers import (
    AuditLogId,
    CredentialId,
    ExpirationPolicyId,
    PrincipalId,
    RotationPolicyId,
    TenantId,
    VaultBackendId,
    VersionId,
)
from credential_vault.domain.value_objects.payloads import EncryptedPayload, KeyEnvelope
from credential_vault.domain.value_objects.states import CredentialState, VersionState


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 7, 19, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def tenant_uuid():
    return uuid4()


@pytest.fixture
def principal_uuid():
    return uuid4()


@pytest.fixture
def credential_uuid():
    return uuid4()


@pytest.fixture
def version_uuid():
    return uuid4()


@pytest.fixture
def backend_uuid():
    return uuid4()


@pytest.fixture
def fake_key_envelope(now: datetime) -> KeyEnvelope:
    return KeyEnvelope(
        wrapped_dek=b"wrapped-dek-bytes-nonempty",
        master_key_id="master-key-1",
        wrapping_algorithm="RSA-OAEP",
        created_at=now,
    )


@pytest.fixture
def fake_encrypted_payload() -> EncryptedPayload:
    return EncryptedPayload(
        ciphertext=b"ciphertext-bytes",
        algorithm="AES-256-GCM",
        iv=b"0123456789abcdef",
        tag=b"0123456789abcdef",
        payload_size=16,
    )


@pytest.fixture
def mock_uow() -> AsyncMock:
    uow = AsyncMock()
    uow.__aenter__.return_value = uow
    uow.__aexit__.return_value = None
    uow.credentials = AsyncMock(spec=ICredentialRepository)
    uow.versions = AsyncMock(spec=ICredentialVersionRepository)
    uow.rotation_policies = AsyncMock(spec=IRotationPolicyRepository)
    uow.expiration_policies = AsyncMock(spec=IExpirationPolicyRepository)
    uow.vault_backends = AsyncMock(spec=IVaultBackendRepository)
    uow.audit_logs = AsyncMock(spec=IAuditLogRepository)
    uow.commit = AsyncMock()
    uow.rollback = AsyncMock()
    return uow


@pytest.fixture
def mock_uow_factory(mock_uow: AsyncMock) -> MagicMock:
    return MagicMock(return_value=mock_uow)


@pytest.fixture
def mock_event_publisher() -> AsyncMock:
    publisher = AsyncMock(spec=IEventPublisher)
    publisher.publish_batch.return_value = None
    return publisher


@pytest.fixture
def mock_key_mgmt_port(fake_key_envelope: KeyEnvelope) -> AsyncMock:
    port = AsyncMock(spec=IKeyManagementPort)
    port.generate_dek.return_value = (b"fake-dek-32bytes-padding-here-x", fake_key_envelope)
    port.unwrap_dek.return_value = b"fake-dek-32bytes-padding-here-x"
    return port


@pytest.fixture
def mock_encryption_port(fake_encrypted_payload: EncryptedPayload) -> AsyncMock:
    port = AsyncMock(spec=IEncryptionPort)
    port.encrypt.return_value = fake_encrypted_payload
    port.decrypt.return_value = b"decrypted-plaintext"
    return port


@pytest.fixture
def mock_permission_port() -> AsyncMock:
    port = AsyncMock(spec=IPermissionPort)
    port.has_permission.return_value = True
    return port


@pytest.fixture
def mock_approval_port() -> AsyncMock:
    port = AsyncMock(spec=IApprovalPort)
    port.is_approved.return_value = True
    port.get_approver_count.return_value = (2, 2)
    return port


@pytest.fixture
def access_control(mock_permission_port: AsyncMock) -> AccessControlPolicyService:
    return AccessControlPolicyService(mock_permission_port)


@pytest.fixture
def break_glass_svc(mock_approval_port: AsyncMock) -> BreakGlassService:
    return BreakGlassService(mock_approval_port)


@pytest.fixture
def recovery_svc(mock_approval_port: AsyncMock) -> RecoveryService:
    return RecoveryService(mock_approval_port)


@pytest.fixture
def resolver_svc(
    mock_encryption_port: AsyncMock,
    mock_key_mgmt_port: AsyncMock,
    mock_permission_port: AsyncMock,
    access_control: AccessControlPolicyService,
    break_glass_svc: BreakGlassService,
) -> CredentialResolverService:
    return CredentialResolverService(
        encryption_port=mock_encryption_port,
        key_mgmt_port=mock_key_mgmt_port,
        permission_port=mock_permission_port,
        access_control=access_control,
        break_glass_svc=break_glass_svc,
    )


@pytest.fixture
def credential_service(
    mock_uow_factory: MagicMock,
    mock_event_publisher: AsyncMock,
    mock_key_mgmt_port: AsyncMock,
    mock_encryption_port: AsyncMock,
    mock_permission_port: AsyncMock,
    mock_approval_port: AsyncMock,
    access_control: AccessControlPolicyService,
    break_glass_svc: BreakGlassService,
    recovery_svc: RecoveryService,
    resolver_svc: CredentialResolverService,
) -> CredentialApplicationService:
    return CredentialApplicationService(
        uow_factory=mock_uow_factory,
        event_publisher=mock_event_publisher,
        key_mgmt_port=mock_key_mgmt_port,
        encryption_port=mock_encryption_port,
        permission_port=mock_permission_port,
        approval_port=mock_approval_port,
        access_control=access_control,
        break_glass_svc=break_glass_svc,
        recovery_svc=recovery_svc,
        resolver_svc=resolver_svc,
    )


def make_credential(
    *,
    state: CredentialState = CredentialState.ACTIVE,
    tenant_id: TenantId | None = None,
    credential_id: CredentialId | None = None,
    principal_id: PrincipalId | None = None,
    vault_backend_id: VaultBackendId | None = None,
    version_id: VersionId | None = None,
    now: datetime | None = None,
    name: str = "test-credential",
    tags: dict[str, str] | None = None,
    description: str | None = "desc",
) -> Credential:
    """Build a real Credential aggregate in the requested state."""
    ts = now or datetime.now(UTC)
    tid = tenant_id or TenantId(uuid4())
    cid = credential_id or CredentialId(uuid4())
    pid = principal_id or PrincipalId(uuid4())
    bid = vault_backend_id or VaultBackendId(uuid4())
    vid = version_id or VersionId(uuid4())

    credential = Credential.create(
        cid,
        tid,
        CredentialName(name),
        CredentialType(CredentialCategory.API_KEY, "GENERIC", None),
        pid,
        bid,
        description,
        tags if tags is not None else {"env": "test"},
        ts,
    )
    credential.pop_events()

    if state == CredentialState.PENDING:
        return credential

    credential.activate(tid, vid, ts)
    credential.pop_events()

    if state == CredentialState.ACTIVE:
        return credential
    if state == CredentialState.ROTATING:
        from credential_vault.domain.value_objects.audit_types import RotationTrigger
        from credential_vault.domain.value_objects.rotation_context import RotationContext

        ctx = RotationContext(
            RotationTrigger.MANUAL,
            pid,
            vid,
            None,
            None,
        )
        credential.begin_rotation(tid, VersionId(uuid7()), ctx, ts)
        credential.pop_events()
        return credential
    if state == CredentialState.DISABLED:
        credential.disable(tid, pid, "disabled for test", ts)
        credential.pop_events()
        return credential
    if state == CredentialState.REVOKED:
        credential.revoke(tid, pid, "revoked for test", ts)
        credential.pop_events()
        return credential
    if state == CredentialState.EXPIRED:
        credential.expire(tid, ts)
        credential.pop_events()
        return credential
    if state == CredentialState.DELETED:
        credential.disable(tid, pid, "prep delete", ts)
        credential.pop_events()
        credential.hard_delete(tid, pid, ts)
        credential.pop_events()
        return credential

    raise ValueError(f"unsupported state {state}")


def make_version(
    *,
    state: VersionState = VersionState.ACTIVE,
    credential_id: CredentialId | None = None,
    tenant_id: TenantId | None = None,
    version_id: VersionId | None = None,
    principal_id: PrincipalId | None = None,
    version_number: int = 1,
    now: datetime | None = None,
    encrypted_payload: EncryptedPayload | None = None,
    key_envelope: KeyEnvelope | None = None,
) -> CredentialVersion:
    ts = now or datetime.now(UTC)
    payload = encrypted_payload or EncryptedPayload(
        ciphertext=b"ciphertext-bytes",
        algorithm="AES-256-GCM",
        iv=b"0123456789abcdef",
        tag=b"0123456789abcdef",
        payload_size=16,
    )
    envelope = key_envelope or KeyEnvelope(
        wrapped_dek=b"wrapped-dek-bytes-nonempty",
        master_key_id="master-key-1",
        wrapping_algorithm="RSA-OAEP",
        created_at=ts,
    )
    return CredentialVersion(
        version_id or VersionId(uuid4()),
        credential_id or CredentialId(uuid4()),
        tenant_id or TenantId(uuid4()),
        version_number,
        payload,
        envelope,
        state,
        None,
        ts,
        principal_id or PrincipalId(uuid4()),
        None,
    )


def make_audit_log(
    credential_id: CredentialId | None = None,
    tenant_id: TenantId | None = None,
    now: datetime | None = None,
) -> AuditLog:
    return AuditLog.create(
        AuditLogId(uuid4()),
        credential_id or CredentialId(uuid4()),
        tenant_id or TenantId(uuid4()),
        now or datetime.now(UTC),
    )


def make_rotation_policy(
    *,
    tenant_id: TenantId | None = None,
    name: str = "rot-policy",
    now: datetime | None = None,
) -> RotationPolicy:
    return RotationPolicy.create(
        RotationPolicyId(uuid4()),
        tenant_id or TenantId(uuid4()),
        name,
        30,
        5,
        7,
        True,
        now or datetime.now(UTC),
    )


def make_expiration_policy(
    *,
    tenant_id: TenantId | None = None,
    name: str = "exp-policy",
    now: datetime | None = None,
) -> ExpirationPolicy:
    return ExpirationPolicy.create(
        ExpirationPolicyId(uuid4()),
        tenant_id or TenantId(uuid4()),
        name,
        90,
        14,
        True,
        now or datetime.now(UTC),
    )


def make_vault_backend(
    *,
    tenant_id: TenantId | None = None,
    name: str = "backend",
    now: datetime | None = None,
) -> VaultBackend:
    return VaultBackend.create(
        VaultBackendId(uuid4()),
        tenant_id or TenantId(uuid4()),
        name,
        VaultBackendType.LOCAL_ENCRYPTED,
        {"path": "/secrets"},
        True,
        now or datetime.now(UTC),
    )
