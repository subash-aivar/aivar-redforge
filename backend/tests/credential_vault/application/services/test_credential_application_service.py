"""Production tests for CredentialApplicationService (M25B Phase 7)."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from tests.credential_vault.application.conftest import (
    make_audit_log,
    make_credential,
    make_expiration_policy,
    make_rotation_policy,
    make_vault_backend,
    make_version,
)

from credential_vault.application.commands.credential_commands import (
    AbortRotationCommand,
    AttachExpirationPolicyCommand,
    AttachRotationPolicyCommand,
    CommitRotationCommand,
    CreateCredentialCommand,
    DetachExpirationPolicyCommand,
    DetachRotationPolicyCommand,
    DisableCredentialCommand,
    EmergencyRevokeCommand,
    EnableCredentialCommand,
    ExpireCredentialCommand,
    HardDeleteCredentialCommand,
    RecoverCredentialCommand,
    ResolveCredentialCommand,
    RevokeCredentialCommand,
    RollbackVersionCommand,
    RotateCredentialCommand,
    UpdateCredentialMetadataCommand,
)
from credential_vault.application.dtos.credential_dtos import CredentialDTO, ResolvedSecretDTO
from credential_vault.application.exceptions import (
    ApplicationAuditFailure,
    ApplicationPortError,
    ApplicationValidationError,
)
from credential_vault.application.services.credential_application_service import (
    CredentialApplicationService,
)
from credential_vault.domain.events.credential_events import (
    BreakGlassAccessed,
    CredentialAccessed,
    CredentialCreated,
    CredentialDeleted,
    CredentialDisabled,
    CredentialEnabled,
    CredentialExpired,
    CredentialMetadataUpdated,
    CredentialRecovered,
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
    AccessDenied,
    ConcurrentRotationConflict,
    CredentialAlreadyExists,
    CredentialIsRevoked,
    CredentialNotFound,
    InsufficientApprovers,
    InvalidStateTransition,
    OptimisticLockConflict,
    VaultBackendNotFound,
)
from credential_vault.domain.value_objects.identifiers import (
    CredentialId,
    PrincipalId,
    TenantId,
    VaultBackendId,
    VersionId,
)
from credential_vault.domain.value_objects.states import CredentialState, VersionState
from redforge.shared.identifiers import EntityId

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _create_cmd(
    *,
    tenant_id=None,
    name: str = "prod-credential",
    category: str = "API_KEY",
    subtype: str = "GENERIC",
    schema_id=None,
    owner_principal_id=None,
    vault_backend_id=None,
    plaintext_secret: bytes = b"super-secret-value",
    description: str | None = "production credential",
    tags: dict[str, str] | None = None,
    expires_at: datetime | None = None,
) -> CreateCredentialCommand:
    return CreateCredentialCommand(
        tenant_id=tenant_id or uuid4(),
        name=name,
        category=category,
        subtype=subtype,
        schema_id=schema_id,
        owner_principal_id=owner_principal_id or EntityId.generate(),
        vault_backend_id=vault_backend_id or uuid4(),
        plaintext_secret=plaintext_secret,
        description=description,
        tags=tags if tags is not None else {"env": "test"},
        expires_at=expires_at,
    )


def _setup_create_success(mock_uow) -> None:
    mock_uow.credentials.exists_by_name.return_value = False
    mock_uow.vault_backends.get_by_id.return_value = make_vault_backend()
    mock_uow.audit_logs.append_entry.return_value = None


def _setup_active_resolve(
    mock_uow,
    *,
    state: CredentialState = CredentialState.ACTIVE,
    tenant_id=None,
    principal_id=None,
    credential_id=None,
    version_id=None,
):
    tid = tenant_id or TenantId.generate()
    pid = principal_id or PrincipalId(uuid4())
    cid = credential_id or CredentialId(uuid4())
    vid = version_id or VersionId(uuid4())
    cred = make_credential(
        state=state,
        tenant_id=tid,
        credential_id=cid,
        principal_id=pid,
        version_id=vid,
    )
    version = make_version(
        state=VersionState.ACTIVE,
        credential_id=cred.credential_id,
        tenant_id=cred.tenant_id,
        version_id=cred.active_version_id,
        principal_id=cred.owner_principal,
    )
    audit = make_audit_log(cred.credential_id, cred.tenant_id)
    mock_uow.credentials.get_by_id.return_value = cred
    mock_uow.versions.get_active_version.return_value = version
    mock_uow.audit_logs.get_by_credential.return_value = audit
    return cred, version, audit


def _resolve_cmd(cred, *, break_glass: bool = False, justification: str | None = None):
    return ResolveCredentialCommand(
        tenant_id=cred.tenant_id,
        credential_id=cred.credential_id.value,
        principal_id=EntityId.from_uuid(cred.owner_principal.value),
        purpose="deployment",
        client_ip="10.0.0.1",
        request_id="req-1",
        break_glass=break_glass,
        justification=justification,
    )


def _published_events(mock_event_publisher) -> list:
    assert mock_event_publisher.publish_batch.called
    return list(mock_event_publisher.publish_batch.call_args.args[0])


def _ids_from_cred(cred):
    return (
        cred.tenant_id,
        cred.credential_id.value,
        EntityId.from_uuid(cred.owner_principal.value),
    )


# ===========================================================================
# create_credential
# ===========================================================================


async def test_create_credential_success(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_event_publisher,
) -> None:
    _setup_create_success(mock_uow)
    cmd = _create_cmd()

    dto = await credential_service.create_credential(cmd)

    assert isinstance(dto, CredentialDTO)
    assert dto.name == cmd.name
    assert dto.state == CredentialState.ACTIVE.value
    assert dto.category == "API_KEY"
    assert dto.subtype == "GENERIC"
    mock_uow.credentials.save.assert_awaited()
    mock_uow.versions.save.assert_awaited()
    mock_uow.audit_logs.save.assert_awaited()
    mock_uow.commit.assert_awaited()
    mock_event_publisher.publish_batch.assert_awaited()


async def test_create_credential_success_dto_fields_populated(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    _setup_create_success(mock_uow)
    cmd = _create_cmd(description="full dto check", tags={"a": "b"})

    dto = await credential_service.create_credential(cmd)

    assert isinstance(dto.credential_id, str) and dto.credential_id
    assert isinstance(dto.tenant_id, str) and dto.tenant_id
    assert isinstance(dto.name, str) and dto.name == cmd.name
    assert isinstance(dto.category, str) and dto.category == "API_KEY"
    assert isinstance(dto.subtype, str) and dto.subtype == "GENERIC"
    assert dto.schema_id is None or isinstance(dto.schema_id, str)
    assert isinstance(dto.state, str) and dto.state == CredentialState.ACTIVE.value
    assert isinstance(dto.owner_principal_id, str) and dto.owner_principal_id
    assert isinstance(dto.active_version_id, str) and dto.active_version_id
    assert dto.rotation_policy_id is None or isinstance(dto.rotation_policy_id, str)
    assert dto.expiration_policy_id is None or isinstance(dto.expiration_policy_id, str)
    assert isinstance(dto.vault_backend_id, str) and dto.vault_backend_id
    assert dto.description == "full dto check"
    assert isinstance(dto.tags, dict) and dto.tags == {"a": "b"}
    assert isinstance(dto.created_at, str) and dto.created_at
    assert isinstance(dto.updated_at, str) and dto.updated_at
    assert isinstance(dto.version, int)


async def test_create_credential_name_already_exists(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    mock_uow.credentials.exists_by_name.return_value = True
    mock_uow.vault_backends.get_by_id.return_value = make_vault_backend()

    with pytest.raises(CredentialAlreadyExists):
        await credential_service.create_credential(_create_cmd())

    mock_uow.commit.assert_not_awaited()


async def test_create_credential_backend_not_found(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    mock_uow.credentials.exists_by_name.return_value = False
    backend_id = VaultBackendId(uuid4())
    mock_uow.vault_backends.get_by_id.side_effect = VaultBackendNotFound(backend_id)

    with pytest.raises(VaultBackendNotFound):
        await credential_service.create_credential(_create_cmd(vault_backend_id=backend_id.value))

    mock_uow.commit.assert_not_awaited()


async def test_create_credential_kms_failure_no_uow_opened(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_key_mgmt_port,
) -> None:
    mock_key_mgmt_port.generate_dek.side_effect = RuntimeError("kms down")

    with pytest.raises(ApplicationPortError) as exc_info:
        await credential_service.create_credential(_create_cmd())

    assert exc_info.value.port_name == "key_management"
    mock_uow.__aenter__.assert_not_awaited()


async def test_create_credential_kms_failure(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_key_mgmt_port,
) -> None:
    mock_key_mgmt_port.generate_dek.side_effect = RuntimeError("kms down")

    with pytest.raises(ApplicationPortError):
        await credential_service.create_credential(_create_cmd())

    mock_uow.__aenter__.assert_not_awaited()


async def test_create_credential_audit_failure(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    _setup_create_success(mock_uow)
    mock_uow.audit_logs.append_entry.side_effect = RuntimeError("audit write failed")

    with pytest.raises(ApplicationAuditFailure):
        await credential_service.create_credential(_create_cmd())

    mock_uow.commit.assert_not_awaited()


async def test_create_credential_events_published(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_event_publisher,
) -> None:
    _setup_create_success(mock_uow)

    await credential_service.create_credential(_create_cmd())

    events = _published_events(mock_event_publisher)
    types = {type(e) for e in events}
    assert CredentialCreated in types
    assert CredentialVersionCreated in types


async def test_create_credential_audit_log_saved_in_same_transaction(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    _setup_create_success(mock_uow)
    order: list[str] = []

    async def track_cred_save(*_a, **_k):
        order.append("credentials.save")

    async def track_audit_save(*_a, **_k):
        order.append("audit_logs.save")

    async def track_append(*_a, **_k):
        order.append("audit_logs.append_entry")

    async def track_commit(*_a, **_k):
        order.append("commit")

    mock_uow.credentials.save.side_effect = track_cred_save
    mock_uow.audit_logs.save.side_effect = track_audit_save
    mock_uow.audit_logs.append_entry.side_effect = track_append
    mock_uow.commit.side_effect = track_commit

    await credential_service.create_credential(_create_cmd())

    assert "credentials.save" in order
    assert "audit_logs.save" in order
    assert order.index("credentials.save") < order.index("commit")
    assert order.index("audit_logs.save") < order.index("commit")
    assert order.index("audit_logs.append_entry") < order.index("commit")


async def test_create_custom_without_schema_id(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    with pytest.raises(ApplicationValidationError) as exc_info:
        await credential_service.create_credential(_create_cmd(category="CUSTOM", schema_id=None))

    assert exc_info.value.field == "schema_id"
    mock_uow.__aenter__.assert_not_awaited()


async def test_create_with_non_custom_with_schema_id(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    with pytest.raises(ApplicationValidationError) as exc_info:
        await credential_service.create_credential(
            _create_cmd(category="API_KEY", schema_id=uuid4())
        )

    assert exc_info.value.field == "schema_id"
    mock_uow.__aenter__.assert_not_awaited()


async def test_create_credential_access_denied(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_permission_port,
) -> None:
    mock_permission_port.has_permission.return_value = False

    with pytest.raises(AccessDenied):
        await credential_service.create_credential(_create_cmd())

    mock_uow.__aenter__.assert_not_awaited()


async def test_create_credential_validation_failure(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    with pytest.raises(ApplicationValidationError) as exc_info:
        await credential_service.create_credential(_create_cmd(plaintext_secret=b""))

    assert exc_info.value.field == "plaintext_secret"
    mock_uow.__aenter__.assert_not_awaited()


async def test_create_credential_publish_failure_nonfatal(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_event_publisher,
) -> None:
    _setup_create_success(mock_uow)
    mock_event_publisher.publish_batch.side_effect = RuntimeError("broker down")

    dto = await credential_service.create_credential(_create_cmd())

    assert isinstance(dto, CredentialDTO)
    mock_uow.commit.assert_awaited()


async def test_create_credential_optimistic_lock(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    _setup_create_success(mock_uow)
    mock_uow.credentials.save.side_effect = OptimisticLockConflict("cred", 1, 2)

    with pytest.raises(OptimisticLockConflict):
        await credential_service.create_credential(_create_cmd())


# ===========================================================================
# resolve_credential
# ===========================================================================


async def test_resolve_credential_success_normal(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_event_publisher,
) -> None:
    cred, version, _audit = _setup_active_resolve(mock_uow)

    dto = await credential_service.resolve_credential(_resolve_cmd(cred))

    assert isinstance(dto, ResolvedSecretDTO)
    assert dto.credential_id == str(cred.credential_id)
    assert dto.version_id == str(version.version_id)
    assert dto.plaintext_secret == b"decrypted-plaintext"
    mock_uow.commit.assert_awaited()
    mock_event_publisher.publish_batch.assert_awaited()


async def test_resolve_returns_plaintext_bytes(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)

    dto = await credential_service.resolve_credential(_resolve_cmd(cred))

    assert isinstance(dto.plaintext_secret, bytes)
    assert dto.plaintext_secret == b"decrypted-plaintext"


async def test_resolve_credential_access_denied(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_permission_port,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    mock_permission_port.has_permission.return_value = False

    with pytest.raises(AccessDenied):
        await credential_service.resolve_credential(_resolve_cmd(cred))

    mock_uow.commit.assert_not_awaited()


async def test_resolve_credential_revoked(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow, state=CredentialState.REVOKED)

    with pytest.raises(CredentialIsRevoked):
        await credential_service.resolve_credential(_resolve_cmd(cred))

    mock_uow.commit.assert_not_awaited()


async def test_resolve_revoked_credential(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow, state=CredentialState.REVOKED)

    with pytest.raises(CredentialIsRevoked):
        await credential_service.resolve_credential(_resolve_cmd(cred))


async def test_resolve_credential_break_glass_success(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_permission_port,
    mock_approval_port,
) -> None:
    cred, version, _audit = _setup_active_resolve(mock_uow)
    mock_permission_port.has_permission.return_value = False
    mock_approval_port.is_approved.return_value = True

    dto = await credential_service.resolve_credential(
        _resolve_cmd(cred, break_glass=True, justification="incident-42")
    )

    assert dto.plaintext_secret == b"decrypted-plaintext"
    assert dto.version_id == str(version.version_id)
    mock_uow.commit.assert_awaited()


async def test_resolve_credential_break_glass_no_approval(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_approval_port,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    mock_approval_port.is_approved.return_value = False
    mock_approval_port.get_approver_count.return_value = (0, 2)

    with pytest.raises(InsufficientApprovers):
        await credential_service.resolve_credential(
            _resolve_cmd(cred, break_glass=True, justification="need access")
        )


async def test_resolve_insufficient_approvers_for_break_glass(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_approval_port,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    mock_approval_port.is_approved.return_value = False
    mock_approval_port.get_approver_count.return_value = (1, 2)

    with pytest.raises(InsufficientApprovers) as exc_info:
        await credential_service.resolve_credential(
            _resolve_cmd(cred, break_glass=True, justification="need access")
        )

    assert exc_info.value.required == 2
    assert exc_info.value.actual == 1


async def test_resolve_credential_break_glass_no_justification(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)

    with pytest.raises(ApplicationValidationError) as exc_info:
        await credential_service.resolve_credential(
            _resolve_cmd(cred, break_glass=True, justification=None)
        )

    assert exc_info.value.field == "justification"
    mock_uow.__aenter__.assert_not_awaited()


async def test_resolve_credential_audit_fail_closed(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    mock_uow.audit_logs.append_entry.side_effect = RuntimeError("audit down")

    with pytest.raises(ApplicationAuditFailure):
        await credential_service.resolve_credential(_resolve_cmd(cred))

    mock_uow.commit.assert_not_awaited()


async def test_resolve_no_secret_returned_on_audit_failure(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    mock_uow.audit_logs.append_entry.side_effect = RuntimeError("audit down")

    result = None
    with pytest.raises(ApplicationAuditFailure):
        result = await credential_service.resolve_credential(_resolve_cmd(cred))

    assert result is None
    mock_uow.commit.assert_not_awaited()


async def test_resolve_credential_saved_after_resolve(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)

    await credential_service.resolve_credential(_resolve_cmd(cred))

    mock_uow.credentials.save.assert_awaited()
    saved = mock_uow.credentials.save.await_args.args[0]
    assert saved.credential_id == cred.credential_id


async def test_resolve_credential_access_event_published(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_event_publisher,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)

    await credential_service.resolve_credential(_resolve_cmd(cred))

    events = _published_events(mock_event_publisher)
    assert any(isinstance(e, CredentialAccessed) for e in events)
    assert not any(isinstance(e, BreakGlassAccessed) for e in events)


async def test_resolve_break_glass_event_published(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_event_publisher,
    mock_approval_port,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    mock_approval_port.is_approved.return_value = True

    await credential_service.resolve_credential(
        _resolve_cmd(cred, break_glass=True, justification="sev1")
    )

    events = _published_events(mock_event_publisher)
    assert any(isinstance(e, BreakGlassAccessed) for e in events)


async def test_resolve_break_glass_emits_break_glass_event(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_event_publisher,
    mock_approval_port,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    mock_approval_port.is_approved.return_value = True

    await credential_service.resolve_credential(
        _resolve_cmd(cred, break_glass=True, justification="sev1")
    )

    events = _published_events(mock_event_publisher)
    assert any(isinstance(e, BreakGlassAccessed) for e in events)
    assert not any(isinstance(e, CredentialAccessed) for e in events)


# ===========================================================================
# rotate / commit / abort
# ===========================================================================


async def test_rotate_credential_success(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_event_publisher,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    existing = make_version(
        state=VersionState.ACTIVE,
        credential_id=cred.credential_id,
        tenant_id=cred.tenant_id,
        version_id=cred.active_version_id,
        version_number=1,
        principal_id=cred.owner_principal,
    )
    mock_uow.versions.list_by_credential.return_value = [existing]
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    dto = await credential_service.rotate_credential(
        RotateCredentialCommand(
            tenant_id=tenant_id,
            credential_id=credential_id,
            principal_id=principal_id,
            new_plaintext_secret=b"rotated-secret",
            trigger="MANUAL",
        )
    )

    assert dto.state == CredentialState.ROTATING.value
    mock_uow.versions.save.assert_awaited()
    mock_uow.credentials.save.assert_awaited()
    mock_uow.commit.assert_awaited()
    events = _published_events(mock_event_publisher)
    assert any(isinstance(e, CredentialRotationStarted) for e in events)


async def test_rotate_credential_already_rotating(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    tid = TenantId.generate()
    pid = PrincipalId(uuid4())
    cid = CredentialId(uuid4())
    vid = VersionId(uuid4())
    cred = make_credential(
        state=CredentialState.ROTATING,
        tenant_id=tid,
        credential_id=cid,
        principal_id=pid,
        version_id=vid,
    )
    mock_uow.credentials.get_by_id.return_value = cred
    mock_uow.versions.list_by_credential.return_value = []
    mock_uow.audit_logs.get_by_credential.return_value = make_audit_log(cid, tid)
    # Bypass ACTIVE gate so ConcurrentRotationConflict from begin_rotation surfaces.
    credential_service._access_control.assert_can_rotate = AsyncMock()  # type: ignore[method-assign]

    with pytest.raises(ConcurrentRotationConflict):
        await credential_service.rotate_credential(
            RotateCredentialCommand(
                tenant_id=tid,
                credential_id=cid.value,
                principal_id=EntityId.from_uuid(pid.value),
                new_plaintext_secret=b"rotated-secret",
                trigger="MANUAL",
            )
        )


async def test_rotate_credential_no_permission(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_permission_port,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    mock_uow.versions.list_by_credential.return_value = []
    mock_permission_port.has_permission.return_value = False
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    with pytest.raises(AccessDenied):
        await credential_service.rotate_credential(
            RotateCredentialCommand(
                tenant_id=tenant_id,
                credential_id=credential_id,
                principal_id=principal_id,
                new_plaintext_secret=b"rotated-secret",
                trigger="MANUAL",
            )
        )


async def test_rotate_credential_audit_fail_closed(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    mock_uow.versions.list_by_credential.return_value = [
        make_version(
            credential_id=cred.credential_id,
            tenant_id=cred.tenant_id,
            version_id=cred.active_version_id,
        )
    ]
    mock_uow.audit_logs.append_entry.side_effect = RuntimeError("audit down")
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    with pytest.raises(ApplicationAuditFailure):
        await credential_service.rotate_credential(
            RotateCredentialCommand(
                tenant_id=tenant_id,
                credential_id=credential_id,
                principal_id=principal_id,
                new_plaintext_secret=b"rotated-secret",
                trigger="MANUAL",
            )
        )

    mock_uow.commit.assert_not_awaited()


async def test_rotate_credential_validation_failure(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    with pytest.raises(ApplicationValidationError) as exc_info:
        await credential_service.rotate_credential(
            RotateCredentialCommand(
                tenant_id=EntityId.generate(),
                credential_id=uuid4(),
                principal_id=EntityId.generate(),
                new_plaintext_secret=b"",
                trigger="MANUAL",
            )
        )

    assert exc_info.value.field == "new_plaintext_secret"
    mock_uow.__aenter__.assert_not_awaited()


async def test_rotate_credential_publish_failure_nonfatal(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_event_publisher,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    mock_uow.versions.list_by_credential.return_value = [
        make_version(
            credential_id=cred.credential_id,
            tenant_id=cred.tenant_id,
            version_id=cred.active_version_id,
        )
    ]
    mock_event_publisher.publish_batch.side_effect = RuntimeError("broker down")
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    dto = await credential_service.rotate_credential(
        RotateCredentialCommand(
            tenant_id=tenant_id,
            credential_id=credential_id,
            principal_id=principal_id,
            new_plaintext_secret=b"rotated-secret",
            trigger="MANUAL",
        )
    )

    assert dto.state == CredentialState.ROTATING.value
    mock_uow.commit.assert_awaited()


def _setup_rotating_for_commit(mock_uow):
    tid = TenantId.generate()
    pid = PrincipalId(uuid4())
    cid = CredentialId(uuid4())
    active_vid = VersionId(uuid4())
    cred = make_credential(
        state=CredentialState.ROTATING,
        tenant_id=tid,
        credential_id=cid,
        principal_id=pid,
        version_id=active_vid,
    )
    pending = make_version(
        state=VersionState.PENDING,
        version_number=2,
        credential_id=cid,
        tenant_id=tid,
        principal_id=pid,
    )
    old = make_version(
        state=VersionState.ACTIVE,
        version_id=cred.active_version_id,
        credential_id=cid,
        tenant_id=tid,
        principal_id=pid,
        version_number=1,
    )
    audit = make_audit_log(cid, tid)
    mock_uow.credentials.get_by_id.return_value = cred
    mock_uow.versions.list_by_credential.return_value = [pending]
    mock_uow.versions.get_by_id.return_value = old
    mock_uow.audit_logs.get_by_credential.return_value = audit
    return cred, pending, old, audit


async def test_commit_rotation_success(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_event_publisher,
) -> None:
    cred, pending, _old, _audit = _setup_rotating_for_commit(mock_uow)
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    dto = await credential_service.commit_rotation(
        CommitRotationCommand(
            tenant_id=tenant_id,
            credential_id=credential_id,
            principal_id=principal_id,
        )
    )

    assert dto.state == CredentialState.ACTIVE.value
    assert dto.active_version_id == str(pending.version_id)
    mock_uow.versions.atomic_promote.assert_awaited()
    mock_uow.credentials.save.assert_awaited()
    mock_uow.commit.assert_awaited()
    events = _published_events(mock_event_publisher)
    assert any(isinstance(e, CredentialRotated) for e in events)


async def test_commit_rotation_not_rotating(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    mock_uow.versions.list_by_credential.return_value = []
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    with pytest.raises(InvalidStateTransition):
        await credential_service.commit_rotation(
            CommitRotationCommand(
                tenant_id=tenant_id,
                credential_id=credential_id,
                principal_id=principal_id,
            )
        )


async def test_commit_rotation_uses_list_by_credential_not_private_field(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    cred, _pending, _old, _audit = _setup_rotating_for_commit(mock_uow)
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    await credential_service.commit_rotation(
        CommitRotationCommand(
            tenant_id=tenant_id,
            credential_id=credential_id,
            principal_id=principal_id,
        )
    )

    mock_uow.versions.list_by_credential.assert_awaited_with(
        cred.credential_id,
        cred.tenant_id,
        states=[VersionState.PENDING],
    )
    mock_uow.versions.atomic_promote.assert_awaited()
    assert mock_uow.versions.atomic_promote.await_count == 1


async def test_commit_rotation_no_pending_version_raises(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    cred, _pending, _old, _audit = _setup_rotating_for_commit(mock_uow)
    mock_uow.versions.list_by_credential.return_value = []
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    with pytest.raises(InvalidStateTransition) as exc_info:
        await credential_service.commit_rotation(
            CommitRotationCommand(
                tenant_id=tenant_id,
                credential_id=credential_id,
                principal_id=principal_id,
            )
        )

    assert exc_info.value.attempted == "commit_rotation"


async def test_commit_rotation_no_separate_version_save_calls(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    cred, _pending, _old, _audit = _setup_rotating_for_commit(mock_uow)
    mock_uow.versions.save.reset_mock()
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    await credential_service.commit_rotation(
        CommitRotationCommand(
            tenant_id=tenant_id,
            credential_id=credential_id,
            principal_id=principal_id,
        )
    )

    mock_uow.versions.save.assert_not_awaited()
    mock_uow.versions.atomic_promote.assert_awaited()


async def test_commit_rotation_access_denied(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_permission_port,
) -> None:
    mock_permission_port.has_permission.return_value = False

    with pytest.raises(AccessDenied):
        await credential_service.commit_rotation(
            CommitRotationCommand(
                tenant_id=EntityId.generate(),
                credential_id=uuid4(),
                principal_id=EntityId.generate(),
            )
        )

    mock_uow.__aenter__.assert_not_awaited()


async def test_commit_rotation_audit_fail_closed(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    cred, _pending, _old, _audit = _setup_rotating_for_commit(mock_uow)
    mock_uow.audit_logs.append_entry.side_effect = RuntimeError("audit down")
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    with pytest.raises(ApplicationAuditFailure):
        await credential_service.commit_rotation(
            CommitRotationCommand(
                tenant_id=tenant_id,
                credential_id=credential_id,
                principal_id=principal_id,
            )
        )

    mock_uow.commit.assert_not_awaited()


async def test_abort_rotation_success(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_event_publisher,
) -> None:
    cred, pending, _old, _audit = _setup_rotating_for_commit(mock_uow)
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    dto = await credential_service.abort_rotation(
        AbortRotationCommand(
            tenant_id=tenant_id,
            credential_id=credential_id,
            principal_id=principal_id,
            reason="rollback experiment",
        )
    )

    assert dto.state == CredentialState.ACTIVE.value
    mock_uow.versions.update.assert_awaited()
    mock_uow.versions.list_by_credential.assert_awaited_with(
        cred.credential_id,
        cred.tenant_id,
        states=[VersionState.PENDING],
    )
    assert pending.version_state == VersionState.REVOKED
    mock_uow.commit.assert_awaited()
    events = _published_events(mock_event_publisher)
    assert any(isinstance(e, RotationAborted) for e in events)


async def test_abort_rotation_access_denied(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_permission_port,
) -> None:
    mock_permission_port.has_permission.return_value = False

    with pytest.raises(AccessDenied):
        await credential_service.abort_rotation(
            AbortRotationCommand(
                tenant_id=EntityId.generate(),
                credential_id=uuid4(),
                principal_id=EntityId.generate(),
                reason="nope",
            )
        )

    mock_uow.__aenter__.assert_not_awaited()


async def test_abort_rotation_audit_fail_closed(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    cred, _pending, _old, _audit = _setup_rotating_for_commit(mock_uow)
    mock_uow.audit_logs.append_entry.side_effect = RuntimeError("audit down")
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    with pytest.raises(ApplicationAuditFailure):
        await credential_service.abort_rotation(
            AbortRotationCommand(
                tenant_id=tenant_id,
                credential_id=credential_id,
                principal_id=principal_id,
                reason="abort",
            )
        )

    mock_uow.commit.assert_not_awaited()


async def test_abort_rotation_validation_failure(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    with pytest.raises(ApplicationValidationError):
        await credential_service.abort_rotation(
            AbortRotationCommand(
                tenant_id=EntityId.generate(),
                credential_id=uuid4(),
                principal_id=EntityId.generate(),
                reason="",
            )
        )

    mock_uow.__aenter__.assert_not_awaited()


# ===========================================================================
# recover / hard delete
# ===========================================================================


def _setup_recover(mock_uow):
    tid = TenantId.generate()
    pid = PrincipalId(uuid4())
    cid = CredentialId(uuid4())
    cred = make_credential(
        state=CredentialState.REVOKED,
        tenant_id=tid,
        credential_id=cid,
        principal_id=pid,
    )
    target = make_version(
        state=VersionState.SUPERSEDED,
        credential_id=cid,
        tenant_id=tid,
        principal_id=pid,
        version_number=1,
    )
    audit = make_audit_log(cid, tid)
    mock_uow.credentials.get_by_id.return_value = cred
    mock_uow.versions.get_by_id.return_value = target
    mock_uow.audit_logs.get_by_credential.return_value = audit
    return cred, target, audit


async def test_recover_credential_success(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_event_publisher,
    mock_approval_port,
) -> None:
    cred, target, _audit = _setup_recover(mock_uow)
    mock_approval_port.is_approved.return_value = True
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    dto = await credential_service.recover_credential(
        RecoverCredentialCommand(
            tenant_id=tenant_id,
            credential_id=credential_id,
            principal_id=principal_id,
            target_version_id=target.version_id.value,
            justification="approved recovery",
        )
    )

    assert dto.state == CredentialState.ACTIVE.value
    assert dto.active_version_id == str(target.version_id)
    mock_uow.versions.update.assert_awaited()
    mock_uow.commit.assert_awaited()
    events = _published_events(mock_event_publisher)
    assert any(isinstance(e, CredentialRecovered) for e in events)


async def test_recover_sets_version_state_directly(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_approval_port,
) -> None:
    cred, target, _audit = _setup_recover(mock_uow)
    mock_approval_port.is_approved.return_value = True
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    await credential_service.recover_credential(
        RecoverCredentialCommand(
            tenant_id=tenant_id,
            credential_id=credential_id,
            principal_id=principal_id,
            target_version_id=target.version_id.value,
            justification="approved recovery",
        )
    )

    assert target.version_state == VersionState.ACTIVE


async def test_recover_credential_not_approved(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_approval_port,
) -> None:
    cred, target, _audit = _setup_recover(mock_uow)
    mock_approval_port.is_approved.return_value = False
    mock_approval_port.get_approver_count.return_value = (0, 2)
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    with pytest.raises(InsufficientApprovers):
        await credential_service.recover_credential(
            RecoverCredentialCommand(
                tenant_id=tenant_id,
                credential_id=credential_id,
                principal_id=principal_id,
                target_version_id=target.version_id.value,
                justification="unapproved",
            )
        )


async def test_recover_not_approved(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_approval_port,
) -> None:
    cred, target, _audit = _setup_recover(mock_uow)
    mock_approval_port.is_approved.return_value = False
    mock_approval_port.get_approver_count.return_value = (0, 2)
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    with pytest.raises(InsufficientApprovers):
        await credential_service.recover_credential(
            RecoverCredentialCommand(
                tenant_id=tenant_id,
                credential_id=credential_id,
                principal_id=principal_id,
                target_version_id=target.version_id.value,
                justification="unapproved",
            )
        )


async def test_recover_credential_access_denied(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_permission_port,
) -> None:
    mock_permission_port.has_permission.return_value = False

    with pytest.raises(AccessDenied):
        await credential_service.recover_credential(
            RecoverCredentialCommand(
                tenant_id=EntityId.generate(),
                credential_id=uuid4(),
                principal_id=EntityId.generate(),
                target_version_id=uuid4(),
                justification="recovery",
            )
        )

    mock_uow.__aenter__.assert_not_awaited()


async def test_recover_credential_audit_fail_closed(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_approval_port,
) -> None:
    cred, target, _audit = _setup_recover(mock_uow)
    mock_approval_port.is_approved.return_value = True
    mock_uow.audit_logs.append_entry.side_effect = RuntimeError("audit down")
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    with pytest.raises(ApplicationAuditFailure):
        await credential_service.recover_credential(
            RecoverCredentialCommand(
                tenant_id=tenant_id,
                credential_id=credential_id,
                principal_id=principal_id,
                target_version_id=target.version_id.value,
                justification="approved recovery",
            )
        )

    mock_uow.commit.assert_not_awaited()


async def test_recover_credential_validation_failure(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    with pytest.raises(ApplicationValidationError):
        await credential_service.recover_credential(
            RecoverCredentialCommand(
                tenant_id=EntityId.generate(),
                credential_id=uuid4(),
                principal_id=EntityId.generate(),
                target_version_id=uuid4(),
                justification="",
            )
        )

    mock_uow.__aenter__.assert_not_awaited()


async def test_hard_delete_success(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_event_publisher,
) -> None:
    tid = TenantId.generate()
    pid = PrincipalId(uuid4())
    cid = CredentialId(uuid4())
    cred = make_credential(
        state=CredentialState.DISABLED,
        tenant_id=tid,
        credential_id=cid,
        principal_id=pid,
    )
    mock_uow.credentials.get_by_id.return_value = cred
    mock_uow.audit_logs.get_by_credential.return_value = make_audit_log(cid, tid)

    result = await credential_service.hard_delete_credential(
        HardDeleteCredentialCommand(
            tenant_id=tid,
            credential_id=cid.value,
            principal_id=EntityId.from_uuid(pid.value),
        )
    )

    assert result is None
    assert cred.state == CredentialState.DELETED
    mock_uow.commit.assert_awaited()
    events = _published_events(mock_event_publisher)
    assert any(isinstance(e, CredentialDeleted) for e in events)


async def test_hard_delete_from_active_state(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    with pytest.raises(InvalidStateTransition) as exc_info:
        await credential_service.hard_delete_credential(
            HardDeleteCredentialCommand(
                tenant_id=tenant_id,
                credential_id=credential_id,
                principal_id=principal_id,
            )
        )

    assert exc_info.value.attempted == "delete"


async def test_hard_delete_access_denied(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_permission_port,
) -> None:
    tid = TenantId.generate()
    pid = PrincipalId(uuid4())
    cid = CredentialId(uuid4())
    cred = make_credential(
        state=CredentialState.DISABLED,
        tenant_id=tid,
        credential_id=cid,
        principal_id=pid,
    )
    mock_uow.credentials.get_by_id.return_value = cred
    mock_uow.audit_logs.get_by_credential.return_value = make_audit_log(cid, tid)
    mock_permission_port.has_permission.return_value = False

    with pytest.raises(AccessDenied):
        await credential_service.hard_delete_credential(
            HardDeleteCredentialCommand(
                tenant_id=tid,
                credential_id=cid.value,
                principal_id=EntityId.from_uuid(pid.value),
            )
        )


async def test_hard_delete_audit_fail_closed(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    tid = TenantId.generate()
    pid = PrincipalId(uuid4())
    cid = CredentialId(uuid4())
    cred = make_credential(
        state=CredentialState.REVOKED,
        tenant_id=tid,
        credential_id=cid,
        principal_id=pid,
    )
    mock_uow.credentials.get_by_id.return_value = cred
    mock_uow.audit_logs.get_by_credential.return_value = make_audit_log(cid, tid)
    mock_uow.audit_logs.append_entry.side_effect = RuntimeError("audit down")

    with pytest.raises(ApplicationAuditFailure):
        await credential_service.hard_delete_credential(
            HardDeleteCredentialCommand(
                tenant_id=tid,
                credential_id=cid.value,
                principal_id=EntityId.from_uuid(pid.value),
            )
        )

    mock_uow.commit.assert_not_awaited()


# ===========================================================================
# disable / enable / revoke / emergency_revoke / expire
# ===========================================================================


async def test_disable_credential_success(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_event_publisher,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    dto = await credential_service.disable_credential(
        DisableCredentialCommand(
            tenant_id=tenant_id,
            credential_id=credential_id,
            principal_id=principal_id,
            reason="maintenance",
        )
    )

    assert dto.state == CredentialState.DISABLED.value
    mock_uow.commit.assert_awaited()
    events = _published_events(mock_event_publisher)
    assert any(isinstance(e, CredentialDisabled) for e in events)


async def test_disable_credential_access_denied(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_permission_port,
) -> None:
    mock_permission_port.has_permission.return_value = False

    with pytest.raises(AccessDenied):
        await credential_service.disable_credential(
            DisableCredentialCommand(
                tenant_id=EntityId.generate(),
                credential_id=uuid4(),
                principal_id=EntityId.generate(),
                reason="nope",
            )
        )

    mock_uow.__aenter__.assert_not_awaited()


async def test_disable_credential_audit_fail_closed(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    mock_uow.audit_logs.append_entry.side_effect = RuntimeError("audit down")
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    with pytest.raises(ApplicationAuditFailure):
        await credential_service.disable_credential(
            DisableCredentialCommand(
                tenant_id=tenant_id,
                credential_id=credential_id,
                principal_id=principal_id,
                reason="maintenance",
            )
        )

    mock_uow.commit.assert_not_awaited()


async def test_disable_credential_validation_failure(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    with pytest.raises(ApplicationValidationError):
        await credential_service.disable_credential(
            DisableCredentialCommand(
                tenant_id=EntityId.generate(),
                credential_id=uuid4(),
                principal_id=EntityId.generate(),
                reason="",
            )
        )

    mock_uow.__aenter__.assert_not_awaited()


async def test_disable_credential_optimistic_lock(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    mock_uow.credentials.save.side_effect = OptimisticLockConflict("cred", 1, 2)
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    with pytest.raises(OptimisticLockConflict):
        await credential_service.disable_credential(
            DisableCredentialCommand(
                tenant_id=tenant_id,
                credential_id=credential_id,
                principal_id=principal_id,
                reason="maintenance",
            )
        )


async def test_enable_credential_success(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_event_publisher,
) -> None:
    tid = TenantId.generate()
    pid = PrincipalId(uuid4())
    cid = CredentialId(uuid4())
    cred = make_credential(
        state=CredentialState.DISABLED,
        tenant_id=tid,
        credential_id=cid,
        principal_id=pid,
    )
    mock_uow.credentials.get_by_id.return_value = cred
    mock_uow.audit_logs.get_by_credential.return_value = make_audit_log(cid, tid)

    dto = await credential_service.enable_credential(
        EnableCredentialCommand(
            tenant_id=tid,
            credential_id=cid.value,
            principal_id=EntityId.from_uuid(pid.value),
        )
    )

    assert dto.state == CredentialState.ACTIVE.value
    mock_uow.commit.assert_awaited()
    events = _published_events(mock_event_publisher)
    assert any(isinstance(e, CredentialEnabled) for e in events)


async def test_enable_credential_access_denied(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_permission_port,
) -> None:
    mock_permission_port.has_permission.return_value = False

    with pytest.raises(AccessDenied):
        await credential_service.enable_credential(
            EnableCredentialCommand(
                tenant_id=EntityId.generate(),
                credential_id=uuid4(),
                principal_id=EntityId.generate(),
            )
        )

    mock_uow.__aenter__.assert_not_awaited()


async def test_enable_credential_audit_fail_closed(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    tid = TenantId.generate()
    pid = PrincipalId(uuid4())
    cid = CredentialId(uuid4())
    cred = make_credential(
        state=CredentialState.DISABLED,
        tenant_id=tid,
        credential_id=cid,
        principal_id=pid,
    )
    mock_uow.credentials.get_by_id.return_value = cred
    mock_uow.audit_logs.get_by_credential.return_value = make_audit_log(cid, tid)
    mock_uow.audit_logs.append_entry.side_effect = RuntimeError("audit down")

    with pytest.raises(ApplicationAuditFailure):
        await credential_service.enable_credential(
            EnableCredentialCommand(
                tenant_id=tid,
                credential_id=cid.value,
                principal_id=EntityId.from_uuid(pid.value),
            )
        )

    mock_uow.commit.assert_not_awaited()


async def test_enable_credential_validation_failure(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    with pytest.raises(ApplicationValidationError) as exc_info:
        await credential_service.enable_credential(
            EnableCredentialCommand(
                tenant_id=UUID(int=0),
                credential_id=uuid4(),
                principal_id=EntityId.generate(),
            )
        )

    assert exc_info.value.field == "tenant_id"
    mock_uow.__aenter__.assert_not_awaited()


async def test_revoke_credential_success(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_event_publisher,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    dto = await credential_service.revoke_credential(
        RevokeCredentialCommand(
            tenant_id=tenant_id,
            credential_id=credential_id,
            principal_id=principal_id,
            reason="compromised",
        )
    )

    assert dto.state == CredentialState.REVOKED.value
    mock_uow.commit.assert_awaited()
    events = _published_events(mock_event_publisher)
    assert any(isinstance(e, CredentialRevoked) for e in events)


async def test_revoke_credential_access_denied(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_permission_port,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    mock_permission_port.has_permission.return_value = False
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    with pytest.raises(AccessDenied):
        await credential_service.revoke_credential(
            RevokeCredentialCommand(
                tenant_id=tenant_id,
                credential_id=credential_id,
                principal_id=principal_id,
                reason="compromised",
            )
        )


async def test_revoke_credential_audit_fail_closed(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    mock_uow.audit_logs.append_entry.side_effect = RuntimeError("audit down")
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    with pytest.raises(ApplicationAuditFailure):
        await credential_service.revoke_credential(
            RevokeCredentialCommand(
                tenant_id=tenant_id,
                credential_id=credential_id,
                principal_id=principal_id,
                reason="compromised",
            )
        )

    mock_uow.commit.assert_not_awaited()


async def test_revoke_credential_validation_failure(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    with pytest.raises(ApplicationValidationError):
        await credential_service.revoke_credential(
            RevokeCredentialCommand(
                tenant_id=EntityId.generate(),
                credential_id=uuid4(),
                principal_id=EntityId.generate(),
                reason="",
            )
        )

    mock_uow.__aenter__.assert_not_awaited()


async def test_emergency_revoke_success(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_event_publisher,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    dto = await credential_service.emergency_revoke(
        EmergencyRevokeCommand(
            tenant_id=tenant_id,
            credential_id=credential_id,
            principal_id=principal_id,
            justification="active breach",
        )
    )

    assert dto.state == CredentialState.REVOKED.value
    mock_uow.commit.assert_awaited()
    events = _published_events(mock_event_publisher)
    assert any(isinstance(e, EmergencyRevoked) for e in events)


async def test_emergency_revoke_access_denied(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_permission_port,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    mock_permission_port.has_permission.return_value = False
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    with pytest.raises(AccessDenied):
        await credential_service.emergency_revoke(
            EmergencyRevokeCommand(
                tenant_id=tenant_id,
                credential_id=credential_id,
                principal_id=principal_id,
                justification="active breach",
            )
        )


async def test_emergency_revoke_audit_fail_closed(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    mock_uow.audit_logs.append_entry.side_effect = RuntimeError("audit down")
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    with pytest.raises(ApplicationAuditFailure):
        await credential_service.emergency_revoke(
            EmergencyRevokeCommand(
                tenant_id=tenant_id,
                credential_id=credential_id,
                principal_id=principal_id,
                justification="active breach",
            )
        )

    mock_uow.commit.assert_not_awaited()


async def test_emergency_revoke_validation_failure(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    with pytest.raises(ApplicationValidationError):
        await credential_service.emergency_revoke(
            EmergencyRevokeCommand(
                tenant_id=EntityId.generate(),
                credential_id=uuid4(),
                principal_id=EntityId.generate(),
                justification="",
            )
        )

    mock_uow.__aenter__.assert_not_awaited()


async def test_expire_credential_success(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_event_publisher,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    dto = await credential_service.expire_credential(
        ExpireCredentialCommand(
            tenant_id=tenant_id,
            credential_id=credential_id,
            principal_id=principal_id,
        )
    )

    assert dto.state == CredentialState.EXPIRED.value
    mock_uow.commit.assert_awaited()
    events = _published_events(mock_event_publisher)
    assert any(isinstance(e, CredentialExpired) for e in events)


async def test_expire_credential_audit_fail_closed(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    mock_uow.audit_logs.append_entry.side_effect = RuntimeError("audit down")
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    with pytest.raises(ApplicationAuditFailure):
        await credential_service.expire_credential(
            ExpireCredentialCommand(
                tenant_id=tenant_id,
                credential_id=credential_id,
                principal_id=principal_id,
            )
        )

    mock_uow.commit.assert_not_awaited()


async def test_expire_credential_validation_failure(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    with pytest.raises(ApplicationValidationError) as exc_info:
        await credential_service.expire_credential(
            ExpireCredentialCommand(
                tenant_id=UUID(int=0),
                credential_id=uuid4(),
                principal_id=EntityId.generate(),
            )
        )

    assert exc_info.value.field == "tenant_id"
    mock_uow.__aenter__.assert_not_awaited()


# ===========================================================================
# rollback_version / update_metadata / policies
# ===========================================================================


async def test_rollback_version_success(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_event_publisher,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    current = make_version(
        state=VersionState.ACTIVE,
        version_id=cred.active_version_id,
        credential_id=cred.credential_id,
        tenant_id=cred.tenant_id,
        principal_id=cred.owner_principal,
        version_number=2,
    )
    target = make_version(
        state=VersionState.SUPERSEDED,
        credential_id=cred.credential_id,
        tenant_id=cred.tenant_id,
        principal_id=cred.owner_principal,
        version_number=1,
    )
    mock_uow.versions.get_by_id.side_effect = [target, current]
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    dto = await credential_service.rollback_version(
        RollbackVersionCommand(
            tenant_id=tenant_id,
            credential_id=credential_id,
            principal_id=principal_id,
            target_version_id=target.version_id.value,
        )
    )

    assert dto.active_version_id == str(target.version_id)
    assert target.version_state == VersionState.ACTIVE
    assert current.version_state == VersionState.SUPERSEDED
    mock_uow.commit.assert_awaited()
    events = _published_events(mock_event_publisher)
    assert any(isinstance(e, VersionRolledBack) for e in events)


async def test_rollback_version_access_denied(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_permission_port,
) -> None:
    mock_permission_port.has_permission.return_value = False

    with pytest.raises(AccessDenied):
        await credential_service.rollback_version(
            RollbackVersionCommand(
                tenant_id=EntityId.generate(),
                credential_id=uuid4(),
                principal_id=EntityId.generate(),
                target_version_id=uuid4(),
            )
        )

    mock_uow.__aenter__.assert_not_awaited()


async def test_rollback_version_audit_fail_closed(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    current = make_version(
        state=VersionState.ACTIVE,
        version_id=cred.active_version_id,
        credential_id=cred.credential_id,
        tenant_id=cred.tenant_id,
        version_number=2,
    )
    target = make_version(
        state=VersionState.SUPERSEDED,
        credential_id=cred.credential_id,
        tenant_id=cred.tenant_id,
        version_number=1,
    )
    mock_uow.versions.get_by_id.side_effect = [target, current]
    mock_uow.audit_logs.append_entry.side_effect = RuntimeError("audit down")
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    with pytest.raises(ApplicationAuditFailure):
        await credential_service.rollback_version(
            RollbackVersionCommand(
                tenant_id=tenant_id,
                credential_id=credential_id,
                principal_id=principal_id,
                target_version_id=target.version_id.value,
            )
        )

    mock_uow.commit.assert_not_awaited()


async def test_rollback_version_validation_failure(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    with pytest.raises(ApplicationValidationError) as exc_info:
        await credential_service.rollback_version(
            RollbackVersionCommand(
                tenant_id=EntityId.generate(),
                credential_id=uuid4(),
                principal_id=EntityId.generate(),
                target_version_id=UUID(int=0),
            )
        )

    assert exc_info.value.field == "target_version_id"
    mock_uow.__aenter__.assert_not_awaited()


async def test_update_metadata_success(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_event_publisher,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    dto = await credential_service.update_metadata(
        UpdateCredentialMetadataCommand(
            tenant_id=tenant_id,
            credential_id=credential_id,
            principal_id=principal_id,
            description="updated desc",
            tags={"team": "security"},
        )
    )

    assert dto.description == "updated desc"
    assert dto.tags == {"team": "security"}
    mock_uow.commit.assert_awaited()
    events = _published_events(mock_event_publisher)
    assert any(isinstance(e, CredentialMetadataUpdated) for e in events)


async def test_update_metadata_access_denied(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_permission_port,
) -> None:
    mock_permission_port.has_permission.return_value = False

    with pytest.raises(AccessDenied):
        await credential_service.update_metadata(
            UpdateCredentialMetadataCommand(
                tenant_id=EntityId.generate(),
                credential_id=uuid4(),
                principal_id=EntityId.generate(),
                description="x",
                tags={},
            )
        )

    mock_uow.__aenter__.assert_not_awaited()


async def test_update_metadata_audit_fail_closed(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    mock_uow.audit_logs.append_entry.side_effect = RuntimeError("audit down")
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    with pytest.raises(ApplicationAuditFailure):
        await credential_service.update_metadata(
            UpdateCredentialMetadataCommand(
                tenant_id=tenant_id,
                credential_id=credential_id,
                principal_id=principal_id,
                description="updated",
                tags={"a": "b"},
            )
        )

    mock_uow.commit.assert_not_awaited()


async def test_update_metadata_validation_failure(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    with pytest.raises(ApplicationValidationError) as exc_info:
        await credential_service.update_metadata(
            UpdateCredentialMetadataCommand(
                tenant_id=EntityId.generate(),
                credential_id=uuid4(),
                principal_id=EntityId.generate(),
                description="x" * 2049,
                tags={},
            )
        )

    assert exc_info.value.field == "description"
    mock_uow.__aenter__.assert_not_awaited()


async def test_attach_rotation_policy_success(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_event_publisher,
    now,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    policy = make_rotation_policy(tenant_id=cred.tenant_id, now=now)
    mock_uow.rotation_policies.get_by_id.return_value = policy
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    dto = await credential_service.attach_rotation_policy(
        AttachRotationPolicyCommand(
            tenant_id=tenant_id,
            credential_id=credential_id,
            policy_id=policy.policy_id.value,
            principal_id=principal_id,
        )
    )

    assert dto.rotation_policy_id == str(policy.policy_id)
    mock_uow.commit.assert_awaited()
    events = _published_events(mock_event_publisher)
    assert any(isinstance(e, RotationPolicyAttached) for e in events)


async def test_attach_rotation_policy_access_denied(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_permission_port,
) -> None:
    mock_permission_port.has_permission.return_value = False

    with pytest.raises(AccessDenied):
        await credential_service.attach_rotation_policy(
            AttachRotationPolicyCommand(
                tenant_id=EntityId.generate(),
                credential_id=uuid4(),
                policy_id=uuid4(),
                principal_id=EntityId.generate(),
            )
        )

    mock_uow.__aenter__.assert_not_awaited()


async def test_attach_rotation_policy_audit_fail_closed(
    credential_service: CredentialApplicationService,
    mock_uow,
    now,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    policy = make_rotation_policy(tenant_id=cred.tenant_id, now=now)
    mock_uow.rotation_policies.get_by_id.return_value = policy
    mock_uow.audit_logs.append_entry.side_effect = RuntimeError("audit down")
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    with pytest.raises(ApplicationAuditFailure):
        await credential_service.attach_rotation_policy(
            AttachRotationPolicyCommand(
                tenant_id=tenant_id,
                credential_id=credential_id,
                policy_id=policy.policy_id.value,
                principal_id=principal_id,
            )
        )

    mock_uow.commit.assert_not_awaited()


async def test_attach_rotation_policy_validation_failure(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    with pytest.raises(ApplicationValidationError) as exc_info:
        await credential_service.attach_rotation_policy(
            AttachRotationPolicyCommand(
                tenant_id=EntityId.generate(),
                credential_id=uuid4(),
                policy_id=UUID(int=0),
                principal_id=EntityId.generate(),
            )
        )

    assert exc_info.value.field == "policy_id"
    mock_uow.__aenter__.assert_not_awaited()


async def test_detach_rotation_policy_success(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_event_publisher,
    now,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    policy = make_rotation_policy(tenant_id=cred.tenant_id, now=now)
    cred.attach_rotation_policy(cred.tenant_id, policy.policy_id, cred.owner_principal, now)
    cred.pop_events()
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    dto = await credential_service.detach_rotation_policy(
        DetachRotationPolicyCommand(
            tenant_id=tenant_id,
            credential_id=credential_id,
            principal_id=principal_id,
        )
    )

    assert dto.rotation_policy_id is None
    mock_uow.commit.assert_awaited()
    events = _published_events(mock_event_publisher)
    assert any(isinstance(e, RotationPolicyDetached) for e in events)


async def test_detach_rotation_policy_access_denied(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_permission_port,
) -> None:
    mock_permission_port.has_permission.return_value = False

    with pytest.raises(AccessDenied):
        await credential_service.detach_rotation_policy(
            DetachRotationPolicyCommand(
                tenant_id=EntityId.generate(),
                credential_id=uuid4(),
                principal_id=EntityId.generate(),
            )
        )

    mock_uow.__aenter__.assert_not_awaited()


async def test_detach_rotation_policy_audit_fail_closed(
    credential_service: CredentialApplicationService,
    mock_uow,
    now,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    policy = make_rotation_policy(tenant_id=cred.tenant_id, now=now)
    cred.attach_rotation_policy(cred.tenant_id, policy.policy_id, cred.owner_principal, now)
    cred.pop_events()
    mock_uow.audit_logs.append_entry.side_effect = RuntimeError("audit down")
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    with pytest.raises(ApplicationAuditFailure):
        await credential_service.detach_rotation_policy(
            DetachRotationPolicyCommand(
                tenant_id=tenant_id,
                credential_id=credential_id,
                principal_id=principal_id,
            )
        )

    mock_uow.commit.assert_not_awaited()


async def test_detach_rotation_policy_validation_failure(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    with pytest.raises(ApplicationValidationError) as exc_info:
        await credential_service.detach_rotation_policy(
            DetachRotationPolicyCommand(
                tenant_id=UUID(int=0),
                credential_id=uuid4(),
                principal_id=EntityId.generate(),
            )
        )

    assert exc_info.value.field == "tenant_id"
    mock_uow.__aenter__.assert_not_awaited()


async def test_attach_expiration_policy_success(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_event_publisher,
    now,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    policy = make_expiration_policy(tenant_id=cred.tenant_id, now=now)
    mock_uow.expiration_policies.get_by_id.return_value = policy
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    dto = await credential_service.attach_expiration_policy(
        AttachExpirationPolicyCommand(
            tenant_id=tenant_id,
            credential_id=credential_id,
            policy_id=policy.policy_id.value,
            principal_id=principal_id,
        )
    )

    assert dto.expiration_policy_id == str(policy.policy_id)
    mock_uow.commit.assert_awaited()
    events = _published_events(mock_event_publisher)
    assert any(isinstance(e, ExpirationPolicyAttached) for e in events)


async def test_attach_expiration_policy_access_denied(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_permission_port,
) -> None:
    mock_permission_port.has_permission.return_value = False

    with pytest.raises(AccessDenied):
        await credential_service.attach_expiration_policy(
            AttachExpirationPolicyCommand(
                tenant_id=EntityId.generate(),
                credential_id=uuid4(),
                policy_id=uuid4(),
                principal_id=EntityId.generate(),
            )
        )

    mock_uow.__aenter__.assert_not_awaited()


async def test_attach_expiration_policy_audit_fail_closed(
    credential_service: CredentialApplicationService,
    mock_uow,
    now,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    policy = make_expiration_policy(tenant_id=cred.tenant_id, now=now)
    mock_uow.expiration_policies.get_by_id.return_value = policy
    mock_uow.audit_logs.append_entry.side_effect = RuntimeError("audit down")
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    with pytest.raises(ApplicationAuditFailure):
        await credential_service.attach_expiration_policy(
            AttachExpirationPolicyCommand(
                tenant_id=tenant_id,
                credential_id=credential_id,
                policy_id=policy.policy_id.value,
                principal_id=principal_id,
            )
        )

    mock_uow.commit.assert_not_awaited()


async def test_attach_expiration_policy_validation_failure(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    with pytest.raises(ApplicationValidationError) as exc_info:
        await credential_service.attach_expiration_policy(
            AttachExpirationPolicyCommand(
                tenant_id=EntityId.generate(),
                credential_id=uuid4(),
                policy_id=UUID(int=0),
                principal_id=EntityId.generate(),
            )
        )

    assert exc_info.value.field == "policy_id"
    mock_uow.__aenter__.assert_not_awaited()


async def test_detach_expiration_policy_success(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_event_publisher,
    now,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    policy = make_expiration_policy(tenant_id=cred.tenant_id, now=now)
    cred.attach_expiration_policy(cred.tenant_id, policy.policy_id, cred.owner_principal, now)
    cred.pop_events()
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    dto = await credential_service.detach_expiration_policy(
        DetachExpirationPolicyCommand(
            tenant_id=tenant_id,
            credential_id=credential_id,
            principal_id=principal_id,
        )
    )

    assert dto.expiration_policy_id is None
    mock_uow.commit.assert_awaited()
    events = _published_events(mock_event_publisher)
    assert any(isinstance(e, ExpirationPolicyDetached) for e in events)


async def test_detach_expiration_policy_access_denied(
    credential_service: CredentialApplicationService,
    mock_uow,
    mock_permission_port,
) -> None:
    mock_permission_port.has_permission.return_value = False

    with pytest.raises(AccessDenied):
        await credential_service.detach_expiration_policy(
            DetachExpirationPolicyCommand(
                tenant_id=EntityId.generate(),
                credential_id=uuid4(),
                principal_id=EntityId.generate(),
            )
        )

    mock_uow.__aenter__.assert_not_awaited()


async def test_detach_expiration_policy_audit_fail_closed(
    credential_service: CredentialApplicationService,
    mock_uow,
    now,
) -> None:
    cred, _version, _audit = _setup_active_resolve(mock_uow)
    policy = make_expiration_policy(tenant_id=cred.tenant_id, now=now)
    cred.attach_expiration_policy(cred.tenant_id, policy.policy_id, cred.owner_principal, now)
    cred.pop_events()
    mock_uow.audit_logs.append_entry.side_effect = RuntimeError("audit down")
    tenant_id, credential_id, principal_id = _ids_from_cred(cred)

    with pytest.raises(ApplicationAuditFailure):
        await credential_service.detach_expiration_policy(
            DetachExpirationPolicyCommand(
                tenant_id=tenant_id,
                credential_id=credential_id,
                principal_id=principal_id,
            )
        )

    mock_uow.commit.assert_not_awaited()


async def test_detach_expiration_policy_validation_failure(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    with pytest.raises(ApplicationValidationError) as exc_info:
        await credential_service.detach_expiration_policy(
            DetachExpirationPolicyCommand(
                tenant_id=UUID(int=0),
                credential_id=uuid4(),
                principal_id=EntityId.generate(),
            )
        )

    assert exc_info.value.field == "tenant_id"
    mock_uow.__aenter__.assert_not_awaited()


# ===========================================================================
# Cross-cutting not-found / invalid-state samples
# ===========================================================================


async def test_disable_credential_not_found(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    cid = CredentialId(uuid4())
    tid = TenantId.generate()
    mock_uow.credentials.get_by_id.side_effect = CredentialNotFound(cid, tid)

    with pytest.raises(CredentialNotFound):
        await credential_service.disable_credential(
            DisableCredentialCommand(
                tenant_id=tid,
                credential_id=cid.value,
                principal_id=EntityId.generate(),
                reason="gone",
            )
        )


async def test_disable_credential_invalid_state(
    credential_service: CredentialApplicationService,
    mock_uow,
) -> None:
    tid = TenantId.generate()
    pid = PrincipalId(uuid4())
    cid = CredentialId(uuid4())
    cred = make_credential(
        state=CredentialState.REVOKED,
        tenant_id=tid,
        credential_id=cid,
        principal_id=pid,
    )
    mock_uow.credentials.get_by_id.return_value = cred
    mock_uow.audit_logs.get_by_credential.return_value = make_audit_log(cid, tid)

    with pytest.raises(InvalidStateTransition):
        await credential_service.disable_credential(
            DisableCredentialCommand(
                tenant_id=tid,
                credential_id=cid.value,
                principal_id=EntityId.from_uuid(pid.value),
                reason="already revoked",
            )
        )
