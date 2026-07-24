"""Tests for application DTOs."""

from __future__ import annotations

import json
from dataclasses import fields
from uuid import uuid4

from tests.credential_vault.application.conftest import (
    make_audit_log,
    make_credential,
    make_expiration_policy,
    make_rotation_policy,
    make_vault_backend,
    make_version,
)

from credential_vault.application.dtos.audit_dtos import AuditEntryDTO
from credential_vault.application.dtos.backend_dtos import VaultBackendDTO
from credential_vault.application.dtos.credential_dtos import (
    CredentialDTO,
    ResolvedSecretDTO,
    VersionDTO,
)
from credential_vault.application.dtos.policy_dtos import (
    ExpirationPolicyDTO,
    RotationPolicyDTO,
)
from credential_vault.domain.entities.audit_entry import AuditEntry
from credential_vault.domain.value_objects.audit_types import AuditOperation, AuditOutcome
from credential_vault.domain.value_objects.identifiers import (
    AuditEntryId,
    AuditLogId,
    CredentialId,
    PrincipalId,
    TenantId,
)
from credential_vault.domain.value_objects.states import VersionState


def test_credential_dto_from_aggregate_maps_fields() -> None:
    credential = make_credential()
    dto = CredentialDTO.from_aggregate(credential)
    assert len(fields(CredentialDTO)) == 17
    assert isinstance(dto.credential_id, str)
    assert isinstance(dto.tenant_id, str)
    assert isinstance(dto.name, str)
    assert dto.category == "API_KEY"
    assert dto.state == "ACTIVE"
    assert isinstance(dto.version, int)
    assert dto.created_at.endswith("+00:00")
    assert dto.updated_at.endswith("+00:00")


def test_credential_dto_tags_is_copy() -> None:
    credential = make_credential(tags={"a": "1"})
    dto = CredentialDTO.from_aggregate(credential)
    dto.tags["a"] = "mutated"
    assert credential.tags["a"] == "1"


def test_credential_dto_to_dict_json_serializable() -> None:
    dto = CredentialDTO.from_aggregate(make_credential())
    payload = dto.to_dict()
    json.dumps(payload)
    assert isinstance(payload["tags"], dict)


def test_version_dto_no_encrypted_payload_or_key_envelope() -> None:
    version = make_version(state=VersionState.ACTIVE)
    dto = VersionDTO.from_entity(version)
    names = {f.name for f in fields(VersionDTO)}
    assert "encrypted_payload" not in names
    assert "key_envelope" not in names
    assert "encrypted_payload" not in dto.to_dict()
    assert "key_envelope" not in dto.to_dict()
    assert not hasattr(dto, "encrypted_payload")
    assert dto.created_at.endswith("+00:00")
    assert isinstance(dto.version_id, str)


def test_resolved_secret_dto_no_to_dict() -> None:
    dto = ResolvedSecretDTO(
        credential_id=str(uuid4()),
        version_id=str(uuid4()),
        plaintext_secret=b"secret",
        resolved_at="2026-07-19T12:00:00+00:00",
    )
    assert "to_dict" not in ResolvedSecretDTO.__dict__
    assert not hasattr(dto, "to_dict") or not callable(getattr(type(dto), "to_dict", None))
    # Spec: method must not exist on the class
    assert "to_dict" not in dir(ResolvedSecretDTO) or not callable(
        getattr(ResolvedSecretDTO, "to_dict", None)
    )
    # Strongest check used by guide:
    assert not hasattr(ResolvedSecretDTO, "to_dict") or "to_dict" not in ResolvedSecretDTO.__dict__
    assert "to_dict" not in ResolvedSecretDTO.__dict__


def test_vault_backend_dto_no_config_field() -> None:
    backend = make_vault_backend()
    dto = VaultBackendDTO.from_aggregate(backend)
    names = {f.name for f in fields(VaultBackendDTO)}
    assert "config" not in names
    assert "config" not in dto.to_dict()
    assert not hasattr(dto, "config")
    assert dto.created_at.endswith("+00:00")


def test_rotation_policy_dto_from_aggregate() -> None:
    policy = make_rotation_policy()
    dto = RotationPolicyDTO.from_aggregate(policy)
    assert isinstance(dto.policy_id, str)
    assert dto.auto_rotate is True
    assert dto.created_at.endswith("+00:00")
    json.dumps(dto.to_dict())


def test_expiration_policy_dto_from_aggregate() -> None:
    policy = make_expiration_policy()
    dto = ExpirationPolicyDTO.from_aggregate(policy)
    assert isinstance(dto.policy_id, str)
    assert dto.ttl_days == 90
    json.dumps(dto.to_dict())


def test_audit_entry_dto_from_entity(now) -> None:
    log = make_audit_log(now=now)
    entry = AuditEntry(
        entry_id=AuditEntryId(uuid4()),
        audit_log_id=log.audit_log_id,
        credential_id=log.credential_id,
        tenant_id=log.tenant_id,
        operation=AuditOperation.CREATED,
        outcome=AuditOutcome.SUCCESS,
        principal_id=PrincipalId(uuid4()),
        occurred_at=now,
        version_id=None,
        client_ip="10.0.0.1",
        request_id="req-1",
        detail="ok",
        state_before=None,
        state_after=None,
    )
    dto = AuditEntryDTO.from_entity(entry)
    assert dto.operation == "CREATED"
    assert dto.outcome == "SUCCESS"
    assert isinstance(dto.principal_id, str)
    assert dto.occurred_at.endswith("+00:00")
    json.dumps(dto.to_dict())


def test_ids_serialized_as_strings() -> None:
    credential = make_credential()
    dto = CredentialDTO.from_aggregate(credential)
    assert dto.credential_id == str(credential.credential_id)
    assert dto.tenant_id == str(credential.tenant_id)
    assert isinstance(CredentialId(uuid4()), CredentialId)
    assert isinstance(TenantId.generate(), TenantId)
    assert isinstance(AuditLogId(uuid4()), AuditLogId)
