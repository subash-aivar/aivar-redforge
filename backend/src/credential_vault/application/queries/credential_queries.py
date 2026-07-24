"""Credential and version query dataclasses (CQRS read side)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import UUID  # noqa: TC003 — runtime type for frozen dataclass fields

if TYPE_CHECKING:
    from credential_vault.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class GetCredentialQuery:
    tenant_id: TenantId
    credential_id: UUID
    principal_id: TenantId


@dataclass(frozen=True, slots=True)
class ListCredentialsQuery:
    tenant_id: TenantId
    principal_id: TenantId
    states: list[str] | None = None
    limit: int = 100
    offset: int = 0


@dataclass(frozen=True, slots=True)
class GetVersionQuery:
    tenant_id: TenantId
    credential_id: UUID
    version_id: UUID
    principal_id: TenantId


@dataclass(frozen=True, slots=True)
class ListVersionsQuery:
    tenant_id: TenantId
    credential_id: UUID
    principal_id: TenantId
    states: list[str] | None = None
