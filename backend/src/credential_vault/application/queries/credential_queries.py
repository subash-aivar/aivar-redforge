"""Credential and version query dataclasses (CQRS read side)."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID  # noqa: TC003 — runtime type for frozen dataclass fields


@dataclass(frozen=True, slots=True)
class GetCredentialQuery:
    tenant_id: UUID
    credential_id: UUID
    principal_id: UUID


@dataclass(frozen=True, slots=True)
class ListCredentialsQuery:
    tenant_id: UUID
    principal_id: UUID
    states: list[str] | None = None
    limit: int = 100
    offset: int = 0


@dataclass(frozen=True, slots=True)
class GetVersionQuery:
    tenant_id: UUID
    credential_id: UUID
    version_id: UUID
    principal_id: UUID


@dataclass(frozen=True, slots=True)
class ListVersionsQuery:
    tenant_id: UUID
    credential_id: UUID
    principal_id: UUID
    states: list[str] | None = None
