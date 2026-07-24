"""Rotation and expiration policy query dataclasses (CQRS read side)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import UUID  # noqa: TC003 — runtime type for frozen dataclass fields

if TYPE_CHECKING:
    from credential_vault.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class GetRotationPolicyQuery:
    tenant_id: TenantId
    policy_id: UUID
    principal_id: TenantId


@dataclass(frozen=True, slots=True)
class ListRotationPoliciesQuery:
    tenant_id: TenantId
    principal_id: TenantId


@dataclass(frozen=True, slots=True)
class GetExpirationPolicyQuery:
    tenant_id: TenantId
    policy_id: UUID
    principal_id: TenantId


@dataclass(frozen=True, slots=True)
class ListExpirationPoliciesQuery:
    tenant_id: TenantId
    principal_id: TenantId
