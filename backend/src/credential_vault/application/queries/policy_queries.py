"""Rotation and expiration policy query dataclasses (CQRS read side)."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID  # noqa: TC003 — runtime type for frozen dataclass fields


@dataclass(frozen=True, slots=True)
class GetRotationPolicyQuery:
    tenant_id: UUID
    policy_id: UUID
    principal_id: UUID


@dataclass(frozen=True, slots=True)
class ListRotationPoliciesQuery:
    tenant_id: UUID
    principal_id: UUID


@dataclass(frozen=True, slots=True)
class GetExpirationPolicyQuery:
    tenant_id: UUID
    policy_id: UUID
    principal_id: UUID


@dataclass(frozen=True, slots=True)
class ListExpirationPoliciesQuery:
    tenant_id: UUID
    principal_id: UUID
