
"""Evidence application queries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from evidence.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class GetEvidence:
    tenant_id: TenantId
    evidence_id: UUID


@dataclass(frozen=True, slots=True)
class ListEvidenceByOperation:
    tenant_id: TenantId
    operation_id: UUID
    limit: int = 100
    offset: int = 0


@dataclass(frozen=True, slots=True)
class GetEvidenceChain:
    tenant_id: TenantId
    chain_id: UUID


@dataclass(frozen=True, slots=True)
class GetEvidenceChainByOperation:
    tenant_id: TenantId
    operation_id: UUID
