from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True, slots=True)
class GetInventoryDashboardQuery:
    tenant_id: UUID
    actor_roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GetRiskRegisterQuery:
    tenant_id: UUID
    actor_roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GetShadowAIDiscoveryReportQuery:
    tenant_id: UUID
    actor_roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GetCompliancePostureQuery:
    tenant_id: UUID
    framework_id: str
    actor_roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GetSupplyChainIntegrityQuery:
    tenant_id: UUID
    actor_roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GetAgentDeviationReportQuery:
    tenant_id: UUID
    actor_roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GetEnvelopeApprovalAuditQuery:
    tenant_id: UUID
    envelope_id: UUID
    actor_roles: tuple[str, ...]
