from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from ai_posture.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class GetInventoryDashboardQuery:
    tenant_id: TenantId
    actor_roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GetRiskRegisterQuery:
    tenant_id: TenantId
    actor_roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GetShadowAIDiscoveryReportQuery:
    tenant_id: TenantId
    actor_roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GetCompliancePostureQuery:
    tenant_id: TenantId
    framework_id: str
    actor_roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GetSupplyChainIntegrityQuery:
    tenant_id: TenantId
    actor_roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GetAgentDeviationReportQuery:
    tenant_id: TenantId
    actor_roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GetEnvelopeApprovalAuditQuery:
    tenant_id: TenantId
    envelope_id: UUID
    actor_roles: tuple[str, ...]
