"""Immutable CQRS query objects for ai_security (M47A)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_security.domain.value_objects.identifiers import DeploymentId, TargetId, TenantId


@dataclass(frozen=True, slots=True)
class GetAiTargetQuery:
    tenant_id: TenantId
    target_id: TargetId


@dataclass(frozen=True, slots=True)
class ListAiTargetsQuery:
    tenant_id: TenantId


@dataclass(frozen=True, slots=True)
class GetDeploymentQuery:
    tenant_id: TenantId
    deployment_id: DeploymentId


@dataclass(frozen=True, slots=True)
class ListDeploymentsQuery:
    tenant_id: TenantId
