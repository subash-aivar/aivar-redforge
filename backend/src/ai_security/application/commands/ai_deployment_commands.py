"""Immutable CQRS command objects for AiDeployment (M47A)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_security.domain.value_objects.endpoint_url import EndpointUrl
    from ai_security.domain.value_objects.enums import DeploymentStatus, ModelFamily
    from ai_security.domain.value_objects.identifiers import (
        DeploymentId,
        ProviderId,
        TargetId,
        TenantId,
    )
    from ai_security.domain.value_objects.model_version import ModelVersion


@dataclass(frozen=True, slots=True)
class CreateDeploymentCommand:
    tenant_id: TenantId
    target_id: TargetId
    model_family: ModelFamily
    model_version: ModelVersion
    provider_id: ProviderId
    endpoint_url: EndpointUrl


@dataclass(frozen=True, slots=True)
class UpdateDeploymentCommand:
    tenant_id: TenantId
    deployment_id: DeploymentId
    status: DeploymentStatus
