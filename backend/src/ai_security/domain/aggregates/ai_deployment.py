"""AiDeployment aggregate — a deployment of a model/provider
combination behind an `AiTarget` (M47A).

References its owning `AiTarget` and `AiProvider` by id only, never by
object reference. Owns a coarse lifecycle status placeholder only — no
runtime health, no evaluation, no guardrail enforcement."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ai_security.domain.events.ai_deployment_events import DeploymentCreated, DeploymentUpdated
from ai_security.domain.exceptions.domain_exceptions import (
    InvalidDeploymentTransition,
    TenantMismatch,
)
from ai_security.domain.value_objects.enums import DeploymentStatus

if TYPE_CHECKING:
    from datetime import datetime

    from ai_security.domain.events.base import BaseDomainEvent
    from ai_security.domain.value_objects.endpoint_url import EndpointUrl
    from ai_security.domain.value_objects.enums import ModelFamily
    from ai_security.domain.value_objects.identifiers import (
        DeploymentId,
        ProviderId,
        TargetId,
        TenantId,
    )
    from ai_security.domain.value_objects.model_version import ModelVersion

_VALID_TRANSITIONS: dict[DeploymentStatus, set[DeploymentStatus]] = {
    DeploymentStatus.PENDING: {DeploymentStatus.ACTIVE, DeploymentStatus.DECOMMISSIONED},
    DeploymentStatus.ACTIVE: {DeploymentStatus.PAUSED, DeploymentStatus.DECOMMISSIONED},
    DeploymentStatus.PAUSED: {DeploymentStatus.ACTIVE, DeploymentStatus.DECOMMISSIONED},
    DeploymentStatus.DECOMMISSIONED: set(),
}


class AiDeployment:
    __slots__ = (
        "_pending_events",
        "created_at",
        "deployment_id",
        "endpoint_url",
        "model_family",
        "model_version",
        "provider_id",
        "status",
        "target_id",
        "tenant_id",
        "updated_at",
    )

    def __init__(
        self,
        deployment_id: DeploymentId,
        tenant_id: TenantId,
        target_id: TargetId,
        model_family: ModelFamily,
        model_version: ModelVersion,
        provider_id: ProviderId,
        endpoint_url: EndpointUrl,
        created_at: datetime,
        updated_at: datetime,
        status: DeploymentStatus = DeploymentStatus.PENDING,
    ) -> None:
        self.deployment_id = deployment_id
        self.tenant_id = tenant_id
        self.target_id = target_id
        self.model_family = model_family
        self.model_version = model_version
        self.provider_id = provider_id
        self.endpoint_url = endpoint_url
        self.created_at = created_at
        self.updated_at = updated_at
        self.status = status
        self._pending_events: list[BaseDomainEvent] = []

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    @classmethod
    def create(
        cls,
        deployment_id: DeploymentId,
        tenant_id: TenantId,
        target_id: TargetId,
        model_family: ModelFamily,
        model_version: ModelVersion,
        provider_id: ProviderId,
        endpoint_url: EndpointUrl,
        now: datetime,
    ) -> AiDeployment:
        deployment = cls(
            deployment_id=deployment_id,
            tenant_id=tenant_id,
            target_id=target_id,
            model_family=model_family,
            model_version=model_version,
            provider_id=provider_id,
            endpoint_url=endpoint_url,
            created_at=now,
            updated_at=now,
        )
        deployment._emit(
            DeploymentCreated(
                tenant_id=str(tenant_id),
                aggregate_id=str(deployment_id),
                aggregate_type="AiDeployment",
                occurred_at=now,
                target_id=str(target_id),
            )
        )
        return deployment

    def transition_status(
        self, tenant_id: TenantId, to_status: DeploymentStatus, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        allowed = _VALID_TRANSITIONS.get(self.status, set())
        if to_status not in allowed:
            raise InvalidDeploymentTransition(self.status.value, to_status.value)
        self.status = to_status
        self.updated_at = now
        self._emit(
            DeploymentUpdated(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.deployment_id),
                aggregate_type="AiDeployment",
                occurred_at=now,
                status=str(to_status),
            )
        )
