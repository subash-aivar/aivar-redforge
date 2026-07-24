from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ai_security.domain.aggregates.ai_deployment import AiDeployment
from ai_security.domain.events.ai_deployment_events import DeploymentCreated, DeploymentUpdated
from ai_security.domain.exceptions.domain_exceptions import (
    InvalidDeploymentTransition,
    TenantMismatch,
)
from ai_security.domain.value_objects.endpoint_url import EndpointUrl
from ai_security.domain.value_objects.enums import DeploymentStatus, ModelFamily
from ai_security.domain.value_objects.identifiers import (
    DeploymentId,
    ProviderId,
    TargetId,
    TenantId,
)
from ai_security.domain.value_objects.model_version import ModelVersion

NOW = datetime.now(UTC)


def _create(**overrides) -> AiDeployment:
    defaults = {
        "deployment_id": DeploymentId.generate(),
        "tenant_id": TenantId.generate(),
        "target_id": TargetId.generate(),
        "model_family": ModelFamily.GPT,
        "model_version": ModelVersion("gpt-4-turbo"),
        "provider_id": ProviderId.generate(),
        "endpoint_url": EndpointUrl("https://api.openai.com/v1"),
        "now": NOW,
    }
    defaults.update(overrides)
    return AiDeployment.create(**defaults)


def test_create_is_pending_and_emits_event() -> None:
    deployment = _create()
    assert deployment.status == DeploymentStatus.PENDING
    events = deployment.pop_events()
    assert len(events) == 1
    assert isinstance(events[0], DeploymentCreated)


def test_valid_transition_pending_to_active() -> None:
    deployment = _create()
    deployment.pop_events()
    deployment.transition_status(deployment.tenant_id, DeploymentStatus.ACTIVE, NOW)
    assert deployment.status == DeploymentStatus.ACTIVE
    events = deployment.pop_events()
    assert isinstance(events[0], DeploymentUpdated)


def test_invalid_transition_raises() -> None:
    deployment = _create()
    deployment.transition_status(deployment.tenant_id, DeploymentStatus.DECOMMISSIONED, NOW)
    with pytest.raises(InvalidDeploymentTransition):
        deployment.transition_status(deployment.tenant_id, DeploymentStatus.ACTIVE, NOW)


def test_decommissioned_is_terminal() -> None:
    deployment = _create()
    deployment.transition_status(deployment.tenant_id, DeploymentStatus.DECOMMISSIONED, NOW)
    with pytest.raises(InvalidDeploymentTransition):
        deployment.transition_status(deployment.tenant_id, DeploymentStatus.ACTIVE, NOW)


def test_transition_wrong_tenant_raises() -> None:
    deployment = _create()
    with pytest.raises(TenantMismatch):
        deployment.transition_status(TenantId.generate(), DeploymentStatus.ACTIVE, NOW)
