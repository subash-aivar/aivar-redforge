"""Domain tests for platform scenario subscription distribution."""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

import pytest

from scenario.domain.aggregates.scenario_template import ScenarioTemplate
from scenario.domain.exceptions.domain_exceptions import InvalidTemplateState
from scenario.domain.value_objects.enums import ScenarioTemplateState
from scenario.domain.value_objects.identifiers import ScenarioTemplateId, TenantId


def test_subscribe_and_local_copy(
    template_kwargs: dict, tenant_id: TenantId, now: datetime
) -> None:
    template = ScenarioTemplate.create(**template_kwargs)
    template.publish(tenant_id, now)
    subscriber = TenantId(uuid4())
    local_id = ScenarioTemplateId.generate()
    local = template.create_tenant_local_copy(
        local_template_id=local_id,
        subscriber_tenant_id=subscriber,
        now=now,
    )
    template.subscribe_tenant(
        tenant_id=tenant_id,
        subscriber_tenant_id=str(subscriber),
        now=now,
        local_template_id=local_id,
    )
    assert local.tenant_id == subscriber
    assert local.state == ScenarioTemplateState.PUBLISHED
    assert local.source_template_id == template.template_id
    assert template.subscription_scope.contains(str(subscriber))
    events = template.pop_events()
    assert any(type(e).__name__ == "ScenarioSubscriptionChanged" for e in events)


def test_subscribe_requires_published(
    template_kwargs: dict, tenant_id: TenantId, now: datetime
) -> None:
    template = ScenarioTemplate.create(**template_kwargs)
    with pytest.raises(InvalidTemplateState):
        template.subscribe_tenant(
            tenant_id=tenant_id,
            subscriber_tenant_id=str(uuid4()),
            now=now,
        )
