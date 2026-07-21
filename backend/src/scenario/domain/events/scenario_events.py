"""Scenario domain events."""

from __future__ import annotations

from dataclasses import dataclass

from scenario.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class ScenarioTemplateCreated(BaseDomainEvent):
    scenario_key: str
    version: str
    name: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ScenarioTemplatePublished(BaseDomainEvent):
    scenario_key: str
    version: str
    technique_count: int
    threat_actor_id: str | None


@dataclass(frozen=True, slots=True, kw_only=True)
class ScenarioTemplateDeprecated(BaseDomainEvent):
    scenario_key: str
    version: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ScenarioInstantiated(BaseDomainEvent):
    scenario_key: str
    version: str
    instantiated_by_tenant_id: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ScenarioSubscriptionChanged(BaseDomainEvent):
    subscribed_tenant_id: str
    action: str  # subscribed | unsubscribed
    local_template_id: str | None = None
