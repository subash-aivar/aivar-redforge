"""In-memory fakes for scenario tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

from scenario.application.ports.i_event_publisher import IEventPublisher
from scenario.application.ports.i_unit_of_work import IUnitOfWork
from scenario.domain.repositories.i_scenario_template_repository import (
    IScenarioTemplateRepository,
)
from scenario.domain.value_objects.enums import ScenarioTemplateState

if TYPE_CHECKING:
    from types import TracebackType

    from scenario.domain.aggregates.scenario_template import ScenarioTemplate
    from scenario.domain.events.base import BaseDomainEvent
    from scenario.domain.value_objects.identifiers import ScenarioTemplateId, TenantId
    from scenario.domain.value_objects.scenario_vos import MitreAttackRef


class FakeScenarioTemplateRepository(IScenarioTemplateRepository):
    def __init__(self) -> None:
        self._items: dict[str, ScenarioTemplate] = {}

    async def save(self, template: ScenarioTemplate) -> None:
        self._items[str(template.template_id)] = template

    async def find_by_id(
        self,
        template_id: ScenarioTemplateId,
        tenant_id: TenantId,
    ) -> ScenarioTemplate | None:
        template = self._items.get(str(template_id))
        if template is None or template.tenant_id != tenant_id:
            return None
        return template

    async def find_published_by_tenant(
        self,
        tenant_id: TenantId,
    ) -> list[ScenarioTemplate]:
        return [
            t
            for t in self._items.values()
            if t.tenant_id == tenant_id and t.state == ScenarioTemplateState.PUBLISHED
        ]

    async def find_by_attack_technique(
        self,
        technique_ref: MitreAttackRef,
        tenant_id: TenantId,
    ) -> list[ScenarioTemplate]:
        return [
            t
            for t in self._items.values()
            if t.tenant_id == tenant_id
            and any(
                r.technique_id == technique_ref.technique_id
                for r in t.covered_techniques.techniques
            )
        ]


class FakeEventPublisher(IEventPublisher):
    def __init__(self) -> None:
        self.events: list[BaseDomainEvent] = []

    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        self.events.extend(events)


class FakeUnitOfWork(IUnitOfWork):
    def __init__(self) -> None:
        super().__init__()
        self.templates = FakeScenarioTemplateRepository()

    async def commit(self) -> None:
        self._committed = True

    async def rollback(self) -> None:
        pass

    async def __aenter__(self) -> FakeUnitOfWork:
        self._committed = False
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if exc_type is not None or not self._committed:
            await self.rollback()
