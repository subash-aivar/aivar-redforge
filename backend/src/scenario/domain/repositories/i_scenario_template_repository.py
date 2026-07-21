"""IScenarioTemplateRepository — domain repository interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scenario.domain.aggregates.scenario_template import ScenarioTemplate
    from scenario.domain.value_objects.identifiers import ScenarioTemplateId, TenantId
    from scenario.domain.value_objects.scenario_vos import MitreAttackRef


class IScenarioTemplateRepository(ABC):
    @abstractmethod
    async def save(self, template: ScenarioTemplate) -> None:
        """Persist the scenario template aggregate (insert or update)."""

    @abstractmethod
    async def find_by_id(
        self,
        template_id: ScenarioTemplateId,
        tenant_id: TenantId,
    ) -> ScenarioTemplate | None:
        """Return template by id and tenant, or None."""

    @abstractmethod
    async def find_published_by_tenant(
        self,
        tenant_id: TenantId,
    ) -> list[ScenarioTemplate]:
        """Return all published templates for a tenant."""

    @abstractmethod
    async def find_by_attack_technique(
        self,
        technique_ref: MitreAttackRef,
        tenant_id: TenantId,
    ) -> list[ScenarioTemplate]:
        """Return templates covering the given ATT&CK technique."""
