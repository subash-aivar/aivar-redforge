"""ModelBillOfMaterials aggregate — component manifest for a model."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from ai_supply_chain.domain.events.supply_chain_events import (
    ModelBillOfMaterialsCompleted,
    ModelBillOfMaterialsComponentAdded,
)
from ai_supply_chain.domain.exceptions.domain_exceptions import (
    MBOMComponentImmutable,
    MBOMIncomplete,
    TenantMismatch,
)
from ai_supply_chain.domain.value_objects.enums import MBOMComponentType

if TYPE_CHECKING:
    from datetime import datetime

    from ai_supply_chain.domain.events.base import BaseDomainEvent
    from ai_supply_chain.domain.value_objects.identifiers import (
        ModelBillOfMaterialsId,
        ModelProvenanceId,
        TenantId,
    )
    from ai_supply_chain.domain.value_objects.supply_chain_vos import MBOMComponent


class ModelBillOfMaterials:
    __slots__ = (
        "_pending_events",
        "_version",
        "completed",
        "components",
        "mbom_id",
        "provenance_id",
        "tenant_id",
    )

    def __init__(
        self,
        mbom_id: ModelBillOfMaterialsId,
        tenant_id: TenantId,
        provenance_id: ModelProvenanceId,
        components: list[MBOMComponent],
        completed: bool,
        version: int,
    ) -> None:
        self.mbom_id = mbom_id
        self.tenant_id = tenant_id
        self.provenance_id = provenance_id
        self.components = list(components)
        self.completed = completed
        self._version = version
        self._pending_events: list[BaseDomainEvent] = []

    @property
    def version(self) -> int:
        return self._version

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
        mbom_id: ModelBillOfMaterialsId,
        tenant_id: TenantId,
        provenance_id: ModelProvenanceId,
    ) -> ModelBillOfMaterials:
        return cls(
            mbom_id=mbom_id,
            tenant_id=tenant_id,
            provenance_id=provenance_id,
            components=[],
            completed=False,
            version=1,
        )

    def add_component(self, tenant_id: TenantId, component: MBOMComponent, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.completed:
            raise MBOMComponentImmutable()
        self.components.append(component)
        self._version += 1
        self._emit(
            ModelBillOfMaterialsComponentAdded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.mbom_id),
                aggregate_type="ModelBillOfMaterials",
                mbom_id=str(self.mbom_id),
                component_name=component.name,
                component_type=component.component_type.value,
            )
        )

    def complete(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if not any(c.component_type == MBOMComponentType.BASE_MODEL for c in self.components):
            raise MBOMIncomplete()
        self.completed = True
        self._version += 1
        self._emit(
            ModelBillOfMaterialsCompleted(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.mbom_id),
                aggregate_type="ModelBillOfMaterials",
                mbom_id=str(self.mbom_id),
                component_count=len(self.components),
            )
        )

    def remove_component(self, *_args: object, **_kwargs: object) -> None:
        raise MBOMComponentImmutable()
