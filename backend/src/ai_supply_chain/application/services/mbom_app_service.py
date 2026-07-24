from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from ai_supply_chain.application._auth import require_at_least
from ai_supply_chain.application.dtos.supply_chain_dtos import MBOMDTO
from ai_supply_chain.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from ai_supply_chain.domain.exceptions.domain_exceptions import SupplyChainDomainError
from ai_supply_chain.domain.services.mbom_builder_service import ModelBillOfMaterialsBuilder
from ai_supply_chain.domain.value_objects.enums import AIPostureRole, MBOMComponentType
from ai_supply_chain.domain.value_objects.identifiers import ModelProvenanceId, TenantId
from ai_supply_chain.domain.value_objects.supply_chain_vos import MBOMComponent

if TYPE_CHECKING:
    from collections.abc import Callable

    from ai_supply_chain.application.commands.supply_chain_commands import BuildMBOMCommand
    from ai_supply_chain.application.ports.i_event_publisher import IEventPublisher
    from ai_supply_chain.application.ports.i_unit_of_work import IUnitOfWork
    from ai_supply_chain.domain.ports.i_vulnerability_query_port import (
        IVulnerabilityQueryPort,
    )


def _to_dto(mbom: Any) -> MBOMDTO:
    return MBOMDTO(
        mbom_id=str(mbom.mbom_id),
        provenance_id=str(mbom.provenance_id),
        completed=mbom.completed,
        components=[
            {
                "component_type": c.component_type.value,
                "name": c.name,
                "version": c.version,
                "source": c.source,
                "checksum": c.checksum,
                "known_cve_ids": list(c.known_cve_ids),
            }
            for c in mbom.components
        ],
    )


class MBOMApplicationService:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
        vulnerability_port: IVulnerabilityQueryPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._publisher = event_publisher
        self._builder = ModelBillOfMaterialsBuilder(vulnerability_port)

    async def build(self, cmd: BuildMBOMCommand) -> MBOMDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.ENGINEER)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        raw: list[MBOMComponent] = []
        for item in cmd.components:
            raw.append(
                MBOMComponent(
                    component_type=MBOMComponentType(item["component_type"]),
                    name=item["name"],
                    version=item["version"],
                    source=item.get("source", ""),
                    checksum=item.get("checksum", ""),
                )
            )
        async with self._uow_factory() as uow:
            prov = await uow.provenances.find_by_id(ModelProvenanceId(cmd.provenance_id), tenant)
            if prov is None:
                raise ApplicationNotFoundError("ModelProvenance", str(cmd.provenance_id))
            existing = await uow.mboms.find_by_provenance(prov.provenance_id, tenant)
            try:
                mbom = await self._builder.build(
                    tenant, prov.provenance_id, raw, now, existing=existing
                )
            except SupplyChainDomainError as exc:
                raise ApplicationValidationError(str(exc)) from exc
            await uow.mboms.save(mbom)
            await uow.commit()
            await self._publisher.publish_batch(mbom.pop_events())
        return _to_dto(mbom)

    async def get_by_provenance(self, tenant_id: TenantId, provenance_id: UUID) -> MBOMDTO:
        tenant = tenant_id
        async with self._uow_factory() as uow:
            mbom = await uow.mboms.find_by_provenance(ModelProvenanceId(provenance_id), tenant)
            if mbom is None:
                raise ApplicationNotFoundError("ModelBillOfMaterials", str(provenance_id))
        return _to_dto(mbom)
