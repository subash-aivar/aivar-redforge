from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import select

from ai_supply_chain.domain.aggregates.model_bill_of_materials import ModelBillOfMaterials
from ai_supply_chain.domain.repositories.i_model_bill_of_materials_repository import (
    IModelBillOfMaterialsRepository,
)
from ai_supply_chain.domain.value_objects.enums import MBOMComponentType
from ai_supply_chain.domain.value_objects.identifiers import (
    ModelBillOfMaterialsId,
    ModelProvenanceId,
    TenantId,
)
from ai_supply_chain.domain.value_objects.supply_chain_vos import MBOMComponent
from ai_supply_chain.infrastructure.persistence.models.supply_chain_models import (
    MBOMComponentModel,
    ModelBillOfMaterialsModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class PgMBOMRepository(IModelBillOfMaterialsRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, mbom: ModelBillOfMaterials) -> None:
        row = await self._session.get(ModelBillOfMaterialsModel, mbom.mbom_id.value)
        if row is None:
            self._session.add(
                ModelBillOfMaterialsModel(
                    id=mbom.mbom_id.value,
                    tenant_id=mbom.tenant_id.value,
                    provenance_id=mbom.provenance_id.value,
                    completed=mbom.completed,
                    row_version=mbom.version,
                )
            )
        else:
            row.completed = mbom.completed
            row.row_version = mbom.version
        existing = {
            (r.name, r.version, r.component_type)
            for r in (
                await self._session.execute(
                    select(MBOMComponentModel).where(
                        MBOMComponentModel.mbom_id == mbom.mbom_id.value
                    )
                )
            ).scalars()
        }
        for c in mbom.components:
            key = (c.name, c.version, c.component_type.value)
            if key in existing:
                continue
            self._session.add(
                MBOMComponentModel(
                    id=uuid4(),
                    tenant_id=mbom.tenant_id.value,
                    mbom_id=mbom.mbom_id.value,
                    component_type=c.component_type.value,
                    name=c.name,
                    version=c.version,
                    source=c.source,
                    checksum=c.checksum,
                    known_cve_ids_json=list(c.known_cve_ids),
                )
            )

    async def find_by_provenance(
        self, provenance_id: ModelProvenanceId, tenant_id: TenantId
    ) -> ModelBillOfMaterials | None:
        result = await self._session.execute(
            select(ModelBillOfMaterialsModel).where(
                ModelBillOfMaterialsModel.tenant_id == tenant_id.value,
                ModelBillOfMaterialsModel.provenance_id == provenance_id.value,
            )
        )
        row = result.scalar_one_or_none()
        if row is None:
            return None
        comps = (
            await self._session.execute(
                select(MBOMComponentModel).where(MBOMComponentModel.mbom_id == row.id)
            )
        ).scalars()
        components = [
            MBOMComponent(
                MBOMComponentType(c.component_type),
                c.name,
                c.version,
                c.source,
                c.checksum,
                tuple(c.known_cve_ids_json or []),
            )
            for c in comps
        ]
        return ModelBillOfMaterials(
            ModelBillOfMaterialsId(row.id),
            TenantId.from_uuid(row.tenant_id),
            ModelProvenanceId(row.provenance_id),
            components,
            row.completed,
            row.row_version,
        )

    async def find_components_with_known_cve(self, tenant_id: TenantId) -> list[MBOMComponent]:
        result = await self._session.execute(
            select(MBOMComponentModel).where(MBOMComponentModel.tenant_id == tenant_id.value)
        )
        out: list[MBOMComponent] = []
        for c in result.scalars():
            cves = list(c.known_cve_ids_json or [])
            if cves:
                out.append(
                    MBOMComponent(
                        MBOMComponentType(c.component_type),
                        c.name,
                        c.version,
                        c.source,
                        c.checksum,
                        tuple(cves),
                    )
                )
        return out
