"""ModelBillOfMaterialsBuilder — assemble MBOM with CVE enrichment."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ai_supply_chain.domain.aggregates.model_bill_of_materials import ModelBillOfMaterials
from ai_supply_chain.domain.value_objects.identifiers import ModelBillOfMaterialsId
from ai_supply_chain.domain.value_objects.supply_chain_vos import MBOMComponent

if TYPE_CHECKING:
    from datetime import datetime

    from ai_supply_chain.domain.ports.i_vulnerability_query_port import (
        IVulnerabilityQueryPort,
    )
    from ai_supply_chain.domain.value_objects.identifiers import (
        ModelProvenanceId,
        TenantId,
    )


class ModelBillOfMaterialsBuilder:
    def __init__(self, vulnerability_port: IVulnerabilityQueryPort) -> None:
        self._vuln = vulnerability_port

    async def build(
        self,
        tenant_id: TenantId,
        provenance_id: ModelProvenanceId,
        raw_components: list[MBOMComponent],
        now: datetime,
        *,
        existing: ModelBillOfMaterials | None = None,
        mark_complete: bool = True,
    ) -> ModelBillOfMaterials:
        mbom = existing or ModelBillOfMaterials.create(
            ModelBillOfMaterialsId.generate(), tenant_id, provenance_id
        )
        for raw in raw_components:
            cves = await self._vuln.find_cves_for_component(tenant_id, raw.name, raw.version)
            enriched = MBOMComponent(
                component_type=raw.component_type,
                name=raw.name,
                version=raw.version,
                source=raw.source,
                checksum=raw.checksum,
                known_cve_ids=tuple(cves),
            )
            mbom.add_component(tenant_id, enriched, now)
        if mark_complete:
            mbom.complete(tenant_id, now)
        return mbom
