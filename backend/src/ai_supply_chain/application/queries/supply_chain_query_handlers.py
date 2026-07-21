"""Supply chain CQRS query handlers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ai_supply_chain.application._auth import require_at_least
from ai_supply_chain.application.dtos.supply_chain_dtos import (
    MBOMDTO,
    DiscoveryScanRunDTO,
    ModelProvenanceDTO,
)
from ai_supply_chain.application.exceptions import ApplicationNotFoundError
from ai_supply_chain.domain.value_objects.enums import AIPostureRole
from ai_supply_chain.domain.value_objects.identifiers import (
    AISystemAssetId,
    ModelProvenanceId,
    TenantId,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from ai_supply_chain.application.ports.i_unit_of_work import IUnitOfWork
    from ai_supply_chain.application.queries.supply_chain_queries import (
        GetIntegrityStatusForAssetQuery,
        GetMBOMByProvenanceQuery,
        GetModelProvenanceQuery,
        ListRecentDiscoveryScansQuery,
    )
    from ai_supply_chain.domain.aggregates.model_bill_of_materials import (
        ModelBillOfMaterials,
    )
    from ai_supply_chain.domain.aggregates.model_provenance import ModelProvenance


def _provenance_dto(p: ModelProvenance) -> ModelProvenanceDTO:
    latest_method = None
    latest_note = ""
    for entry in reversed(p.chain_entries):
        if entry.verification_method is not None:
            latest_method = entry.verification_method.value
            latest_note = entry.trust_delegation_note
            break
    return ModelProvenanceDTO(
        provenance_id=str(p.provenance_id),
        tenant_id=str(p.tenant_id),
        ai_system_asset_id=str(p.ai_system_asset_id),
        model_origin=p.model_origin.value,
        integrity_status=p.integrity_status.value,
        operational_status=p.operational_status.value,
        artifact_size_bytes=p.artifact_size_bytes,
        verification_method_latest=latest_method,
        trust_delegation_note_latest=latest_note,
        chain_entry_count=len(p.chain_entries),
        consecutive_failures=p.consecutive_failures,
    )


def _mbom_dto(m: ModelBillOfMaterials) -> MBOMDTO:
    return MBOMDTO(
        mbom_id=str(m.mbom_id),
        provenance_id=str(m.provenance_id),
        completed=m.completed,
        components=[
            {
                "component_type": c.component_type.value,
                "name": c.name,
                "version": c.version,
                "source": c.source,
                "checksum": c.checksum,
                "known_cve_ids": list(c.known_cve_ids),
            }
            for c in m.components
        ],
    )


class SupplyChainQueryHandler:
    def __init__(self, uow_factory: Callable[[], IUnitOfWork]) -> None:
        self._uow_factory = uow_factory

    async def get_provenance(self, query: GetModelProvenanceQuery) -> ModelProvenanceDTO:
        require_at_least(query.actor_roles, AIPostureRole.READER)
        tenant = TenantId(query.tenant_id)
        async with self._uow_factory() as uow:
            prov = await uow.provenances.find_by_id(ModelProvenanceId(query.provenance_id), tenant)
            if prov is None:
                raise ApplicationNotFoundError("ModelProvenance", str(query.provenance_id))
        return _provenance_dto(prov)

    async def get_mbom(self, query: GetMBOMByProvenanceQuery) -> MBOMDTO:
        require_at_least(query.actor_roles, AIPostureRole.READER)
        tenant = TenantId(query.tenant_id)
        async with self._uow_factory() as uow:
            mbom = await uow.mboms.find_by_provenance(
                ModelProvenanceId(query.provenance_id), tenant
            )
            if mbom is None:
                raise ApplicationNotFoundError("ModelBillOfMaterials", str(query.provenance_id))
        return _mbom_dto(mbom)

    async def get_integrity_for_asset(self, query: GetIntegrityStatusForAssetQuery) -> str | None:
        tenant = TenantId(query.tenant_id)
        async with self._uow_factory() as uow:
            prov = await uow.provenances.find_by_asset(AISystemAssetId(query.asset_id), tenant)
        return None if prov is None else prov.integrity_status.value

    async def list_recent_scans(
        self, query: ListRecentDiscoveryScansQuery
    ) -> list[DiscoveryScanRunDTO]:
        require_at_least(query.actor_roles, AIPostureRole.READER)
        tenant = TenantId(query.tenant_id)
        async with self._uow_factory() as uow:
            runs = await uow.scans.find_recent(tenant, query.limit)
        return [
            DiscoveryScanRunDTO(
                scan_run_id=str(r.scan_run_id),
                state=r.state.value,
                partial=r.partial,
                discovered_count=len(r.discovered),
                unmatched_count=len(r.unmatched),
                failed_partitions=list(r.failed_partitions),
                api_calls_used=r.api_calls_used,
            )
            for r in runs
        ]
