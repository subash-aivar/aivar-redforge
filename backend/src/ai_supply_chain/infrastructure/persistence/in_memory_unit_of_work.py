from __future__ import annotations

from typing import TYPE_CHECKING

from ai_supply_chain.application.ports.i_unit_of_work import IUnitOfWork
from ai_supply_chain.domain.repositories.i_discovery_scan_run_repository import (
    IDiscoveryScanRunRepository,
)
from ai_supply_chain.domain.repositories.i_model_bill_of_materials_repository import (
    IModelBillOfMaterialsRepository,
)
from ai_supply_chain.domain.repositories.i_model_provenance_repository import (
    IModelProvenanceRepository,
)
from ai_supply_chain.domain.repositories.i_tenant_verification_settings_repository import (
    ITenantVerificationSettingsRepository,
    TenantVerificationSettings,
)
from ai_supply_chain.domain.value_objects.enums import ProvenanceIntegrityStatus

if TYPE_CHECKING:
    from types import TracebackType

    from ai_supply_chain.domain.aggregates.ai_discovery_scan_run import AIDiscoveryScanRun
    from ai_supply_chain.domain.aggregates.model_bill_of_materials import (
        ModelBillOfMaterials,
    )
    from ai_supply_chain.domain.aggregates.model_provenance import ModelProvenance
    from ai_supply_chain.domain.value_objects.identifiers import (
        AIDiscoveryScanRunId,
        AISystemAssetId,
        ModelProvenanceId,
        TenantId,
    )
    from ai_supply_chain.domain.value_objects.supply_chain_vos import MBOMComponent


class InMemoryProvenanceRepository(IModelProvenanceRepository):
    def __init__(self) -> None:
        self.items: dict[str, ModelProvenance] = {}

    async def save(self, provenance: ModelProvenance) -> None:
        self.items[str(provenance.provenance_id)] = provenance

    async def find_by_id(
        self, provenance_id: ModelProvenanceId, tenant_id: TenantId
    ) -> ModelProvenance | None:
        p = self.items.get(str(provenance_id))
        if p is None or p.tenant_id != tenant_id:
            return None
        return p

    async def find_by_asset(
        self, asset_id: AISystemAssetId, tenant_id: TenantId
    ) -> ModelProvenance | None:
        for p in self.items.values():
            if p.tenant_id == tenant_id and p.ai_system_asset_id == asset_id:
                return p
        return None

    async def find_mismatched(self, tenant_id: TenantId) -> list[ModelProvenance]:
        return [
            p
            for p in self.items.values()
            if p.tenant_id == tenant_id
            and p.integrity_status == ProvenanceIntegrityStatus.MISMATCHED
        ]


class InMemoryMBOMRepository(IModelBillOfMaterialsRepository):
    def __init__(self) -> None:
        self.items: dict[str, ModelBillOfMaterials] = {}

    async def save(self, mbom: ModelBillOfMaterials) -> None:
        self.items[str(mbom.mbom_id)] = mbom

    async def find_by_provenance(
        self, provenance_id: ModelProvenanceId, tenant_id: TenantId
    ) -> ModelBillOfMaterials | None:
        for m in self.items.values():
            if m.tenant_id == tenant_id and m.provenance_id == provenance_id:
                return m
        return None

    async def find_components_with_known_cve(self, tenant_id: TenantId) -> list[MBOMComponent]:
        result: list[MBOMComponent] = []
        for m in self.items.values():
            if m.tenant_id != tenant_id:
                continue
            for c in m.components:
                if c.known_cve_ids:
                    result.append(c)
        return result


class InMemoryScanRepository(IDiscoveryScanRunRepository):
    def __init__(self) -> None:
        self.items: dict[str, AIDiscoveryScanRun] = {}

    async def save(self, run: AIDiscoveryScanRun) -> None:
        self.items[str(run.scan_run_id)] = run

    async def find_by_id(
        self, run_id: AIDiscoveryScanRunId, tenant_id: TenantId
    ) -> AIDiscoveryScanRun | None:
        run = self.items.get(str(run_id))
        if run is None or run.tenant_id != tenant_id:
            return None
        return run

    async def find_recent(self, tenant_id: TenantId, limit: int) -> list[AIDiscoveryScanRun]:
        runs = [r for r in self.items.values() if r.tenant_id == tenant_id]
        runs.sort(key=lambda r: r.started_at, reverse=True)
        return runs[:limit]


class InMemorySettingsRepository(ITenantVerificationSettingsRepository):
    def __init__(self) -> None:
        self._settings: dict[str, TenantVerificationSettings] = {}

    async def get(self, tenant_id: TenantId) -> TenantVerificationSettings:
        key = str(tenant_id)
        if key not in self._settings:
            self._settings[key] = TenantVerificationSettings()
        return self._settings[key]

    async def save(self, tenant_id: TenantId, settings: TenantVerificationSettings) -> None:
        self._settings[str(tenant_id)] = settings


class InMemoryUnitOfWork(IUnitOfWork):
    def __init__(self) -> None:
        super().__init__()
        self.provenances = InMemoryProvenanceRepository()
        self.mboms = InMemoryMBOMRepository()
        self.scans = InMemoryScanRepository()
        self.settings = InMemorySettingsRepository()

    async def commit(self) -> None:
        self._committed = True

    async def rollback(self) -> None:
        pass

    async def __aenter__(self) -> InMemoryUnitOfWork:
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
