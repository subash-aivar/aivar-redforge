from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import TracebackType

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
    )


class IUnitOfWork(ABC):
    provenances: IModelProvenanceRepository
    mboms: IModelBillOfMaterialsRepository
    scans: IDiscoveryScanRunRepository
    settings: ITenantVerificationSettingsRepository

    def __init__(self) -> None:
        self._committed = False

    @abstractmethod
    async def commit(self) -> None: ...

    @abstractmethod
    async def rollback(self) -> None: ...

    @abstractmethod
    async def __aenter__(self) -> IUnitOfWork: ...

    @abstractmethod
    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None: ...
