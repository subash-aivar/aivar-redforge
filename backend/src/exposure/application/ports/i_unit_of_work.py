from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Self

if TYPE_CHECKING:
    from exposure.application.ports.i_pipeline_stores import (
        IPendingRecomputationStore,
        IProcessedExposureSignalStore,
        ITenantExposureProfileStore,
    )
    from exposure.domain.repositories.i_amplifier_weight_configuration_repository import (
        IAmplifierWeightConfigurationRepository,
    )
    from exposure.domain.repositories.i_exposure_record_repository import (
        IExposureRecordRepository,
    )
    from exposure.domain.repositories.i_exposure_score_snapshot_repository import (
        IExposureScoreSnapshotRepository,
    )


class IUnitOfWork(ABC):
    records: IExposureRecordRepository
    snapshots: IExposureScoreSnapshotRepository
    weights: IAmplifierWeightConfigurationRepository
    pending: IPendingRecomputationStore
    processed_signals: IProcessedExposureSignalStore
    profiles: ITenantExposureProfileStore

    @abstractmethod
    async def commit(self) -> None: ...

    @abstractmethod
    async def rollback(self) -> None: ...

    @abstractmethod
    async def __aenter__(self) -> Self: ...

    @abstractmethod
    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None: ...
