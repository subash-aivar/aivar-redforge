"""Frozen repository interfaces for ml_pipeline (M33 Finalization §2).

Concrete Phase 3 adapters live in
`infrastructure.persistence.in_memory_repositories` and match these contracts.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

    from ml_pipeline.domain.aggregates.ml_model import MLModel
    from ml_pipeline.domain.aggregates.predictive_risk_signal import PredictiveRiskSignal
    from ml_pipeline.domain.value_objects.enums import MLModelStatus, MLModelType
    from ml_pipeline.domain.value_objects.identifiers import MLModelId, TenantId


class IMLModelRepository(ABC):
    @abstractmethod
    async def find_by_id(self, tenant_id: TenantId, model_id: MLModelId) -> MLModel | None: ...

    @abstractmethod
    async def find_deployed_by_type(
        self, tenant_id: TenantId, model_type: MLModelType
    ) -> MLModel | None: ...

    @abstractmethod
    async def list_for_tenant(
        self,
        tenant_id: TenantId,
        *,
        model_type: MLModelType | None = None,
        status: MLModelStatus | None = None,
    ) -> list[MLModel]: ...

    @abstractmethod
    async def find_models_for_drift_check(self, last_checked_before: datetime) -> list[MLModel]: ...

    @abstractmethod
    async def save(self, tenant_id: TenantId, model: MLModel) -> None: ...


class IPredictiveRiskSignalRepository(ABC):
    @abstractmethod
    async def find_by_asset(
        self, tenant_id: TenantId, asset_ref_id: UUID, *, now: datetime
    ) -> list[PredictiveRiskSignal]: ...

    @abstractmethod
    async def find_active_by_type(
        self, tenant_id: TenantId, signal_type: str, *, now: datetime
    ) -> list[PredictiveRiskSignal]: ...

    @abstractmethod
    async def save_many(self, tenant_id: TenantId, signals: list[PredictiveRiskSignal]) -> None: ...


class IMLModelArtifactStore(ABC):
    @abstractmethod
    async def store_artifact(
        self, tenant_id: UUID, model_id: UUID, artifact_bytes: bytes
    ) -> str: ...

    @abstractmethod
    async def load_artifact(self, tenant_id: UUID, model_id: UUID) -> tuple[bytes, str]: ...
