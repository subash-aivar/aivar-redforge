from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from ml_pipeline.domain.exceptions.domain_exceptions import ArtifactNotFoundError
from ml_pipeline.domain.repositories.i_ml_repositories import (
    IMLModelArtifactStore,
    IMLModelRepository,
    IPredictiveRiskSignalRepository,
)
from ml_pipeline.domain.value_objects.enums import MLModelStatus
from ml_pipeline.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

    from ml_pipeline.domain.aggregates.ml_model import MLModel
    from ml_pipeline.domain.aggregates.predictive_risk_signal import PredictiveRiskSignal
    from ml_pipeline.domain.value_objects.enums import MLModelType
    from ml_pipeline.domain.value_objects.identifiers import (
        MLModelId,
        TenantId,
    )


class InMemoryMLModelRepository(IMLModelRepository):
    def __init__(self) -> None:
        self._rows: dict[str, dict[str, MLModel]] = {}

    async def save(self, tenant_id: TenantId, model: MLModel) -> None:
        self._rows.setdefault(str(tenant_id), {})[str(model.model_id)] = model

    async def find_by_id(self, tenant_id: TenantId, model_id: MLModelId) -> MLModel | None:
        return self._rows.get(str(tenant_id), {}).get(str(model_id))

    async def find_deployed_by_type(
        self, tenant_id: TenantId, model_type: MLModelType
    ) -> MLModel | None:
        for m in self._rows.get(str(tenant_id), {}).values():
            if m.model_type == model_type and m.status == MLModelStatus.DEPLOYED:
                return m
        return None

    async def list_for_tenant(
        self,
        tenant_id: TenantId,
        *,
        model_type: MLModelType | None = None,
        status: MLModelStatus | None = None,
    ) -> list[MLModel]:
        rows = list(self._rows.get(str(tenant_id), {}).values())
        if model_type is not None:
            rows = [m for m in rows if m.model_type == model_type]
        if status is not None:
            rows = [m for m in rows if m.status == status]
        return rows

    async def find_models_for_drift_check(self, last_checked_before: datetime) -> list[MLModel]:
        out: list[MLModel] = []
        for bucket in self._rows.values():
            for m in bucket.values():
                if m.status != MLModelStatus.DEPLOYED:
                    continue
                if m.last_drift_check_at is None or m.last_drift_check_at < last_checked_before:
                    out.append(m)
        return out


class InMemoryPredictiveRiskSignalRepository(IPredictiveRiskSignalRepository):
    def __init__(self) -> None:
        self._rows: dict[str, list[PredictiveRiskSignal]] = {}

    async def save_many(self, tenant_id: TenantId, signals: list[PredictiveRiskSignal]) -> None:
        self._rows.setdefault(str(tenant_id), []).extend(signals)

    async def find_by_asset(
        self, tenant_id: TenantId, asset_ref_id: UUID, *, now: datetime
    ) -> list[PredictiveRiskSignal]:
        return [
            s
            for s in self._rows.get(str(tenant_id), [])
            if s.asset_ref_id == asset_ref_id and s.is_active(now)
        ]

    async def find_active_by_type(
        self, tenant_id: TenantId, signal_type: str, *, now: datetime
    ) -> list[PredictiveRiskSignal]:
        return [
            s
            for s in self._rows.get(str(tenant_id), [])
            if s.signal_type == signal_type and s.is_active(now)
        ]


class InMemoryMLModelArtifactStore(IMLModelArtifactStore):
    """Tenant-scoped BYTEA-like artifact store with SHA-256 integrity."""

    def __init__(self) -> None:
        self._store: dict[str, dict[str, tuple[bytes, str]]] = {}

    async def store_artifact(
        self, tenant_id: TenantId, model_id: UUID, artifact_bytes: bytes
    ) -> str:
        digest = hashlib.sha256(artifact_bytes).hexdigest()
        self._store.setdefault(str(tenant_id), {})[str(model_id)] = (
            bytes(artifact_bytes),
            digest,
        )
        return digest

    async def load_artifact(self, tenant_id: TenantId, model_id: UUID) -> tuple[bytes, str]:
        row = self._store.get(str(tenant_id), {}).get(str(model_id))
        if row is None:
            raise ArtifactNotFoundError("artifact not found for tenant/model")
        blob, stored_hash = row
        digest = hashlib.sha256(blob).hexdigest()
        if digest != stored_hash:
            from ml_pipeline.domain.exceptions.domain_exceptions import (
                ArtifactIntegrityError,
            )

            raise ArtifactIntegrityError("SHA-256 mismatch on load")
        return blob, stored_hash

    def corrupt_for_test(self, tenant_id: TenantId, model_id: UUID) -> None:
        """Bit-flip stored bytes without updating hash (integrity test helper)."""
        blob, digest = self._store[str(tenant_id)][str(model_id)]
        mutated = bytearray(blob)
        if mutated:
            mutated[0] ^= 0xFF
        self._store[str(tenant_id)][str(model_id)] = (bytes(mutated), digest)
