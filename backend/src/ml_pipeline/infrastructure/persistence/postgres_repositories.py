"""PostgreSQL repositories for ml_pipeline.

Session-per-call from an injected async_sessionmaker, matching the pattern
used across the other converted bounded contexts.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import select, update

from ml_pipeline.domain.aggregates.ml_model import MLModel
from ml_pipeline.domain.aggregates.predictive_risk_signal import PredictiveRiskSignal
from ml_pipeline.domain.exceptions.domain_exceptions import (
    ArtifactIntegrityError,
    ArtifactNotFoundError,
)
from ml_pipeline.domain.repositories.i_ml_repositories import (
    IMLModelArtifactStore,
    IMLModelRepository,
    IPredictiveRiskSignalRepository,
)
from ml_pipeline.domain.value_objects.enums import MLAlgorithm, MLModelStatus, MLModelType
from ml_pipeline.domain.value_objects.identifiers import (
    MLModelId,
    PredictiveRiskSignalId,
    TenantId,
)
from ml_pipeline.infrastructure.persistence.models.orm_models import (
    MLModelArtifactModel,
    MLModelModel,
    PredictiveRiskSignalModel,
)

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


def _model_to_row(model: MLModel) -> MLModelModel:
    return MLModelModel(
        id=model.model_id.value,
        tenant_id=model.tenant_id.value,
        model_type=model.model_type.value,
        algorithm=model.algorithm.value,
        status=model.status.value,
        dataset_id=UUID(model.dataset_id) if model.dataset_id else None,
        accuracy_metrics_json=dict(model.accuracy_metrics),
        artifact_hash=model.artifact_hash,
        failure_reason=model.failure_reason,
        created_at=model.created_at,
        trained_at=model.trained_at,
        deployed_at=model.deployed_at,
        deprecated_at=model.deprecated_at,
        last_drift_check_at=model.last_drift_check_at,
        psi_score=model.psi_score,
        governance_history_json=list(model.governance_history),
    )


def _row_to_model(row: MLModelModel) -> MLModel:
    return MLModel(
        model_id=MLModelId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id),
        model_type=MLModelType(row.model_type),
        algorithm=MLAlgorithm(row.algorithm),
        created_at=row.created_at,
        dataset_id=str(row.dataset_id) if row.dataset_id else None,
        status=MLModelStatus(row.status),
        accuracy_metrics=dict(row.accuracy_metrics_json),
        artifact_hash=row.artifact_hash,
        failure_reason=row.failure_reason,
        trained_at=row.trained_at,
        deployed_at=row.deployed_at,
        deprecated_at=row.deprecated_at,
        last_drift_check_at=row.last_drift_check_at,
        psi_score=row.psi_score,
        governance_history=list(row.governance_history_json),
    )


class PgMLModelRepository(IMLModelRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def save(self, tenant_id: TenantId, model: MLModel) -> None:
        async with self._session_factory() as session:
            await session.merge(_model_to_row(model))
            await session.commit()

    async def find_by_id(self, tenant_id: TenantId, model_id: MLModelId) -> MLModel | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(MLModelModel).where(
                        MLModelModel.tenant_id == tenant_id.value,
                        MLModelModel.id == model_id.value,
                    )
                )
            ).scalar_one_or_none()
            return _row_to_model(row) if row is not None else None

    async def find_deployed_by_type(
        self, tenant_id: TenantId, model_type: MLModelType
    ) -> MLModel | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(MLModelModel).where(
                        MLModelModel.tenant_id == tenant_id.value,
                        MLModelModel.model_type == model_type.value,
                        MLModelModel.status == MLModelStatus.DEPLOYED.value,
                    )
                )
            ).scalar_one_or_none()
            return _row_to_model(row) if row is not None else None

    async def list_for_tenant(
        self,
        tenant_id: TenantId,
        *,
        model_type: MLModelType | None = None,
        status: MLModelStatus | None = None,
    ) -> list[MLModel]:
        async with self._session_factory() as session:
            stmt = select(MLModelModel).where(MLModelModel.tenant_id == tenant_id.value)
            if model_type is not None:
                stmt = stmt.where(MLModelModel.model_type == model_type.value)
            if status is not None:
                stmt = stmt.where(MLModelModel.status == status.value)
            rows = (await session.execute(stmt)).scalars().all()
            return [_row_to_model(r) for r in rows]

    async def find_models_for_drift_check(self, last_checked_before: datetime) -> list[MLModel]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(MLModelModel).where(
                        MLModelModel.status == MLModelStatus.DEPLOYED.value,
                        (MLModelModel.last_drift_check_at.is_(None))
                        | (MLModelModel.last_drift_check_at < last_checked_before),
                    )
                )
            ).scalars().all()
            return [_row_to_model(r) for r in rows]


class PgPredictiveRiskSignalRepository(IPredictiveRiskSignalRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def save_many(self, tenant_id: TenantId, signals: list[PredictiveRiskSignal]) -> None:
        async with self._session_factory() as session:
            for signal in signals:
                session.add(
                    PredictiveRiskSignalModel(
                        id=signal.signal_id.value,
                        tenant_id=tenant_id.value,
                        model_id=signal.model_id.value,
                        asset_ref_id=signal.asset_ref_id,
                        signal_type=signal.signal_type,
                        score=signal.score,
                        confidence=signal.confidence,
                        created_at=signal.created_at,
                        expires_at=signal.expires_at,
                        features_json=dict(signal.features),
                    )
                )
            await session.commit()

    async def find_by_asset(
        self, tenant_id: TenantId, asset_ref_id: UUID, *, now: datetime
    ) -> list[PredictiveRiskSignal]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(PredictiveRiskSignalModel).where(
                        PredictiveRiskSignalModel.tenant_id == tenant_id.value,
                        PredictiveRiskSignalModel.asset_ref_id == asset_ref_id,
                        PredictiveRiskSignalModel.expires_at > now,
                    )
                )
            ).scalars().all()
            return [_row_to_signal(r) for r in rows]

    async def find_active_by_type(
        self, tenant_id: TenantId, signal_type: str, *, now: datetime
    ) -> list[PredictiveRiskSignal]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(PredictiveRiskSignalModel).where(
                        PredictiveRiskSignalModel.tenant_id == tenant_id.value,
                        PredictiveRiskSignalModel.signal_type == signal_type,
                        PredictiveRiskSignalModel.expires_at > now,
                    )
                )
            ).scalars().all()
            return [_row_to_signal(r) for r in rows]


def _row_to_signal(row: PredictiveRiskSignalModel) -> PredictiveRiskSignal:
    return PredictiveRiskSignal(
        signal_id=PredictiveRiskSignalId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id),
        model_id=MLModelId(row.model_id),
        asset_ref_id=row.asset_ref_id,
        signal_type=row.signal_type,
        score=row.score,
        confidence=row.confidence,
        created_at=row.created_at,
        expires_at=row.expires_at,
        features=dict(row.features_json),
    )


class PgMLModelArtifactStore(IMLModelArtifactStore):
    """Tenant-scoped BYTEA artifact store — one active artifact per (tenant,
    model), matching InMemoryMLModelArtifactStore's overwrite semantics.
    Superseded artifacts are kept (is_active=False) rather than deleted,
    since the migration's is_active column exists specifically for that.
    """

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def store_artifact(self, tenant_id: TenantId, model_id: UUID, artifact_bytes: bytes) -> str:
        digest = hashlib.sha256(artifact_bytes).hexdigest()
        async with self._session_factory() as session:
            await session.execute(
                update(MLModelArtifactModel)
                .where(
                    MLModelArtifactModel.tenant_id == tenant_id,
                    MLModelArtifactModel.model_id == model_id,
                    MLModelArtifactModel.is_active.is_(True),
                )
                .values(is_active=False)
            )
            from datetime import UTC, datetime

            session.add(
                MLModelArtifactModel(
                    id=uuid4(),
                    tenant_id=tenant_id,
                    model_id=model_id,
                    sha256=digest,
                    artifact_bytes=bytes(artifact_bytes),
                    byte_size=len(artifact_bytes),
                    is_active=True,
                    created_at=datetime.now(UTC),
                )
            )
            await session.commit()
        return digest

    async def load_artifact(self, tenant_id: TenantId, model_id: UUID) -> tuple[bytes, str]:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(MLModelArtifactModel).where(
                        MLModelArtifactModel.tenant_id == tenant_id,
                        MLModelArtifactModel.model_id == model_id,
                        MLModelArtifactModel.is_active.is_(True),
                    )
                )
            ).scalar_one_or_none()
            if row is None:
                raise ArtifactNotFoundError("artifact not found for tenant/model")
            blob = bytes(row.artifact_bytes)
            digest = hashlib.sha256(blob).hexdigest()
            if digest != row.sha256:
                raise ArtifactIntegrityError("SHA-256 mismatch on load")
            return blob, row.sha256
