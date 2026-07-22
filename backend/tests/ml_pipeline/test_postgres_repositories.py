"""Integration tests for ml_pipeline's Postgres repositories and artifact store."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid7

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from ml_pipeline.domain.aggregates.ml_model import MLModel
from ml_pipeline.domain.aggregates.predictive_risk_signal import PredictiveRiskSignal
from ml_pipeline.domain.exceptions.domain_exceptions import (
    ArtifactIntegrityError,
    ArtifactNotFoundError,
)
from ml_pipeline.domain.value_objects.enums import MLAlgorithm, MLModelType
from ml_pipeline.domain.value_objects.identifiers import (
    MLModelId,
    PredictiveRiskSignalId,
    TenantId,
)
from ml_pipeline.infrastructure.persistence.postgres_repositories import (
    PgMLModelArtifactStore,
    PgMLModelRepository,
    PgPredictiveRiskSignalRepository,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.environ.get("TEST_DATABASE_URL"), reason="requires TEST_DATABASE_URL"
    ),
]

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://redforge:redforge@localhost:5432/redforge_test",
)


@pytest.fixture
def session_factory() -> async_sessionmaker[AsyncSession]:
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.mark.asyncio
async def test_model_lifecycle_round_trip(session_factory) -> None:
    repo = PgMLModelRepository(session_factory)
    tenant_id = TenantId(uuid7())
    now = datetime.now(UTC)

    model = MLModel.schedule_training(
        MLModelId.generate(), tenant_id, MLModelType.RISK_PREDICTOR, MLAlgorithm.RANDOM_FOREST, now
    )
    await repo.save(tenant_id, model)

    fetched = await repo.find_by_id(tenant_id, model.model_id)
    assert fetched is not None
    assert fetched.status.value == "TRAINING"
    assert fetched.governance_history == model.governance_history

    model.mark_trained(tenant_id, accuracy_metrics={"auc_roc": 0.82}, artifact_hash="abc123", at=now)
    model.promote(tenant_id, deployed_by="engineer-1", at=now)
    await repo.save(tenant_id, model)

    deployed = await repo.find_deployed_by_type(tenant_id, MLModelType.RISK_PREDICTOR)
    assert deployed is not None
    assert str(deployed.model_id) == str(model.model_id)
    assert len(deployed.governance_history) == 3  # scheduled, trained, promoted

    listed = await repo.list_for_tenant(tenant_id, status=deployed.status)
    assert len(listed) == 1

    stale_cutoff = now + timedelta(days=1)
    pending_drift = await repo.find_models_for_drift_check(stale_cutoff)
    assert any(str(m.model_id) == str(model.model_id) for m in pending_drift)


@pytest.mark.asyncio
async def test_predictive_risk_signals_active_filtering(session_factory) -> None:
    repo = PgPredictiveRiskSignalRepository(session_factory)
    tenant_id = TenantId(uuid7())
    model_id = MLModelId.generate()
    asset_ref_id = uuid7()
    now = datetime.now(UTC)

    active = PredictiveRiskSignal(
        PredictiveRiskSignalId.generate(),
        tenant_id,
        model_id,
        asset_ref_id,
        "beaconing_risk",
        0.7,
        0.9,
        now,
        now + timedelta(days=1),
        {"feature_a": 1.0},
    )
    expired = PredictiveRiskSignal(
        PredictiveRiskSignalId.generate(),
        tenant_id,
        model_id,
        asset_ref_id,
        "beaconing_risk",
        0.5,
        0.6,
        now - timedelta(days=2),
        now - timedelta(days=1),
        {},
    )
    await repo.save_many(tenant_id, [active, expired])

    by_asset = await repo.find_by_asset(tenant_id, asset_ref_id, now=now)
    assert len(by_asset) == 1
    assert str(by_asset[0].signal_id) == str(active.signal_id)

    by_type = await repo.find_active_by_type(tenant_id, "beaconing_risk", now=now)
    assert len(by_type) == 1


@pytest.mark.asyncio
async def test_artifact_store_overwrite_and_integrity(session_factory) -> None:
    store = PgMLModelArtifactStore(session_factory)
    tenant_id = uuid7()
    model_id = uuid7()

    digest1 = await store.store_artifact(tenant_id, model_id, b"model-bytes-v1")
    blob1, hash1 = await store.load_artifact(tenant_id, model_id)
    assert blob1 == b"model-bytes-v1"
    assert hash1 == digest1

    digest2 = await store.store_artifact(tenant_id, model_id, b"model-bytes-v2-longer")
    blob2, hash2 = await store.load_artifact(tenant_id, model_id)
    assert blob2 == b"model-bytes-v2-longer"
    assert hash2 == digest2
    assert digest1 != digest2


@pytest.mark.asyncio
async def test_artifact_store_missing_raises(session_factory) -> None:
    store = PgMLModelArtifactStore(session_factory)
    with pytest.raises(ArtifactNotFoundError):
        await store.load_artifact(uuid7(), uuid7())


@pytest.mark.asyncio
async def test_artifact_store_integrity_violation_raises(session_factory) -> None:
    from sqlalchemy import update

    from ml_pipeline.infrastructure.persistence.models.orm_models import MLModelArtifactModel

    store = PgMLModelArtifactStore(session_factory)
    tenant_id = uuid7()
    model_id = uuid7()
    await store.store_artifact(tenant_id, model_id, b"original-bytes")

    async with session_factory() as session:
        await session.execute(
            update(MLModelArtifactModel)
            .where(
                MLModelArtifactModel.tenant_id == tenant_id,
                MLModelArtifactModel.model_id == model_id,
            )
            .values(artifact_bytes=b"tampered-bytes")
        )
        await session.commit()

    with pytest.raises(ArtifactIntegrityError):
        await store.load_artifact(tenant_id, model_id)
