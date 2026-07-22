"""PostgreSQL repositories for posture_forecasting.

Each repository opens one session per call from an injected
async_sessionmaker, matching the incident/remediation_impact pattern:
ForecastApplicationService is constructed once with concrete repository
instances (see infrastructure/container.py), not through a per-request
unit-of-work.

save() is idempotent on forecast_id (upsert), not append-only — the
accuracy worker re-fetches a forecast via find_pending_accuracy_check,
mutates it in place (appending an accuracy record), and calls save() again
for the same forecast_id. Accuracy records are replaced wholesale on every
save (delete + reinsert), same as incident's timeline entries — the
in-memory forecast.accuracy_records list is always the full, current set.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import delete, select

from posture_forecasting.domain.aggregates.forecast_configuration import ForecastConfiguration
from posture_forecasting.domain.aggregates.posture_forecast import PostureForecast
from posture_forecasting.domain.repositories.i_repositories import (
    IForecastConfigurationRepository,
    IPostureForecastRepository,
)
from posture_forecasting.domain.value_objects.identifiers import ForecastId, TenantId
from posture_forecasting.domain.value_objects.snapshots import (
    ForecastAccuracyRecord,
    ForecastInputSnapshot,
)
from posture_forecasting.infrastructure.persistence.models import (
    ForecastAccuracyRecordModel,
    ForecastConfigurationModel,
    ForecastInputSnapshotModel,
    PostureForecastModel,
)

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


def _forecast_to_row(forecast: PostureForecast) -> PostureForecastModel:
    return PostureForecastModel(
        id=forecast.forecast_id.value,
        tenant_id=forecast.tenant_id.value,
        predicted_30d=forecast.predicted_30d,
        predicted_60d=forecast.predicted_60d,
        predicted_90d=forecast.predicted_90d,
        model_id=forecast.model_id,
        model_version=forecast.model_version,
        generated_at=forecast.generated_at,
    )


def _snapshot_to_row(forecast: PostureForecast) -> ForecastInputSnapshotModel:
    snap = forecast.input_snapshot
    return ForecastInputSnapshotModel(
        id=uuid4(),
        forecast_id=forecast.forecast_id.value,
        tenant_id=forecast.tenant_id.value,
        baseline_exposure_score=snap.baseline_exposure_score,
        remediation_velocity_per_day=snap.remediation_velocity_per_day,
        open_critical_count=snap.open_critical_count,
        open_high_count=snap.open_high_count,
        snapshot_at=snap.snapshot_at,
    )


def _row_to_snapshot(row: ForecastInputSnapshotModel, tenant_id: TenantId) -> ForecastInputSnapshot:
    return ForecastInputSnapshot(
        baseline_exposure_score=row.baseline_exposure_score,
        remediation_velocity_per_day=row.remediation_velocity_per_day,
        open_critical_count=row.open_critical_count,
        open_high_count=row.open_high_count,
        snapshot_at=row.snapshot_at,
        tenant_id=tenant_id,
    )


def _row_to_forecast(
    row: PostureForecastModel,
    snapshot: ForecastInputSnapshot,
    accuracy_records: list[ForecastAccuracyRecord],
) -> PostureForecast:
    return PostureForecast(
        forecast_id=ForecastId(row.id),
        tenant_id=TenantId(row.tenant_id),
        input_snapshot=snapshot,
        predicted_30d=row.predicted_30d,
        predicted_60d=row.predicted_60d,
        predicted_90d=row.predicted_90d,
        model_id=row.model_id,
        model_version=row.model_version,
        generated_at=row.generated_at,
        accuracy_records=accuracy_records,
    )


class PgPostureForecastRepository(IPostureForecastRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def _load(
        self, session: AsyncSession, row: PostureForecastModel
    ) -> PostureForecast:
        tenant_id = TenantId(row.tenant_id)
        snapshot_row = (
            await session.execute(
                select(ForecastInputSnapshotModel).where(
                    ForecastInputSnapshotModel.forecast_id == row.id
                )
            )
        ).scalar_one()
        snapshot = _row_to_snapshot(snapshot_row, tenant_id)

        accuracy_rows = (
            await session.execute(
                select(ForecastAccuracyRecordModel)
                .where(ForecastAccuracyRecordModel.forecast_id == row.id)
                .order_by(ForecastAccuracyRecordModel.recorded_at)
            )
        ).scalars().all()
        accuracy_records = [
            ForecastAccuracyRecord(
                horizon_days=a.horizon_days,
                actual_score=a.actual_score,
                predicted_score=a.predicted_score,
                absolute_error=a.absolute_error,
                recorded_at=a.recorded_at,
            )
            for a in accuracy_rows
        ]
        return _row_to_forecast(row, snapshot, accuracy_records)

    async def save(self, forecast: PostureForecast, tenant_id: TenantId) -> None:
        async with self._session_factory() as session:
            existing = (
                await session.execute(
                    select(PostureForecastModel.id).where(
                        PostureForecastModel.id == forecast.forecast_id.value
                    )
                )
            ).scalar_one_or_none()

            row = _forecast_to_row(forecast)
            if existing is None:
                session.add(row)
                session.add(_snapshot_to_row(forecast))
            else:
                await session.merge(row)

            await session.execute(
                delete(ForecastAccuracyRecordModel).where(
                    ForecastAccuracyRecordModel.forecast_id == forecast.forecast_id.value
                )
            )
            for record in forecast.accuracy_records:
                session.add(
                    ForecastAccuracyRecordModel(
                        id=uuid4(),
                        forecast_id=forecast.forecast_id.value,
                        tenant_id=tenant_id.value,
                        horizon_days=record.horizon_days,
                        actual_score=record.actual_score,
                        predicted_score=record.predicted_score,
                        absolute_error=record.absolute_error,
                        recorded_at=record.recorded_at,
                    )
                )
            await session.commit()

    async def find_latest(self, tenant_id: TenantId) -> PostureForecast | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(PostureForecastModel)
                    .where(PostureForecastModel.tenant_id == tenant_id.value)
                    .order_by(PostureForecastModel.generated_at.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            return await self._load(session, row) if row is not None else None

    async def find_pending_accuracy_check(
        self, horizon_days: int, cutoff: datetime
    ) -> list[PostureForecast]:
        from datetime import timedelta

        threshold = cutoff - timedelta(days=horizon_days)
        async with self._session_factory() as session:
            candidate_rows = (
                await session.execute(
                    select(PostureForecastModel).where(
                        PostureForecastModel.generated_at <= threshold
                    )
                )
            ).scalars().all()
            out: list[PostureForecast] = []
            for row in candidate_rows:
                already_checked = (
                    await session.execute(
                        select(ForecastAccuracyRecordModel.id).where(
                            ForecastAccuracyRecordModel.forecast_id == row.id,
                            ForecastAccuracyRecordModel.horizon_days == horizon_days,
                        )
                    )
                ).scalar_one_or_none()
                if already_checked is None:
                    out.append(await self._load(session, row))
            return out


class PgForecastConfigurationRepository(IForecastConfigurationRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def get_or_create_default(self, tenant_id: TenantId) -> ForecastConfiguration:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(ForecastConfigurationModel).where(
                        ForecastConfigurationModel.tenant_id == tenant_id.value
                    )
                )
            ).scalar_one_or_none()
            if row is not None:
                return ForecastConfiguration(
                    tenant_id=tenant_id,
                    forecast_frequency_hours=row.forecast_frequency_hours,
                    signal_weights=dict(row.signal_weights),
                )

            config = ForecastConfiguration.default(tenant_id)
            session.add(
                ForecastConfigurationModel(
                    tenant_id=tenant_id.value,
                    forecast_frequency_hours=config.forecast_frequency_hours,
                    signal_weights=dict(config.signal_weights),
                )
            )
            await session.commit()
            return config
