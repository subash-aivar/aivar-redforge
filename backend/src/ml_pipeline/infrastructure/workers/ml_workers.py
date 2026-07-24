from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from ml_pipeline.application.commands.ml_commands import ScheduleMLModelTrainingCommand
from ml_pipeline.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from uuid import UUID

    from ml_pipeline.application.services.ml_application_service import (
        MLApplicationService,
    )


class MLTrainingWorker:
    def __init__(self, app: MLApplicationService) -> None:
        self._app = app
        self._seen_jobs: set[str] = set()

    async def run(
        self,
        *,
        job_id: str,
        tenant_id: TenantId,
        model_type: str,
        dataset_id: str | None = None,
        training_rows: tuple[dict[str, object], ...] = (),
    ) -> dict[str, Any]:
        if job_id in self._seen_jobs:
            return {"deduplicated": True, "job_id": job_id}
        self._seen_jobs.add(job_id)
        result = await self._app.schedule_training(
            ScheduleMLModelTrainingCommand(
                tenant_id=tenant_id,
                model_type=model_type,
                dataset_id=dataset_id,
                actor_roles=("analytics:admin",),
                training_rows=training_rows,
            )
        )
        result["job_id"] = job_id
        result["deduplicated"] = False
        return result


class MLInferenceWorker:
    def __init__(self, app: MLApplicationService) -> None:
        self._app = app

    async def run(
        self,
        *,
        tenant_id: TenantId,
        model_type: str,
        assets: list[dict[str, Any]],
    ) -> dict[str, Any]:
        return await self._app.run_inference(tenant_id, model_type, assets, ("analytics:analyst",))


class DriftCheckWorker:
    def __init__(self, app: MLApplicationService) -> None:
        self._app = app

    async def run_for_model(
        self, tenant_id: TenantId, model_id: UUID, actual: list[float]
    ) -> dict[str, Any]:
        return await self._app.check_drift(tenant_id, model_id, actual)

    async def weekly_tick(self) -> dict[str, Any]:
        return {"checked_before": (datetime.now(UTC) - timedelta(days=7)).isoformat()}
