from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ml_pipeline.domain.events.ml_events import (
    MLModelDeployed,
    MLModelDeprecated,
    MLModelDriftDetected,
    MLModelTrained,
    MLModelTrainingFailed,
    MLModelTrainingStarted,
)
from ml_pipeline.domain.exceptions.domain_exceptions import (
    InvalidModelTransition,
    TenantMismatch,
)
from ml_pipeline.domain.value_objects.enums import MLModelStatus

if TYPE_CHECKING:
    from datetime import datetime

    from ml_pipeline.domain.events.base import BaseDomainEvent
    from ml_pipeline.domain.value_objects.enums import MLAlgorithm, MLModelType
    from ml_pipeline.domain.value_objects.identifiers import MLModelId, TenantId


class MLModel:
    __slots__ = (
        "_events",
        "accuracy_metrics",
        "algorithm",
        "artifact_hash",
        "created_at",
        "dataset_id",
        "deployed_at",
        "deprecated_at",
        "failure_reason",
        "governance_history",
        "last_drift_check_at",
        "model_id",
        "model_type",
        "psi_score",
        "status",
        "tenant_id",
        "trained_at",
    )

    def __init__(
        self,
        model_id: MLModelId,
        tenant_id: TenantId,
        model_type: MLModelType,
        algorithm: MLAlgorithm,
        created_at: datetime,
        *,
        dataset_id: str | None = None,
        status: MLModelStatus = MLModelStatus.TRAINING,
        accuracy_metrics: dict[str, float] | None = None,
        artifact_hash: str | None = None,
        failure_reason: str | None = None,
        trained_at: datetime | None = None,
        deployed_at: datetime | None = None,
        deprecated_at: datetime | None = None,
        last_drift_check_at: datetime | None = None,
        psi_score: float | None = None,
        governance_history: list[dict[str, Any]] | None = None,
    ) -> None:
        self.model_id = model_id
        self.tenant_id = tenant_id
        self.model_type = model_type
        self.algorithm = algorithm
        self.created_at = created_at
        self.dataset_id = dataset_id
        self.status = status
        self.accuracy_metrics = accuracy_metrics or {}
        self.artifact_hash = artifact_hash
        self.failure_reason = failure_reason
        self.trained_at = trained_at
        self.deployed_at = deployed_at
        self.deprecated_at = deprecated_at
        self.last_drift_check_at = last_drift_check_at
        self.psi_score = psi_score
        self.governance_history = governance_history or []
        self._events: list[BaseDomainEvent] = []

    @classmethod
    def schedule_training(
        cls,
        model_id: MLModelId,
        tenant_id: TenantId,
        model_type: MLModelType,
        algorithm: MLAlgorithm,
        at: datetime,
        *,
        dataset_id: str | None = None,
    ) -> MLModel:
        obj = cls(model_id, tenant_id, model_type, algorithm, at, dataset_id=dataset_id)
        obj._events.append(
            MLModelTrainingStarted(
                str(tenant_id),
                str(model_id),
                model_type=model_type.value,
                algorithm=algorithm.value,
            )
        )
        obj.governance_history.append({"action": "training_scheduled", "at": at.isoformat()})
        return obj

    def mark_trained(
        self,
        tenant_id: TenantId,
        *,
        accuracy_metrics: dict[str, float],
        artifact_hash: str,
        at: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.status != MLModelStatus.TRAINING:
            raise InvalidModelTransition("only TRAINING can become TRAINED")
        self.status = MLModelStatus.TRAINED
        self.accuracy_metrics = accuracy_metrics
        self.artifact_hash = artifact_hash
        self.trained_at = at
        self.governance_history.append(
            {"action": "trained", "at": at.isoformat(), "metrics": accuracy_metrics}
        )
        self._events.append(
            MLModelTrained(
                str(tenant_id),
                str(self.model_id),
                artifact_ref=artifact_hash,
                accuracy_metrics=accuracy_metrics,
            )
        )

    def mark_failed(self, tenant_id: TenantId, *, reason: str, at: datetime) -> None:
        self._assert_tenant(tenant_id)
        self.status = MLModelStatus.FAILED
        self.failure_reason = reason
        self.governance_history.append({"action": "failed", "at": at.isoformat(), "reason": reason})
        self._events.append(
            MLModelTrainingFailed(str(tenant_id), str(self.model_id), error_reason=reason)
        )

    def promote(self, tenant_id: TenantId, *, deployed_by: str, at: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.status != MLModelStatus.TRAINED:
            raise InvalidModelTransition("only TRAINED can be promoted")
        self.status = MLModelStatus.DEPLOYED
        self.deployed_at = at
        self.governance_history.append(
            {"action": "promoted", "at": at.isoformat(), "by": deployed_by}
        )
        self._events.append(
            MLModelDeployed(str(tenant_id), str(self.model_id), deployed_by=deployed_by)
        )

    def deprecate(self, tenant_id: TenantId, *, deprecated_by: str, at: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.status not in {MLModelStatus.DEPLOYED, MLModelStatus.TRAINED}:
            raise InvalidModelTransition("cannot deprecate from current status")
        self.status = MLModelStatus.DEPRECATED
        self.deprecated_at = at
        self.governance_history.append(
            {"action": "deprecated", "at": at.isoformat(), "by": deprecated_by}
        )
        self._events.append(
            MLModelDeprecated(str(tenant_id), str(self.model_id), deprecated_by=deprecated_by)
        )

    def record_drift(
        self,
        tenant_id: TenantId,
        *,
        psi_score: float,
        threshold: float,
        at: datetime,
        auto_deprecate: bool,
    ) -> None:
        self._assert_tenant(tenant_id)
        self.psi_score = psi_score
        self.last_drift_check_at = at
        self.governance_history.append(
            {
                "action": "drift_detected",
                "at": at.isoformat(),
                "psi": psi_score,
                "auto_deprecate": auto_deprecate,
            }
        )
        self._events.append(
            MLModelDriftDetected(
                str(tenant_id),
                str(self.model_id),
                psi_score=psi_score,
                threshold=threshold,
                auto_deprecated=auto_deprecate,
            )
        )
        if auto_deprecate and self.status == MLModelStatus.DEPLOYED:
            self.deprecate(tenant_id, deprecated_by="drift_auto", at=at)

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch("tenant mismatch")

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._events)
        self._events.clear()
        return events
