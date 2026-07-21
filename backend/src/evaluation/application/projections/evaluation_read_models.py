"""Evaluation read-model projections for ProjectionRegistry.

Read models:
- DetectionCoverageTrendView
- TechniqueSuccessRateView
- KillChainProgressionView
- ObjectiveHistoryView

Rebuildable from CampaignEvaluationCompleted / MetricsSnapshotCreated /
DetectionCoverageComputed / ObjectiveAssessmentCompleted events.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from redforge.application.platform.projections.base import ProjectionBase

if TYPE_CHECKING:
    from redforge.domain.platform.events import EventEnvelope


def _payload_as_dict(payload: object) -> dict[str, Any]:
    if isinstance(payload, dict):
        return payload
    if hasattr(payload, "__dict__"):
        return dict(vars(payload))
    return {}


class _InMemoryStore:
    def __init__(self) -> None:
        self.docs: dict[str, dict[str, Any]] = {}

    def upsert(self, key: str, doc: dict[str, Any]) -> None:
        self.docs[key] = doc

    def get(self, key: str) -> dict[str, Any] | None:
        return self.docs.get(key)


class DetectionCoverageTrendProjection(ProjectionBase):
    projection_name = "evaluation.detection_coverage_trend"

    def __init__(self, repo: Any = None) -> None:
        self._repo = repo
        self._store = _InMemoryStore()

    def register_with(self, engine: Any) -> None:
        self._register(engine, "MetricsSnapshotCreated", self.on_snapshot)
        self._register(engine, "CampaignEvaluationCompleted", self.on_evaluation_completed)

    async def on_snapshot(self, envelope: EventEnvelope) -> None:
        payload = _payload_as_dict(envelope.payload)
        campaign_id = str(payload.get("campaign_id", envelope.aggregate_id))
        key = f"trend:{envelope.organization_id}:{campaign_id}"
        existing = self._store.get(key) or {
            "campaign_id": campaign_id,
            "runs": [],
        }
        runs = list(existing["runs"])
        runs.append(
            {
                "run_number": payload.get("run_number"),
                "detection_coverage_percent": payload.get("detection_coverage_percent"),
                "technique_success_rate": payload.get("technique_success_rate"),
                "composite_outcome": payload.get("composite_outcome"),
            }
        )
        runs.sort(key=lambda r: r.get("run_number") or 0)
        direction = _trend_direction(
            [float(r["detection_coverage_percent"] or 0) for r in runs]
        )
        doc = {
            "campaign_id": campaign_id,
            "runs": runs,
            "trend_direction": direction,
            "latest_coverage": (
                runs[-1]["detection_coverage_percent"] if runs else 0.0
            ),
        }
        self._store.upsert(key, doc)
        if self._repo is not None:
            await self._repo.upsert(
                organization_id=envelope.organization_id,
                projection_name=self.projection_name,
                document_key=key,
                document=doc,
            )

    async def on_evaluation_completed(self, envelope: EventEnvelope) -> None:
        # MetricsSnapshotCreated is the primary trend source
        return


class TechniqueSuccessRateProjection(ProjectionBase):
    projection_name = "evaluation.technique_success_rate"

    def __init__(self, repo: Any = None) -> None:
        self._repo = repo
        self._store = _InMemoryStore()

    def register_with(self, engine: Any) -> None:
        self._register(engine, "MetricsSnapshotCreated", self.on_snapshot)

    async def on_snapshot(self, envelope: EventEnvelope) -> None:
        payload = _payload_as_dict(envelope.payload)
        campaign_id = str(payload.get("campaign_id", envelope.aggregate_id))
        key = f"technique_rate:{envelope.organization_id}:{campaign_id}"
        existing = self._store.get(key) or {"campaign_id": campaign_id, "rates": []}
        rates = list(existing["rates"])
        rates.append(
            {
                "run_number": payload.get("run_number"),
                "technique_success_rate": payload.get("technique_success_rate"),
            }
        )
        doc = {"campaign_id": campaign_id, "rates": rates}
        self._store.upsert(key, doc)
        if self._repo is not None:
            await self._repo.upsert(
                organization_id=envelope.organization_id,
                projection_name=self.projection_name,
                document_key=key,
                document=doc,
            )


class KillChainProgressionProjection(ProjectionBase):
    projection_name = "evaluation.kill_chain_progression"

    def __init__(self, repo: Any = None) -> None:
        self._repo = repo
        self._store = _InMemoryStore()

    def register_with(self, engine: Any) -> None:
        self._register(engine, "CampaignEvaluationCompleted", self.on_completed)

    async def on_completed(self, envelope: EventEnvelope) -> None:
        payload = _payload_as_dict(envelope.payload)
        instance_id = str(payload.get("campaign_instance_id", envelope.aggregate_id))
        key = f"killchain:{envelope.organization_id}:{instance_id}"
        doc = {
            "campaign_instance_id": instance_id,
            "composite_outcome": payload.get("composite_outcome"),
            "objectives_achieved": payload.get("objectives_achieved"),
            "objectives_failed": payload.get("objectives_failed"),
        }
        self._store.upsert(key, doc)
        if self._repo is not None:
            await self._repo.upsert(
                organization_id=envelope.organization_id,
                projection_name=self.projection_name,
                document_key=key,
                document=doc,
            )


class ObjectiveHistoryProjection(ProjectionBase):
    projection_name = "evaluation.objective_history"

    def __init__(self, repo: Any = None) -> None:
        self._repo = repo
        self._store = _InMemoryStore()

    def register_with(self, engine: Any) -> None:
        self._register(engine, "ObjectiveAssessmentCompleted", self.on_assessment)

    async def on_assessment(self, envelope: EventEnvelope) -> None:
        payload = _payload_as_dict(envelope.payload)
        objective_id = str(payload.get("objective_id", ""))
        key = (
            f"objective:{envelope.organization_id}:"
            f"{envelope.aggregate_id}:{objective_id}"
        )
        doc = {
            "evaluation_id": envelope.aggregate_id,
            "objective_id": objective_id,
            "objective_type": payload.get("objective_type"),
            "outcome": payload.get("outcome"),
            "evidence_count": payload.get("evidence_count"),
        }
        self._store.upsert(key, doc)
        if self._repo is not None:
            await self._repo.upsert(
                organization_id=envelope.organization_id,
                projection_name=self.projection_name,
                document_key=key,
                document=doc,
            )


def register_evaluation_projections(registry: Any, repo: Any = None) -> None:
    """Register all evaluation read-model projections with ProjectionRegistry."""
    registry.register(DetectionCoverageTrendProjection(repo))
    registry.register(TechniqueSuccessRateProjection(repo))
    registry.register(KillChainProgressionProjection(repo))
    registry.register(ObjectiveHistoryProjection(repo))


def _trend_direction(values: list[float]) -> str:
    if len(values) < 2:
        return "same"
    window = values[-3:] if len(values) >= 3 else values
    net = window[-1] - window[0]
    if net > 0:
        return "better"
    if net < 0:
        return "worse"
    return "same"
