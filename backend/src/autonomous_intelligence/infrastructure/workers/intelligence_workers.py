from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from autonomous_intelligence.application.commands.intelligence_commands import (
    CreateIntelligenceSuggestion,
    MarkSuggestionApplied,
)
from autonomous_intelligence.domain.value_objects.identifiers import TenantId


class SuggestionGenerationWorker:
    def __init__(self, app: Any) -> None:
        self._app = app
        self.processed = 0

    async def handle_signal(
        self,
        tenant_id: UUID,
        target_type: str,
        target_context: str,
        confidence: float,
        roles: tuple[str, ...] = ("system",),
    ) -> Any:
        self.processed += 1
        return await self._app.create_suggestion(
            CreateIntelligenceSuggestion(
                tenant_id,
                target_context,
                None,
                target_type,
                {"change": "proposed"},
                "model-default",
                1,
                confidence,
                ("signal-1",),
                "Generated from inbound signal",
                roles,
            )
        )


class SuggestionExpiryWorker:
    def __init__(self, suggestions: Any) -> None:
        self._suggestions = suggestions
        self.expired = 0

    async def tick(self) -> int:
        now = datetime.now(UTC)
        stale = await self._suggestions.find_expired_pending(now)
        count = 0
        for s in stale:
            s.expire(s.tenant_id)
            await self._suggestions.save(s, s.tenant_id)
            count += 1
        self.expired += count
        return count


class SuggestionApplicationWorker:
    def __init__(self, app: Any) -> None:
        self._app = app
        self.applied = 0

    async def confirm(self, tenant_id: UUID, suggestion_id: UUID, target_context_ref: str) -> Any:
        self.applied += 1
        return await self._app.mark_applied(
            MarkSuggestionApplied(tenant_id, suggestion_id, target_context_ref, ("system",))
        )


class OutcomeMeasurementWorker:
    def __init__(self, outcomes: Any, models: Any) -> None:
        self._outcomes = outcomes
        self._models = models
        self.measured = 0

    async def tick(self, tenant_id: UUID) -> int:
        from autonomous_intelligence.domain.services.feedback_ingestion_service import (
            FeedbackIngestionService,
        )

        pending = await self._outcomes.find_pending_measurement(
            datetime.now(UTC), TenantId(tenant_id)
        )
        feedback = FeedbackIngestionService()
        count = 0
        for outcome in pending:
            outcome.record_measurement(outcome.baseline_metric - 0.05, datetime.now(UTC))
            await self._outcomes.update_measurement(outcome, TenantId(tenant_id))
            model = await self._models.find_deployed(TenantId(tenant_id), outcome.target_type)
            if model:
                feedback.ingest(model, outcome)
                await self._models.save(model, TenantId(tenant_id))
            count += 1
        self.measured += count
        return count


class ModelRetrainingWorker:
    def __init__(self, models: Any) -> None:
        self._models = models
        self.triggered = 0

    async def tick(self, tenant_id: UUID) -> int:
        from autonomous_intelligence.domain.value_objects.enums import SuggestionTargetType

        count = 0
        for tt in SuggestionTargetType:
            model = await self._models.find_deployed(TenantId(tenant_id), tt)
            if model and model.needs_retraining():
                self.triggered += 1
                count += 1
        return count


class M36SecurityGraphWorker:
    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, object]] = {}
        self.edges: set[tuple[str, str, str]] = set()

    def project(self, event: Any) -> None:
        name = type(event).__name__
        if name == "SuggestionCreated":
            self.nodes[event.suggestion_id] = {
                "type": "IntelligenceSuggestionNode",
                "status": "pending_review",
                "confidence_score": event.confidence_score,
                "tenant_id": event.tenant_id,
                "target_type": event.target_type,
            }
            target_id = getattr(event, "target_id", None) or event.target_type
            self.edges.add((event.suggestion_id, "SUGGESTED_MODIFICATION", str(target_id)))
        elif name == "SuggestionApproved":
            self.edges.add((event.suggestion_id, "APPROVED_SUGGESTION", event.target_type))
        elif name == "SuggestionOutcomeCaptured":
            model_ref = getattr(event, "target_type", "model")
            self.edges.add((event.suggestion_id, "OUTCOME_FEEDBACK", str(model_ref)))
        elif name == "ThreatHuntCandidatePromoted":
            self.edges.add(
                (
                    event.candidate_id,
                    "GENERATED_DETECTION",
                    str(event.promoted_rule_version_id),
                )
            )
        elif name == "ModelDeployed":
            nid = f"{event.model_id}_v{event.model_version}"
            self.nodes[nid] = {
                "type": "OptimizationModelNode",
                "status": "deployed",
                "tenant_id": event.tenant_id,
                "target_type": event.target_type,
            }


class M36AnalyticsProjector:
    def __init__(self) -> None:
        self.rows: list[dict[str, object]] = []

    def project(self, event: Any) -> None:
        self.rows.append(
            {
                "event_type": type(event).__name__,
                "tenant_id": getattr(event, "tenant_id", ""),
                "suggestion_id": getattr(event, "suggestion_id", ""),
            }
        )


class MetricsWorker:
    def __init__(self) -> None:
        self.ticks = 0
        self.counters: dict[str, float] = {}

    def tick(self) -> None:
        self.ticks += 1
        self.counters["m36.worker.ticks"] = float(self.ticks)


class IntelligenceScheduler:
    def __init__(
        self,
        expiry: SuggestionExpiryWorker,
        outcome: OutcomeMeasurementWorker,
        retrain: ModelRetrainingWorker,
        metrics: MetricsWorker,
    ) -> None:
        self.expiry = expiry
        self.outcome = outcome
        self.retrain = retrain
        self.metrics = metrics

    async def tick_all(self, tenant_id: UUID) -> dict[str, int]:
        expired = await self.expiry.tick()
        measured = await self.outcome.tick(tenant_id)
        retrained = await self.retrain.tick(tenant_id)
        self.metrics.tick()
        return {
            "expired": expired,
            "measured": measured,
            "retrain_triggers": retrained,
            "metrics_ticks": self.metrics.ticks,
        }
