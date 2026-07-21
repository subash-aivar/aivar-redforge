"""CampaignSummaryView projection — owned by campaign context.

Registered in ProjectionRegistry alongside evaluation projections.
"""

from __future__ import annotations

from typing import Any

from redforge.application.platform.projections.base import ProjectionBase
from redforge.domain.platform.events import EventEnvelope


class CampaignSummaryProjection(ProjectionBase):
    projection_name = "campaign.campaign_summary"

    def __init__(self, repo: Any = None) -> None:
        self._repo = repo
        self._docs: dict[str, dict[str, Any]] = {}

    def register_with(self, engine: Any) -> None:
        self._register(engine, "CampaignCreated", self.on_campaign_event)
        self._register(engine, "CampaignApproved", self.on_campaign_event)
        self._register(engine, "CampaignEvaluationCompleted", self.on_evaluation)

    async def on_campaign_event(self, envelope: EventEnvelope) -> None:
        payload = (
            envelope.payload
            if isinstance(envelope.payload, dict)
            else dict(vars(envelope.payload))
            if hasattr(envelope.payload, "__dict__")
            else {}
        )
        campaign_id = envelope.aggregate_id
        key = f"summary:{envelope.organization_id}:{campaign_id}"
        doc = self._docs.get(key) or {"campaign_id": campaign_id}
        doc.update(
            {
                "state": payload.get("state") or doc.get("state"),
                "name": payload.get("name") or doc.get("name"),
                "kind": payload.get("kind") or doc.get("kind"),
            }
        )
        self._docs[key] = doc
        if self._repo is not None:
            await self._repo.upsert(
                organization_id=envelope.organization_id,
                projection_name=self.projection_name,
                document_key=key,
                document=doc,
            )

    async def on_evaluation(self, envelope: EventEnvelope) -> None:
        payload = (
            envelope.payload
            if isinstance(envelope.payload, dict)
            else dict(vars(envelope.payload))
            if hasattr(envelope.payload, "__dict__")
            else {}
        )
        instance_id = payload.get("campaign_instance_id")
        if not instance_id:
            return
        key = f"summary_instance:{envelope.organization_id}:{instance_id}"
        doc = {
            "campaign_instance_id": instance_id,
            "composite_outcome": payload.get("composite_outcome"),
            "detection_coverage_percent": payload.get("detection_coverage_percent"),
        }
        self._docs[key] = doc
        if self._repo is not None:
            await self._repo.upsert(
                organization_id=envelope.organization_id,
                projection_name=self.projection_name,
                document_key=key,
                document=doc,
            )


def register_campaign_summary_projection(registry: Any, repo: Any = None) -> None:
    registry.register(CampaignSummaryProjection(repo))
