"""CampaignProjection — tracks campaign states and lifecycle."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

from redforge.application.platform.projection_engine import (
    ProjectionEngine,
)
from redforge.application.platform.projections.base import ProjectionBase
from redforge.domain.platform.events import EventEnvelope
from redforge.domain.platform.read_models import CampaignReadModel


def _utc_now() -> datetime:
    return datetime.now(UTC)


class CampaignProjection(ProjectionBase):
    """Tracks total campaigns and their lifecycle states per organisation."""

    projection_name = "campaign"

    def __init__(self, repo: Any) -> None:
        self._repo = repo
        self._by_status: dict[str, dict[str, int]] = {}
        self._active_ids: dict[str, set[str]] = {}
        self._total: dict[str, int] = {}
        self._last_started: dict[str, datetime | None] = {}
        self._last_positions: dict[str, int] = {}

    def register_with(self, engine: ProjectionEngine) -> None:
        engine.register(self.projection_name, "campaign.CampaignCreated", self._handle_created)
        engine.register(self.projection_name, "campaign.CampaignStarted", self._handle_started)
        engine.register(self.projection_name, "campaign.CampaignCompleted", self._handle_completed)
        engine.register(self.projection_name, "campaign.CampaignCancelled", self._handle_cancelled)
        engine.register(self.projection_name, "campaign.CampaignPaused", self._handle_paused)

    def _init_org(self, org: str) -> None:
        if org not in self._by_status:
            self._by_status[org] = {}
            self._active_ids[org] = set()
            self._total[org] = 0
            self._last_started[org] = None

    async def _handle_created(self, envelope: EventEnvelope) -> None:
        org = envelope.organization_id
        self._init_org(org)
        self._total[org] += 1
        self._by_status[org]["created"] = self._by_status[org].get("created", 0) + 1
        self._last_positions[org] = envelope.global_position
        await self._persist(org)

    async def _handle_started(self, envelope: EventEnvelope) -> None:
        org = envelope.organization_id
        self._init_org(org)
        self._active_ids[org].add(envelope.aggregate_id)
        created = self._by_status[org].get("created", 0)
        if created > 0:
            self._by_status[org]["created"] = created - 1
        self._by_status[org]["running"] = self._by_status[org].get("running", 0) + 1
        self._last_started[org] = envelope.occurred_at
        self._last_positions[org] = envelope.global_position
        await self._persist(org)

    async def _handle_completed(self, envelope: EventEnvelope) -> None:
        org = envelope.organization_id
        self._init_org(org)
        self._active_ids[org].discard(envelope.aggregate_id)
        running = self._by_status[org].get("running", 0)
        if running > 0:
            self._by_status[org]["running"] = running - 1
        self._by_status[org]["completed"] = self._by_status[org].get("completed", 0) + 1
        self._last_positions[org] = envelope.global_position
        await self._persist(org)

    async def _handle_cancelled(self, envelope: EventEnvelope) -> None:
        org = envelope.organization_id
        self._init_org(org)
        self._active_ids[org].discard(envelope.aggregate_id)
        self._by_status[org]["cancelled"] = self._by_status[org].get("cancelled", 0) + 1
        self._last_positions[org] = envelope.global_position
        await self._persist(org)

    async def _handle_paused(self, envelope: EventEnvelope) -> None:
        org = envelope.organization_id
        self._init_org(org)
        self._by_status[org]["paused"] = self._by_status[org].get("paused", 0) + 1
        self._last_positions[org] = envelope.global_position
        await self._persist(org)

    async def _persist(self, org: str) -> None:
        model = CampaignReadModel(
            organization_id=org,
            total_campaigns=self._total.get(org, 0),
            campaigns_by_status=dict(self._by_status.get(org, {})),
            active_campaign_ids=tuple(sorted(self._active_ids.get(org, set()))),
            last_campaign_started_at=self._last_started.get(org),
            last_updated_at=_utc_now(),
            last_event_position=self._last_positions.get(org, 0),
        )
        await self._repo.save(model)

    async def get(self, organization_id: str) -> CampaignReadModel | None:
        return cast("CampaignReadModel | None", await self._repo.load("campaign", organization_id))

    async def flush_to_durable_repo(self, target_repo: Any, organization_id: str) -> None:
        model = await self._repo.load(self.projection_name, organization_id)
        if model is not None:
            await target_repo.save(model)
