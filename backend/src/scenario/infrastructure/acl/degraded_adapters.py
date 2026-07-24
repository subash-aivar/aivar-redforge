"""Stub ACL adapters for scenario — testing without live M21/graph/campaign."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import uuid4

from scenario.domain.ports.i_campaign_draft_port import ICampaignDraftPort
from scenario.domain.ports.i_security_graph_write_port import ISecurityGraphWritePort
from scenario.domain.ports.i_threat_intel_query_port import IThreatIntelQueryPort

if TYPE_CHECKING:
    from uuid import UUID

    from scenario.domain.value_objects.identifiers import TenantId
    from scenario.domain.value_objects.scenario_vos import ThreatActorRef


class StubThreatIntelAdapter(IThreatIntelQueryPort):
    def __init__(
        self,
        actors: dict[str, ThreatActorRef] | None = None,
    ) -> None:
        self._actors = dict(actors or {})

    async def resolve_threat_actor(
        self,
        threat_actor_id: str,
        tenant_id: TenantId,
    ) -> ThreatActorRef | None:
        return self._actors.get(threat_actor_id)


class StubScenarioGraphWriteAdapter(ISecurityGraphWritePort):
    def __init__(self) -> None:
        self.nodes: list[dict[str, object]] = []
        self.threat_actor_edges: list[dict[str, object]] = []
        self.based_on_scenario_edges: list[dict[str, object]] = []

    async def upsert_scenario_template_node(
        self,
        tenant_id: str,
        template_id: str,
        scenario_key: str,
        version: str,
        state: str,
        technique_count: int,
    ) -> None:
        key = (tenant_id, template_id)
        self.nodes = [n for n in self.nodes if (n["tenant_id"], n["template_id"]) != key]
        self.nodes.append(
            {
                "tenant_id": tenant_id,
                "template_id": template_id,
                "scenario_key": scenario_key,
                "version": version,
                "state": state,
                "technique_count": technique_count,
            }
        )

    async def upsert_emulates_threat_actor_edge(
        self,
        tenant_id: str,
        template_id: str,
        threat_actor_id: str,
        confidence: float = 1.0,
    ) -> None:
        key = (tenant_id, template_id, threat_actor_id)
        self.threat_actor_edges = [
            e
            for e in self.threat_actor_edges
            if (
                e["tenant_id"],
                e["template_id"],
                e["threat_actor_id"],
            )
            != key
        ]
        self.threat_actor_edges.append(
            {
                "tenant_id": tenant_id,
                "template_id": template_id,
                "threat_actor_id": threat_actor_id,
                "confidence": confidence,
            }
        )

    async def upsert_based_on_scenario_edge(
        self,
        tenant_id: str,
        campaign_id: str,
        template_id: str,
    ) -> None:
        key = (tenant_id, campaign_id, template_id)
        self.based_on_scenario_edges = [
            e
            for e in self.based_on_scenario_edges
            if (e["tenant_id"], e["campaign_id"], e["template_id"]) != key
        ]
        self.based_on_scenario_edges.append(
            {
                "tenant_id": tenant_id,
                "campaign_id": campaign_id,
                "template_id": template_id,
            }
        )


class StubCampaignDraftPort(ICampaignDraftPort):
    """Validates Phase 1 draft gates; optionally records synthetic campaign ids."""

    def __init__(self) -> None:
        self.validated_specs: list[dict[str, Any]] = []
        self.created_campaigns: list[dict[str, Any]] = []

    async def validate_draft_spec(
        self,
        *,
        tenant_id: TenantId,
        draft_spec: dict[str, Any],
    ) -> list[str]:
        errors: list[str] = []
        name = draft_spec.get("name")
        if not isinstance(name, str) or not name.strip():
            errors.append("name is required")
        safety = draft_spec.get("safety_policy")
        if not isinstance(safety, dict):
            errors.append("safety_policy is required")
        else:
            max_actions = safety.get("max_concurrent_actions")
            if not isinstance(max_actions, int) or max_actions < 1:
                errors.append("safety_policy.max_concurrent_actions must be >= 1")
            ceiling = safety.get("blast_radius_ceiling")
            if not isinstance(ceiling, str) or not ceiling.strip():
                errors.append("safety_policy.blast_radius_ceiling is required")
        objectives = draft_spec.get("objectives")
        if not isinstance(objectives, list):
            errors.append("objectives must be a list")
        elif not objectives:
            errors.append("at least one objective is required")
        else:
            for idx, obj in enumerate(objectives):
                if not isinstance(obj, dict):
                    errors.append(f"objectives[{idx}] must be an object")
                    continue
                if not obj.get("objective_type"):
                    errors.append(f"objectives[{idx}].objective_type is required")
                if not obj.get("condition_type"):
                    errors.append(f"objectives[{idx}].condition_type is required")
        if not draft_spec.get("scenario_template_id"):
            errors.append("scenario_template_id is required")
        self.validated_specs.append({"tenant_id": str(tenant_id), "draft_spec": draft_spec})
        return errors

    async def create_draft_campaign(
        self,
        *,
        tenant_id: TenantId,
        engagement_id: UUID,
        owner_id: str,
        draft_spec: dict[str, Any],
        scenario_template_id: str,
    ) -> UUID:
        errors = await self.validate_draft_spec(tenant_id=tenant_id, draft_spec=draft_spec)
        if errors:
            raise ValueError("; ".join(errors))
        campaign_id = uuid4()
        self.created_campaigns.append(
            {
                "campaign_id": str(campaign_id),
                "tenant_id": str(tenant_id),
                "engagement_id": str(engagement_id),
                "owner_id": owner_id,
                "scenario_template_id": scenario_template_id,
                "draft_spec": draft_spec,
            }
        )
        return campaign_id
