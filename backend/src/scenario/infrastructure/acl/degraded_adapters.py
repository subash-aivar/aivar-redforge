"""Stub ACL adapters for scenario — testing without live M21/graph."""

from __future__ import annotations

from typing import TYPE_CHECKING

from scenario.domain.ports.i_security_graph_write_port import ISecurityGraphWritePort
from scenario.domain.ports.i_threat_intel_query_port import IThreatIntelQueryPort

if TYPE_CHECKING:
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
        self.nodes = [
            n for n in self.nodes if (n["tenant_id"], n["template_id"]) != key
        ]
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
