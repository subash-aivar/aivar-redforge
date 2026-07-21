"""ISecurityGraphWritePort — outbound port for Security Graph scenario ontology writes."""

from __future__ import annotations

from abc import ABC, abstractmethod


class ISecurityGraphWritePort(ABC):
    """Write scenario template ontology to the Security Graph.

    All writes are idempotent under event replay (graph nodes are upserted).
    """

    @abstractmethod
    async def upsert_scenario_template_node(
        self,
        tenant_id: str,
        template_id: str,
        scenario_key: str,
        version: str,
        state: str,
        technique_count: int,
    ) -> None:
        """Create or update a ScenarioTemplateNode in the Security Graph."""

    @abstractmethod
    async def upsert_emulates_threat_actor_edge(
        self,
        tenant_id: str,
        template_id: str,
        threat_actor_id: str,
        confidence: float = 1.0,
    ) -> None:
        """Create or update EMULATES_THREAT_ACTOR edge to ThreatActorNode (M21)."""
