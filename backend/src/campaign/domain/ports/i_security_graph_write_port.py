"""ISecurityGraphWritePort — campaign ontology writes (freeze §15)."""

from __future__ import annotations

from abc import ABC, abstractmethod


class ISecurityGraphWritePort(ABC):
    """Idempotent Security Graph upserts for campaign / instance / task graph nodes."""

    @abstractmethod
    async def upsert_campaign_node(
        self,
        *,
        tenant_id: str,
        campaign_id: str,
        classification: str,
        kind: str,
        state: str,
    ) -> None: ...

    @abstractmethod
    async def upsert_campaign_instance_node(
        self,
        *,
        tenant_id: str,
        instance_id: str,
        campaign_id: str,
        run_number: int,
        composite_outcome: str | None = None,
    ) -> None: ...

    @abstractmethod
    async def upsert_instance_of_campaign_edge(
        self,
        *,
        tenant_id: str,
        instance_id: str,
        campaign_id: str,
        run_number: int,
    ) -> None: ...

    @abstractmethod
    async def upsert_task_graph_node(
        self,
        *,
        tenant_id: str,
        graph_id: str,
        version: str,
    ) -> None: ...

    @abstractmethod
    async def upsert_uses_graph_edge(
        self,
        *,
        tenant_id: str,
        campaign_id: str,
        graph_id: str,
        version: str,
    ) -> None: ...

    @abstractmethod
    async def upsert_campaign_task_node(
        self,
        *,
        tenant_id: str,
        task_id: str,
        task_type: str,
        criticality: str,
    ) -> None: ...

    @abstractmethod
    async def upsert_graph_contains_edge(
        self,
        *,
        tenant_id: str,
        graph_id: str,
        task_id: str,
        sequence: int,
    ) -> None: ...

    @abstractmethod
    async def upsert_task_depends_on_edge(
        self,
        *,
        tenant_id: str,
        from_task_id: str,
        to_task_id: str,
        predicate: str,
    ) -> None: ...

    @abstractmethod
    async def upsert_based_on_scenario_edge(
        self,
        *,
        tenant_id: str,
        campaign_id: str,
        template_id: str,
    ) -> None: ...
