"""ACL degraded adapters for campaign — stub implementations for testing without M29/M22."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from campaign.domain.ports.i_engagement_query_port import (
    EngagementStatus,
    IEngagementQueryPort,
)
from campaign.domain.ports.i_inventory_query_port import IInventoryQueryPort
from campaign.domain.ports.i_scheduler_port import ISchedulerPort
from campaign.domain.ports.i_security_graph_write_port import ISecurityGraphWritePort
from campaign.domain.value_objects.campaign_vos import RecurrencePolicy, TargetRef
from campaign.domain.value_objects.identifiers import TenantId


class AlwaysActiveEngagementAdapter(IEngagementQueryPort):
    """Stub engagement adapter that returns a fake Active+Armed status.

    Used for integration testing and local development without a live M29 instance.
    Never use in production.
    """

    async def get_engagement_status(
        self,
        engagement_id: UUID,
        tenant_id: TenantId,
    ) -> EngagementStatus:
        return EngagementStatus(
            engagement_id=engagement_id,
            state="Active",
            kill_switch_state="Armed",
            allowed_target_ids=None,  # None = no scope restriction
        )


class StubInventoryQueryAdapter(IInventoryQueryPort):
    """Stub inventory adapter that returns synthetic TargetRef objects.

    Generates deterministic stub targets from the provided rules.
    Used for integration testing and local development without a live M22 instance.
    Never use in production.
    """

    async def resolve_targets(
        self,
        rules: list[dict[str, str]],
        tenant_id: TenantId,
    ) -> list[TargetRef]:
        stub_id = UUID("00000000-0000-0000-0000-000000000001")
        return [
            TargetRef(
                asset_id=stub_id,
                asset_type="host",
            )
        ]


class StubSchedulerPort(ISchedulerPort):
    """Stub scheduler port for testing. Records registered/cancelled jobs."""

    def __init__(self) -> None:
        self.registered: list[dict[str, str]] = []
        self.cancelled: list[str] = []

    async def register_schedule(
        self,
        campaign_id: object,
        tenant_id: object,
        policy: RecurrencePolicy,
    ) -> str:
        job_id = f"stub-job-{campaign_id}"
        self.registered.append({"campaign_id": str(campaign_id), "job_id": job_id})
        return job_id

    async def cancel_schedule(
        self,
        campaign_id: object,
        tenant_id: object,
        job_id: str,
    ) -> None:
        self.cancelled.append(job_id)

    async def get_next_fire_time(
        self,
        cron_expression: str,
        after: datetime,
    ) -> datetime:
        from croniter import croniter

        it = croniter(cron_expression, after)
        result: datetime = it.get_next(datetime)
        return result

    async def list_active_schedules(self, tenant_id: object) -> list[dict[str, str]]:
        return [r for r in self.registered if r["job_id"] not in self.cancelled]

    async def register_one_shot(
        self,
        campaign_id: object,
        tenant_id: object,
        fire_at: datetime,
    ) -> str:
        job_id = f"stub-oneshot-{campaign_id}"
        self.registered.append(
            {
                "campaign_id": str(campaign_id),
                "job_id": job_id,
                "fire_at": fire_at.isoformat(),
            }
        )
        return job_id


class StubCampaignGraphWriteAdapter(ISecurityGraphWritePort):
    """Records campaign ontology upserts for tests; idempotent by natural key."""

    def __init__(self) -> None:
        self.campaign_nodes: list[dict[str, object]] = []
        self.instance_nodes: list[dict[str, object]] = []
        self.instance_edges: list[dict[str, object]] = []
        self.task_graph_nodes: list[dict[str, object]] = []
        self.uses_graph_edges: list[dict[str, object]] = []
        self.task_nodes: list[dict[str, object]] = []
        self.graph_contains_edges: list[dict[str, object]] = []
        self.task_depends_edges: list[dict[str, object]] = []
        self.based_on_scenario_edges: list[dict[str, object]] = []

    async def upsert_campaign_node(
        self,
        *,
        tenant_id: str,
        campaign_id: str,
        classification: str,
        kind: str,
        state: str,
    ) -> None:
        key = (tenant_id, campaign_id)
        self.campaign_nodes = [
            n for n in self.campaign_nodes if (n["tenant_id"], n["campaign_id"]) != key
        ]
        self.campaign_nodes.append(
            {
                "tenant_id": tenant_id,
                "campaign_id": campaign_id,
                "classification": classification,
                "kind": kind,
                "state": state,
            }
        )

    async def upsert_campaign_instance_node(
        self,
        *,
        tenant_id: str,
        instance_id: str,
        campaign_id: str,
        run_number: int,
        composite_outcome: str | None = None,
    ) -> None:
        key = (tenant_id, instance_id)
        self.instance_nodes = [
            n for n in self.instance_nodes if (n["tenant_id"], n["instance_id"]) != key
        ]
        self.instance_nodes.append(
            {
                "tenant_id": tenant_id,
                "instance_id": instance_id,
                "campaign_id": campaign_id,
                "run_number": run_number,
                "composite_outcome": composite_outcome,
            }
        )

    async def upsert_instance_of_campaign_edge(
        self,
        *,
        tenant_id: str,
        instance_id: str,
        campaign_id: str,
        run_number: int,
    ) -> None:
        key = (tenant_id, instance_id, campaign_id)
        self.instance_edges = [
            e
            for e in self.instance_edges
            if (e["tenant_id"], e["instance_id"], e["campaign_id"]) != key
        ]
        self.instance_edges.append(
            {
                "tenant_id": tenant_id,
                "instance_id": instance_id,
                "campaign_id": campaign_id,
                "run_number": run_number,
            }
        )

    async def upsert_task_graph_node(
        self,
        *,
        tenant_id: str,
        graph_id: str,
        version: str,
    ) -> None:
        key = (tenant_id, graph_id)
        self.task_graph_nodes = [
            n for n in self.task_graph_nodes if (n["tenant_id"], n["graph_id"]) != key
        ]
        self.task_graph_nodes.append(
            {"tenant_id": tenant_id, "graph_id": graph_id, "version": version}
        )

    async def upsert_uses_graph_edge(
        self,
        *,
        tenant_id: str,
        campaign_id: str,
        graph_id: str,
        version: str,
    ) -> None:
        key = (tenant_id, campaign_id, graph_id)
        self.uses_graph_edges = [
            e
            for e in self.uses_graph_edges
            if (e["tenant_id"], e["campaign_id"], e["graph_id"]) != key
        ]
        self.uses_graph_edges.append(
            {
                "tenant_id": tenant_id,
                "campaign_id": campaign_id,
                "graph_id": graph_id,
                "version": version,
            }
        )

    async def upsert_campaign_task_node(
        self,
        *,
        tenant_id: str,
        task_id: str,
        task_type: str,
        criticality: str,
    ) -> None:
        key = (tenant_id, task_id)
        self.task_nodes = [n for n in self.task_nodes if (n["tenant_id"], n["task_id"]) != key]
        self.task_nodes.append(
            {
                "tenant_id": tenant_id,
                "task_id": task_id,
                "task_type": task_type,
                "criticality": criticality,
            }
        )

    async def upsert_graph_contains_edge(
        self,
        *,
        tenant_id: str,
        graph_id: str,
        task_id: str,
        sequence: int,
    ) -> None:
        key = (tenant_id, graph_id, task_id)
        self.graph_contains_edges = [
            e
            for e in self.graph_contains_edges
            if (e["tenant_id"], e["graph_id"], e["task_id"]) != key
        ]
        self.graph_contains_edges.append(
            {
                "tenant_id": tenant_id,
                "graph_id": graph_id,
                "task_id": task_id,
                "sequence": sequence,
            }
        )

    async def upsert_task_depends_on_edge(
        self,
        *,
        tenant_id: str,
        from_task_id: str,
        to_task_id: str,
        predicate: str,
    ) -> None:
        key = (tenant_id, from_task_id, to_task_id)
        self.task_depends_edges = [
            e
            for e in self.task_depends_edges
            if (e["tenant_id"], e["from_task_id"], e["to_task_id"]) != key
        ]
        self.task_depends_edges.append(
            {
                "tenant_id": tenant_id,
                "from_task_id": from_task_id,
                "to_task_id": to_task_id,
                "predicate": predicate,
            }
        )

    async def upsert_based_on_scenario_edge(
        self,
        *,
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
