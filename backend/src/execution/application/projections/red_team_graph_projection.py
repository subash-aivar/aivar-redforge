"""RedTeamGraphProjection — ProjectionBase-compatible registry consumer."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from redforge.application.platform.projections.base import ProjectionBase
from redforge.domain.platform.events import EventEnvelope


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass
class RedTeamKGNode:
    node_id: str
    node_type: str
    label: str
    metadata: dict[str, Any] = field(default_factory=dict)


class RedTeamGraphProjection(ProjectionBase):
    """Projects red-team events into an in-process node set for ProjectionRegistry.

    Compatible with ProjectionRegistry (single ``repo`` constructor arg).
    Does not replace Security Graph writes owned by ProjectionCoordinator.
    """

    projection_name = "red_team_security_graph"

    def __init__(self, repo: Any = None) -> None:
        self._repo = repo
        self._nodes: dict[str, dict[str, RedTeamKGNode]] = {}
        self._last_positions: dict[str, int] = {}
        self._events_processed = 0

    def register_with(self, engine: Any) -> None:
        pn = self.projection_name
        for event_type in (
            "execution.AttackActionStarted",
            "execution.AttackActionCompleted",
            "execution.ExecutionWorkerRegistered",
            "engagement.EngagementCreated",
            "engagement.EngagementActivated",
            "operation.OperationCreated",
            "operation.OperationApproved",
            "red_team.AttackActionStarted",
            "red_team.AttackActionCompleted",
            "red_team.EngagementCreated",
            "red_team.OperationCreated",
        ):
            engine.register(pn, event_type, self._handle)

    async def _handle(self, envelope: EventEnvelope) -> None:
        org = envelope.organization_id
        nodes = self._nodes.setdefault(org, {})
        et = envelope.event_type
        if et.endswith("AttackActionStarted") or et.endswith("AttackActionCompleted"):
            node_id = f"attack_action:{envelope.aggregate_id}"
            state = "Completed" if et.endswith("Completed") else "Executing"
            nodes[node_id] = RedTeamKGNode(
                node_id=node_id,
                node_type="attack_action",
                label=envelope.aggregate_id,
                metadata={
                    "aggregate_id": envelope.aggregate_id,
                    "organization_id": org,
                    "state": state,
                    "event_type": et,
                },
            )
        elif et.endswith("ExecutionWorkerRegistered"):
            node_id = f"execution_worker:{envelope.aggregate_id}"
            nodes[node_id] = RedTeamKGNode(
                node_id=node_id,
                node_type="execution_worker",
                label=envelope.aggregate_id,
                metadata={"organization_id": org, "event_type": et},
            )
        elif et.endswith("EngagementCreated") or et.endswith("EngagementActivated"):
            node_id = f"engagement:{envelope.aggregate_id}"
            state = "Active" if et.endswith("Activated") else "Draft"
            existing = nodes.get(node_id)
            if existing is not None:
                existing.metadata["state"] = state
            else:
                nodes[node_id] = RedTeamKGNode(
                    node_id=node_id,
                    node_type="engagement",
                    label=envelope.aggregate_id,
                    metadata={"state": state, "organization_id": org},
                )
        elif et.endswith("OperationCreated") or et.endswith("OperationApproved"):
            node_id = f"operation:{envelope.aggregate_id}"
            state = "Approved" if et.endswith("Approved") else "Draft"
            existing = nodes.get(node_id)
            if existing is not None:
                existing.metadata["state"] = state
            else:
                nodes[node_id] = RedTeamKGNode(
                    node_id=node_id,
                    node_type="operation",
                    label=envelope.aggregate_id,
                    metadata={"state": state, "organization_id": org},
                )

        self._last_positions[org] = envelope.global_position
        self._events_processed += 1
        if self._repo is not None and hasattr(self._repo, "save"):
            await self._repo.save(
                type(
                    "RedTeamKGReadModel",
                    (),
                    {
                        "projection_name": self.projection_name,
                        "organization_id": org,
                        "node_count": len(nodes),
                        "last_event_position": envelope.global_position,
                        "last_updated_at": _utc_now(),
                    },
                )()
            )

    def nodes_for(self, organization_id: str) -> list[RedTeamKGNode]:
        return list(self._nodes.get(organization_id, {}).values())

    def reset(self) -> None:
        self._nodes.clear()
        self._last_positions.clear()
        self._events_processed = 0

    @property
    def events_processed(self) -> int:
        return self._events_processed
