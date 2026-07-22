"""Outbound ACL subscriber for M36 proposals — ADR-M36-007."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4


@dataclass
class PendingScenarioItem:
    item_id: UUID
    tenant_id: str
    suggestion_id: str
    proposal_payload: dict[str, object]
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    status: str = "pending"


class M36ProposalSubscriber:
    def __init__(self) -> None:
        self.queue: list[PendingScenarioItem] = []

    def handle(
        self,
        tenant_id: str,
        suggestion_id: str,
        proposal_payload: dict[str, object],
    ) -> PendingScenarioItem:
        item = PendingScenarioItem(uuid4(), tenant_id, suggestion_id, dict(proposal_payload))
        self.queue.append(item)
        return item
