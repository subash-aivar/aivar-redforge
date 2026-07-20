"""Degraded ACL adapters for execution Phase 3/4/5."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from execution.domain.ports.i_engagement_scope_port import IEngagementScopePort
from execution.domain.ports.i_payload_query_port import (
    IPayloadQueryPort,
    PayloadDispatchCheck,
)
from execution.domain.value_objects.execution_vos import ScopeSnapshot

if TYPE_CHECKING:
    from execution.domain.value_objects.identifiers import EngagementId, TenantId


class DegradedEngagementScopeAdapter(IEngagementScopePort):
    """
    Degraded ACL: empty authorized targets / techniques.

    Real engagement ACL replaces this when wired. Empty sets cause scope
    verification to fail for any target — tests inject configured adapters.
    """

    async def get_scope_snapshot(
        self,
        engagement_id: EngagementId,
        tenant_id: TenantId,
    ) -> ScopeSnapshot:
        return ScopeSnapshot(
            engagement_id=engagement_id,
            tenant_id=tenant_id,
            authorized_target_ids=frozenset(),
            scope_hash="",
            engagement_version=0,
            state="Unknown",
            window_start=None,
            window_end=None,
            allowed_techniques=frozenset(),
            kill_switch_field_hint=None,
            degraded=True,
        )


class DegradedPayloadQueryAdapter(IPayloadQueryPort):
    """
    Degraded ACL: when no payload_id is supplied by caller, treat as ok.

    When payload_id is present, returns approved/hash_ok=True so tests that
    do not wire a real payload BC still exercise the happy path. Tests inject
    a configured adapter to simulate revoke / hash mismatch.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[UUID, UUID, str | None]] = []

    async def verify_for_dispatch(
        self,
        tenant_id: UUID,
        payload_id: UUID,
        expected_hash: str | None = None,
    ) -> PayloadDispatchCheck:
        self.calls.append((tenant_id, payload_id, expected_hash))
        if payload_id.int == 0:
            return PayloadDispatchCheck(approved=True, hash_ok=True)
        return PayloadDispatchCheck(approved=True, hash_ok=True)
