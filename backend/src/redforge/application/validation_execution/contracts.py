"""Protocol contracts for the Gated Safe Active Validation bounded
context. Mirrors application/campaigns/contracts.py's
ExecutionPolicyPort pattern — each bounded context defines its own
narrow port for the M10 policy dependency rather than importing
application.authorization's concrete class, keeping the seam clean.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class ExecutionPolicyDecisionResult(Protocol):
    decision: str
    reason_code: str
    decision_id: str


@runtime_checkable
class ExecutionPolicyPort(Protocol):
    """The mandatory M10 execution-authorization gate. ValidationExecutionService
    calls this TWICE per execution: once to decide whether to authorize
    at all, and again immediately before step dispatch (the time-of-use
    check) — see execution_service.py's module docstring."""

    async def evaluate(
        self,
        *,
        organization_id: str,
        actor_user_id: str,
        action_class: str,
        entity_refs: list[tuple[str, str]],
    ) -> ExecutionPolicyDecisionResult: ...


@runtime_checkable
class EntityOwnershipPort(Protocol):
    """Same shape as application.authorization.contracts.EntityOwnershipPort
    — re-declared locally so this bounded context doesn't import
    another one's seam module directly."""

    async def is_owned_by_organization(
        self, entity_type: str, entity_id: str, organization_id: str
    ) -> bool: ...
