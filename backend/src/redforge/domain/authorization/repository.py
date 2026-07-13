"""Repository interfaces for the Security Authorization bounded context."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.domain.authorization.entity import (
        AuthorizationApproval,
        SecurityAuthorization,
    )
    from redforge.domain.authorization.value_objects import (
        AuthorizationStatus,
        ExecutionPolicyDecision,
    )
    from redforge.shared.identifiers import EntityId


@runtime_checkable
class SecurityAuthorizationRepository(Protocol):
    """Port for SecurityAuthorization persistence, always tenant-scoped."""

    async def get_by_id_for_organization(
        self, authorization_id: EntityId, organization_id: EntityId
    ) -> SecurityAuthorization | None:
        """Retrieve an authorization by id, scoped to organization_id.
        Returns None for a foreign-tenant id — callers must never
        distinguish this from "does not exist" in API responses."""
        ...

    async def get_by_id_for_organization_for_update(
        self, authorization_id: EntityId, organization_id: EntityId
    ) -> SecurityAuthorization | None:
        """Locked read (SELECT ... FOR UPDATE against PostgreSQL) —
        callers about to transition lifecycle status under potential
        concurrency (approve/reject/revoke) must use this."""
        ...

    async def list_by_organization(
        self,
        organization_id: EntityId,
        status: AuthorizationStatus | None,
        limit: int,
        offset: int,
    ) -> list[SecurityAuthorization]:
        """List authorizations for one organization, newest first."""
        ...

    async def find_active_covering(
        self, organization_id: EntityId
    ) -> list[SecurityAuthorization]:
        """Return all ACTIVE authorizations for the organization —
        ExecutionPolicyService filters these in-memory by scope/action
        class/validity rather than pushing that logic into SQL, keeping
        the policy decision auditable and testable as pure domain code."""
        ...

    async def count_by_status(self, organization_id: EntityId) -> dict[str, int]:
        """Backend-derived counts per AuthorizationStatus value, keyed
        by the raw status string. Statuses with zero rows are simply
        absent from the returned dict."""
        ...

    async def save(self, authorization: SecurityAuthorization) -> None:
        """Persist a new or updated authorization (insert or update)."""
        ...


@runtime_checkable
class AuthorizationApprovalRepository(Protocol):
    """Port for AuthorizationApproval persistence."""

    async def get_by_authorization_id(
        self, authorization_id: EntityId, organization_id: EntityId
    ) -> AuthorizationApproval | None:
        ...

    async def get_by_authorization_id_for_update(
        self, authorization_id: EntityId, organization_id: EntityId
    ) -> AuthorizationApproval | None:
        """Locked read (SELECT ... FOR UPDATE against PostgreSQL) —
        callers deciding an approval (approve/reject) must use this,
        not get_by_authorization_id, to be race-free under concurrency."""
        ...

    async def save(self, approval: AuthorizationApproval) -> None:
        ...


@runtime_checkable
class ExecutionPolicyDecisionRepository(Protocol):
    """Port for the immutable ExecutionPolicyDecision audit log."""

    async def record(
        self,
        organization_id: EntityId,
        actor_user_id: EntityId,
        decision: ExecutionPolicyDecision,
        *,
        raw_action_class: str,
    ) -> str:
        """Persist one decision. Returns the generated decision_id."""
        ...

    async def list_by_organization(
        self, organization_id: EntityId, limit: int, offset: int,
    ) -> list[dict[str, object]]:
        """Return decision history rows (dicts — this is a pure read
        model, not reconstructed into domain objects) for one
        organization, newest first."""
        ...
