"""Dependency contracts for the Application Layer.

These protocols define what the application layer requires from
infrastructure. They are injected at composition time (app startup).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, Self, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Sequence


@runtime_checkable
class ValidationRepositoryPort(Protocol):
    """Port for ValidationRun persistence."""

    async def get_by_id(self, run_id: str) -> dict[str, Any] | None:
        """Unscoped lookup. Internal use only (e.g. ValidationService's
        own write path, which already controls organization scope
        contextually). API-facing callers MUST use
        get_by_id_for_organization instead — see that method's docstring.
        """
        ...

    async def get_by_id_for_organization(
        self, run_id: str, organization_id: str
    ) -> dict[str, Any] | None:
        """Tenant-scoped lookup for any caller acting on behalf of an API
        request. Returns None both when the run does not exist AND when
        it exists but belongs to a different organization — the two
        cases are indistinguishable by design (IDOR prevention).
        """
        ...

    async def list_by_organization(
        self, org_id: str, target_id: str | None, status: str | None,
        limit: int, offset: int,
    ) -> list[dict[str, Any]]: ...
    async def save(self, data: dict[str, Any]) -> None: ...


@runtime_checkable
class FindingRepositoryPort(Protocol):
    """Port for Finding persistence."""

    async def get_by_id(self, finding_id: str) -> dict[str, Any] | None:
        """Unscoped lookup. Internal use only — see
        ValidationRepositoryPort.get_by_id docstring for the rationale.
        """
        ...

    async def get_by_id_for_organization(
        self, finding_id: str, organization_id: str
    ) -> dict[str, Any] | None:
        """Tenant-scoped lookup. See
        ValidationRepositoryPort.get_by_id_for_organization docstring.
        """
        ...

    async def list_by_organization(
        self, org_id: str, target_id: str | None, severity: str | None,
        status: str | None, limit: int, offset: int,
    ) -> list[dict[str, Any]]: ...
    async def save(self, data: dict[str, Any]) -> None: ...
    async def update(self, finding_id: str, data: dict[str, Any]) -> dict[str, Any] | None: ...
    async def update_for_organization(
        self, finding_id: str, organization_id: str, data: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Tenant-scoped update — a no-op (returns None) if the finding
        does not belong to organization_id."""
        ...


@runtime_checkable
class EvidenceRepositoryPort(Protocol):
    """Port for Evidence persistence."""

    async def get_by_id(self, evidence_id: str) -> dict[str, Any] | None:
        """Unscoped lookup. Internal use only — see
        ValidationRepositoryPort.get_by_id docstring for the rationale.
        """
        ...

    async def get_by_id_for_organization(
        self, evidence_id: str, organization_id: str
    ) -> dict[str, Any] | None:
        """Tenant-scoped lookup. See
        ValidationRepositoryPort.get_by_id_for_organization docstring.
        """
        ...

    async def list_by_run(
        self, run_id: str, target_id: str | None, result: str | None,
        limit: int, offset: int,
    ) -> tuple[list[dict[str, Any]], int]: ...


@runtime_checkable
class AttackRepositoryPort(Protocol):
    """Port for Attack Definition persistence."""

    async def get_by_id(self, attack_id: str) -> dict[str, Any] | None: ...
    async def list_all(
        self, category: str | None, severity: str | None,
        status: str | None, limit: int, offset: int,
    ) -> list[dict[str, Any]]: ...
    async def save(self, data: dict[str, Any]) -> None: ...
    async def update_status(self, attack_id: str, status: str) -> dict[str, Any] | None: ...


@runtime_checkable
class PolicyRepositoryPort(Protocol):
    """Port for Validation Policy persistence."""

    async def get_by_id(self, policy_id: str) -> dict[str, Any] | None:
        """Unscoped lookup. Internal use only — see
        ValidationRepositoryPort.get_by_id docstring for the rationale.
        """
        ...

    async def get_by_id_for_organization(
        self, policy_id: str, organization_id: str
    ) -> dict[str, Any] | None:
        """Tenant-scoped lookup. See
        ValidationRepositoryPort.get_by_id_for_organization docstring.
        """
        ...

    async def list_by_organization(
        self, org_id: str, enabled: bool | None, limit: int, offset: int,
    ) -> list[dict[str, Any]]: ...
    async def save(self, data: dict[str, Any]) -> None: ...
    async def update(self, policy_id: str, data: dict[str, Any]) -> dict[str, Any] | None: ...
    async def update_for_organization(
        self, policy_id: str, organization_id: str, data: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Tenant-scoped update — a no-op (returns None) if the policy
        does not belong to organization_id."""
        ...
    async def delete(self, policy_id: str) -> None:
        """Unscoped delete. Internal use only."""
        ...
    async def delete_for_organization(
        self, policy_id: str, organization_id: str
    ) -> bool:
        """Tenant-scoped delete. Returns False (and does not delete) if
        the policy does not belong to organization_id."""
        ...


@runtime_checkable
class ProviderRepositoryPort(Protocol):
    """Port for Provider Registration persistence."""

    async def get_by_id(self, provider_id: str) -> dict[str, Any] | None: ...
    async def list_all(
        self, provider_type: str | None, enabled: bool | None,
        limit: int, offset: int,
    ) -> list[dict[str, Any]]: ...
    async def save(self, data: dict[str, Any]) -> None: ...
    async def update(self, provider_id: str, data: dict[str, Any]) -> dict[str, Any] | None: ...


@runtime_checkable
class PayloadTemplateRepositoryPort(Protocol):
    """Port for PayloadTemplate persistence."""

    async def get_by_id(self, template_id: str) -> dict[str, Any] | None: ...
    async def list_all(
        self, category: str | None, severity: str | None,
        limit: int, offset: int,
    ) -> list[dict[str, Any]]: ...
    async def save(self, data: dict[str, Any]) -> None: ...
    async def delete(self, template_id: str) -> None: ...


@runtime_checkable
class UnitOfWorkPort(Protocol):
    """Application-layer protocol for UnitOfWork.

    Defines the contract services depend on. Implementations live
    in infrastructure (SqlAlchemy) and test doubles (InMemory).
    """

    @property
    def validations(self) -> ValidationRepositoryPort: ...
    @property
    def findings(self) -> FindingRepositoryPort: ...
    @property
    def evidence(self) -> EvidenceRepositoryPort: ...
    @property
    def attacks(self) -> AttackRepositoryPort: ...
    @property
    def policies(self) -> PolicyRepositoryPort: ...
    @property
    def providers(self) -> ProviderRepositoryPort: ...
    @property
    def payloads(self) -> PayloadTemplateRepositoryPort: ...

    async def __aenter__(self) -> Self: ...
    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object | None,
    ) -> None: ...
    async def commit(self) -> None: ...
    async def rollback(self) -> None: ...


@runtime_checkable
class UnitOfWorkFactory(Protocol):
    """Factory that produces UnitOfWork instances.

    Services receive this callable. Each invocation creates a new
    UnitOfWork with its own session/transaction scope.

    Note: returns UnitOfWorkPort but implementations may return
    concrete types (SqlAlchemy or InMemory).
    """

    def __call__(self) -> Any: ...


@runtime_checkable
class EventPublisherPort(Protocol):
    """Port for publishing domain events after successful persistence."""

    async def publish(self, events: Sequence[object]) -> None:
        """Publish a batch of domain events."""
        ...


@runtime_checkable
class CredentialResolverPort(Protocol):
    """Port for server-side provider credential resolution.

    Infrastructure implements this. Application code calls resolve() with
    an opaque auth_ref string (e.g. an environment variable name or a
    secrets-manager path) and receives the resolved secret value.

    The resolved value MUST NOT be logged, persisted, or included in any
    API response or event payload.
    """

    def resolve(self, auth_ref: str) -> str:
        """Resolve an auth_ref to its secret value.

        Raises CredentialResolutionError if the ref is unknown/unset.
        """
        ...
