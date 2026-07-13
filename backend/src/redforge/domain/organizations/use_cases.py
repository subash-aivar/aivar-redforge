"""Application use cases for the Organization bounded context.

Use cases orchestrate domain operations without containing business logic.
They are the entry points for application workflows:

1. Accept primitive input (strings, enums).
2. Validate preconditions (slug uniqueness, existence checks).
3. Delegate to the domain aggregate for business rules.
4. Persist results via the repository.
5. Collect and return domain events for downstream publishing.

Use cases depend on the OrganizationRepository protocol (injected).
They are framework-independent — no FastAPI, no SQLAlchemy.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.domain.organizations.entity import Organization
from redforge.domain.organizations.exceptions import (
    OrganizationNotFoundError,
    OrganizationSlugTakenError,
)
from redforge.domain.organizations.value_objects import (
    OrganizationName,
    OrganizationPlan,
    OrganizationSlug,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from redforge.domain.organizations.events import DomainEvent
    from redforge.domain.organizations.repository import OrganizationRepository

# ─── Commands ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class RegisterOrganizationCommand:
    """Input for registering a new Organization."""

    name: str
    slug: str
    plan: str = "free"


@dataclass(frozen=True, slots=True)
class RenameOrganizationCommand:
    """Input for renaming an Organization."""

    organization_id: str
    new_name: str


@dataclass(frozen=True, slots=True)
class ChangeOrganizationPlanCommand:
    """Input for changing an Organization's plan."""

    organization_id: str
    new_plan: str


# ─── Results ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class OrganizationResult:
    """Read-only representation of an Organization for the application boundary."""

    id: str
    name: str
    slug: str
    status: str
    plan: str
    created_at: str
    updated_at: str

    @classmethod
    def from_entity(cls, org: Organization) -> OrganizationResult:
        """Map a domain entity to an application result."""
        return cls(
            id=str(org.id),
            name=str(org.name),
            slug=str(org.slug),
            status=str(org.status),
            plan=str(org.plan),
            created_at=org.timestamps.created_at.isoformat(),
            updated_at=org.timestamps.updated_at.isoformat(),
        )


# ─── Use Cases ────────────────────────────────────────────────────────────────


class RegisterOrganizationUseCase:
    """Register a new Organization.

    Workflow:
    1. Validate slug uniqueness.
    2. Create the Organization aggregate.
    3. Persist via repository.
    4. Return the result with collected events.
    """

    def __init__(self, repository: OrganizationRepository) -> None:
        self._repository = repository

    async def execute(
        self, command: RegisterOrganizationCommand
    ) -> tuple[OrganizationResult, list[DomainEvent]]:
        slug = OrganizationSlug(command.slug)

        if await self._repository.slug_exists(slug):
            raise OrganizationSlugTakenError(command.slug)

        organization = Organization.create(
            name=OrganizationName(command.name),
            slug=slug,
            plan=OrganizationPlan(command.plan),
        )

        await self._repository.save(organization)
        events = organization.collect_events()

        return OrganizationResult.from_entity(organization), events


class GetOrganizationUseCase:
    """Retrieve an Organization by id or slug.

    Workflow:
    1. Attempt lookup by id.
    2. If not found, raise OrganizationNotFoundError.
    3. Return the result.
    """

    def __init__(self, repository: OrganizationRepository) -> None:
        self._repository = repository

    async def execute_by_id(self, organization_id: str) -> OrganizationResult:
        entity_id = EntityId.from_string(organization_id)
        organization = await self._repository.get_by_id(entity_id)

        if organization is None:
            raise OrganizationNotFoundError(organization_id)

        return OrganizationResult.from_entity(organization)

    async def execute_by_slug(self, slug: str) -> OrganizationResult:
        org_slug = OrganizationSlug(slug)
        organization = await self._repository.get_by_slug(org_slug)

        if organization is None:
            raise OrganizationNotFoundError(slug)

        return OrganizationResult.from_entity(organization)


class RenameOrganizationUseCase:
    """Rename an existing Organization.

    Workflow:
    1. Load the Organization.
    2. Invoke rename behavior on the aggregate.
    3. Persist the updated state.
    4. Return the result with collected events.
    """

    def __init__(self, repository: OrganizationRepository) -> None:
        self._repository = repository

    async def execute(
        self, command: RenameOrganizationCommand
    ) -> tuple[OrganizationResult, list[DomainEvent]]:
        organization = await self._load(command.organization_id)

        organization.rename(OrganizationName(command.new_name))

        await self._repository.save(organization)
        events = organization.collect_events()

        return OrganizationResult.from_entity(organization), events

    async def _load(self, organization_id: str) -> Organization:
        entity_id = EntityId.from_string(organization_id)
        organization = await self._repository.get_by_id(entity_id)
        if organization is None:
            raise OrganizationNotFoundError(organization_id)
        return organization


class ActivateOrganizationUseCase:
    """Activate an inactive Organization.

    Workflow:
    1. Load the Organization.
    2. Invoke activate behavior.
    3. Persist the updated state.
    4. Return the result with collected events.
    """

    def __init__(self, repository: OrganizationRepository) -> None:
        self._repository = repository

    async def execute(
        self, organization_id: str
    ) -> tuple[OrganizationResult, list[DomainEvent]]:
        entity_id = EntityId.from_string(organization_id)
        organization = await self._repository.get_by_id(entity_id)

        if organization is None:
            raise OrganizationNotFoundError(organization_id)

        organization.activate()

        await self._repository.save(organization)
        events = organization.collect_events()

        return OrganizationResult.from_entity(organization), events


class DeactivateOrganizationUseCase:
    """Deactivate an active Organization.

    Workflow:
    1. Load the Organization.
    2. Invoke deactivate behavior.
    3. Persist the updated state.
    4. Return the result with collected events.
    """

    def __init__(self, repository: OrganizationRepository) -> None:
        self._repository = repository

    async def execute(
        self, organization_id: str
    ) -> tuple[OrganizationResult, list[DomainEvent]]:
        entity_id = EntityId.from_string(organization_id)
        organization = await self._repository.get_by_id(entity_id)

        if organization is None:
            raise OrganizationNotFoundError(organization_id)

        organization.deactivate()

        await self._repository.save(organization)
        events = organization.collect_events()

        return OrganizationResult.from_entity(organization), events


class ChangeOrganizationPlanUseCase:
    """Change an Organization's subscription plan.

    Workflow:
    1. Load the Organization.
    2. Invoke change_plan behavior.
    3. Persist the updated state.
    4. Return the result with collected events.
    """

    def __init__(self, repository: OrganizationRepository) -> None:
        self._repository = repository

    async def execute(
        self, command: ChangeOrganizationPlanCommand
    ) -> tuple[OrganizationResult, list[DomainEvent]]:
        entity_id = EntityId.from_string(command.organization_id)
        organization = await self._repository.get_by_id(entity_id)

        if organization is None:
            raise OrganizationNotFoundError(command.organization_id)

        organization.change_plan(OrganizationPlan(command.new_plan))

        await self._repository.save(organization)
        events = organization.collect_events()

        return OrganizationResult.from_entity(organization), events
