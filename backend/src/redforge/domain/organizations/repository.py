"""Repository interface for the Organization aggregate.

This is a domain-level contract that defines how Organizations are persisted
and retrieved. The implementation lives in the infrastructure layer and may
use SQLAlchemy, an in-memory store, or any other persistence mechanism.

The domain layer depends on this interface. The infrastructure layer
implements it. This is the Dependency Inversion Principle in action.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.domain.organizations.entity import Organization
    from redforge.domain.organizations.value_objects import OrganizationSlug
    from redforge.shared.identifiers import EntityId


@runtime_checkable
class OrganizationRepository(Protocol):
    """Port for Organization persistence operations.

    Implementations must handle:
    - Persistence of new organizations
    - Retrieval by id and slug
    - Updates to existing organizations
    - Slug uniqueness checks
    """

    async def get_by_id(self, organization_id: EntityId) -> Organization | None:
        """Retrieve an Organization by its unique identifier.

        Returns None if no organization exists with the given id.
        """
        ...

    async def get_by_slug(self, slug: OrganizationSlug) -> Organization | None:
        """Retrieve an Organization by its unique slug.

        Returns None if no organization exists with the given slug.
        """
        ...

    async def slug_exists(self, slug: OrganizationSlug) -> bool:
        """Check whether a slug is already taken.

        Used before creating an organization to enforce uniqueness
        at the domain level.
        """
        ...

    async def save(self, organization: Organization) -> None:
        """Persist a new or updated Organization.

        For new organizations, this inserts a new record.
        For existing organizations, this updates the existing record.
        The implementation determines insert vs update semantics.
        """
        ...
