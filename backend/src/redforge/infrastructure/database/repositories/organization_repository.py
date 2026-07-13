"""SQLAlchemy implementation of OrganizationRepository.

This is the infrastructure adapter that implements the domain's
OrganizationRepository protocol using async SQLAlchemy sessions.

It depends on the domain interface (inward) and uses ORM models +
mappers to translate between persistence and domain representations.
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from redforge.domain.organizations.entity import Organization
from redforge.domain.organizations.value_objects import OrganizationSlug
from redforge.infrastructure.database.mappings import organization_mapper
from redforge.infrastructure.database.models.organization import OrganizationModel
from redforge.shared.identifiers import EntityId


class SqlAlchemyOrganizationRepository:
    """Async SQLAlchemy implementation of OrganizationRepository.

    Each instance is scoped to a single AsyncSession, which represents
    one unit of work (typically one request). The session manages the
    transaction lifecycle externally.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, organization_id: EntityId) -> Organization | None:
        """Load an Organization by its ULID primary key."""
        stmt = select(OrganizationModel).where(
            OrganizationModel.id == str(organization_id)
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()

        if model is None:
            return None

        return organization_mapper.to_entity(model)

    async def get_by_slug(self, slug: OrganizationSlug) -> Organization | None:
        """Load an Organization by its unique slug."""
        stmt = select(OrganizationModel).where(
            OrganizationModel.slug == str(slug)
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()

        if model is None:
            return None

        return organization_mapper.to_entity(model)

    async def slug_exists(self, slug: OrganizationSlug) -> bool:
        """Check if a slug is already taken without loading the full entity."""
        stmt = select(OrganizationModel.id).where(
            OrganizationModel.slug == str(slug)
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none() is not None

    async def save(self, organization: Organization) -> None:
        """Persist a new or updated Organization.

        Uses merge() to handle both insert and update semantics:
        - If the id doesn't exist in the database, it inserts.
        - If the id exists, it updates the existing row.
        """
        model = organization_mapper.to_model(organization)
        await self._session.merge(model)
        await self._session.flush()
