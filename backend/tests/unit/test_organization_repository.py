"""Unit tests for OrganizationRepository interface contract.

These tests verify that the repository Protocol is correctly defined
and that a conforming implementation satisfies the contract. We use a
simple in-memory implementation to validate the interface shape.
"""

from redforge.domain.organizations.entity import Organization
from redforge.domain.organizations.repository import OrganizationRepository
from redforge.domain.organizations.value_objects import (
    OrganizationName,
    OrganizationPlan,
    OrganizationSlug,
)
from redforge.shared.identifiers import EntityId


class InMemoryOrganizationRepository:
    """Minimal in-memory implementation for contract testing."""

    def __init__(self) -> None:
        self._store: dict[str, Organization] = {}

    async def get_by_id(self, organization_id: EntityId) -> Organization | None:
        return self._store.get(str(organization_id))

    async def get_by_slug(self, slug: OrganizationSlug) -> Organization | None:
        for org in self._store.values():
            if org.slug == slug:
                return org
        return None

    async def slug_exists(self, slug: OrganizationSlug) -> bool:
        return any(org.slug == slug for org in self._store.values())

    async def save(self, organization: Organization) -> None:
        self._store[str(organization.id)] = organization


def _make_org(slug: str = "test-org") -> Organization:
    return Organization.create(
        name=OrganizationName("Test Organization"),
        slug=OrganizationSlug(slug),
        plan=OrganizationPlan.FREE,
    )


class TestRepositoryProtocolConformance:
    """Verify that InMemoryOrganizationRepository satisfies the Protocol."""

    def test_conforms_to_protocol(self) -> None:
        repo = InMemoryOrganizationRepository()
        # This assertion verifies structural subtyping at runtime.
        # If the class doesn't implement all Protocol methods, this would
        # fail during the isinstance check or at call sites.
        assert isinstance(repo, OrganizationRepository)


class TestRepositoryGetById:
    async def test_returns_none_when_not_found(self) -> None:
        repo = InMemoryOrganizationRepository()
        result = await repo.get_by_id(EntityId.generate())
        assert result is None

    async def test_returns_organization_when_found(self) -> None:
        repo = InMemoryOrganizationRepository()
        org = _make_org()
        await repo.save(org)
        result = await repo.get_by_id(org.id)
        assert result is not None
        assert result.id == org.id


class TestRepositoryGetBySlug:
    async def test_returns_none_when_not_found(self) -> None:
        repo = InMemoryOrganizationRepository()
        result = await repo.get_by_slug(OrganizationSlug("nonexistent"))
        assert result is None

    async def test_returns_organization_when_found(self) -> None:
        repo = InMemoryOrganizationRepository()
        org = _make_org(slug="my-org")
        await repo.save(org)
        result = await repo.get_by_slug(OrganizationSlug("my-org"))
        assert result is not None
        assert result.slug == OrganizationSlug("my-org")


class TestRepositorySlugExists:
    async def test_returns_false_when_slug_available(self) -> None:
        repo = InMemoryOrganizationRepository()
        exists = await repo.slug_exists(OrganizationSlug("available"))
        assert exists is False

    async def test_returns_true_when_slug_taken(self) -> None:
        repo = InMemoryOrganizationRepository()
        org = _make_org(slug="taken")
        await repo.save(org)
        exists = await repo.slug_exists(OrganizationSlug("taken"))
        assert exists is True


class TestRepositorySave:
    async def test_save_new_organization(self) -> None:
        repo = InMemoryOrganizationRepository()
        org = _make_org()
        await repo.save(org)
        result = await repo.get_by_id(org.id)
        assert result == org

    async def test_save_updated_organization(self) -> None:
        repo = InMemoryOrganizationRepository()
        org = _make_org()
        await repo.save(org)
        org.rename(OrganizationName("Updated Name"))
        await repo.save(org)
        result = await repo.get_by_id(org.id)
        assert result is not None
        assert result.name == OrganizationName("Updated Name")
