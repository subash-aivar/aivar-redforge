"""Unit tests for Organization application use cases.

Uses the InMemoryOrganizationRepository to test use case orchestration
without any infrastructure dependencies.
"""

import pytest

from redforge.domain.organizations.entity import Organization
from redforge.domain.organizations.events import (
    OrganizationActivated,
    OrganizationCreated,
    OrganizationDeactivated,
    OrganizationPlanChanged,
    OrganizationRenamed,
)
from redforge.domain.organizations.exceptions import (
    InvalidOrganizationTransitionError,
    OrganizationInactiveError,
    OrganizationNotFoundError,
    OrganizationSlugTakenError,
)
from redforge.domain.organizations.use_cases import (
    ActivateOrganizationUseCase,
    ChangeOrganizationPlanCommand,
    ChangeOrganizationPlanUseCase,
    DeactivateOrganizationUseCase,
    GetOrganizationUseCase,
    OrganizationResult,
    RegisterOrganizationCommand,
    RegisterOrganizationUseCase,
    RenameOrganizationCommand,
    RenameOrganizationUseCase,
)
from redforge.domain.organizations.value_objects import (
    OrganizationName,
    OrganizationPlan,
    OrganizationSlug,
)
from redforge.shared.identifiers import EntityId

# ─── Test Repository ──────────────────────────────────────────────────────────


class InMemoryOrganizationRepository:
    """In-memory repository for use case testing."""

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


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _repo() -> InMemoryOrganizationRepository:
    return InMemoryOrganizationRepository()


async def _seed_org(
    repo: InMemoryOrganizationRepository,
    name: str = "Acme Corp",
    slug: str = "acme-corp",
    plan: OrganizationPlan = OrganizationPlan.FREE,
) -> Organization:
    """Create and persist an Organization, clearing its creation events."""
    org = Organization.create(
        name=OrganizationName(name),
        slug=OrganizationSlug(slug),
        plan=plan,
    )
    org.collect_events()  # clear creation event
    await repo.save(org)
    return org


# ─── RegisterOrganizationUseCase ──────────────────────────────────────────────


class TestRegisterOrganization:
    async def test_registers_successfully(self) -> None:
        repo = _repo()
        use_case = RegisterOrganizationUseCase(repo)

        result, events = await use_case.execute(
            RegisterOrganizationCommand(name="Acme Corp", slug="acme-corp")
        )

        assert result.name == "Acme Corp"
        assert result.slug == "acme-corp"
        assert result.status == "active"
        assert result.plan == "free"
        assert len(events) == 1
        assert isinstance(events[0], OrganizationCreated)

    async def test_registers_with_custom_plan(self) -> None:
        repo = _repo()
        use_case = RegisterOrganizationUseCase(repo)

        result, _ = await use_case.execute(
            RegisterOrganizationCommand(
                name="Enterprise Co", slug="enterprise-co", plan="enterprise"
            )
        )

        assert result.plan == "enterprise"

    async def test_persists_to_repository(self) -> None:
        repo = _repo()
        use_case = RegisterOrganizationUseCase(repo)

        result, _ = await use_case.execute(
            RegisterOrganizationCommand(name="Acme", slug="acme")
        )

        stored = await repo.get_by_id(EntityId.from_string(result.id))
        assert stored is not None
        assert str(stored.name) == "Acme"

    async def test_raises_on_duplicate_slug(self) -> None:
        repo = _repo()
        await _seed_org(repo, slug="taken")
        use_case = RegisterOrganizationUseCase(repo)

        with pytest.raises(OrganizationSlugTakenError):
            await use_case.execute(
                RegisterOrganizationCommand(name="Other Org", slug="taken")
            )

    async def test_raises_on_invalid_name(self) -> None:
        repo = _repo()
        use_case = RegisterOrganizationUseCase(repo)

        with pytest.raises(ValueError, match="at least 2"):
            await use_case.execute(
                RegisterOrganizationCommand(name="A", slug="valid-slug")
            )

    async def test_raises_on_invalid_slug(self) -> None:
        repo = _repo()
        use_case = RegisterOrganizationUseCase(repo)

        with pytest.raises(ValueError, match="lowercase"):
            await use_case.execute(
                RegisterOrganizationCommand(name="Valid Name", slug="INVALID")
            )

    async def test_raises_on_invalid_plan(self) -> None:
        repo = _repo()
        use_case = RegisterOrganizationUseCase(repo)

        with pytest.raises(ValueError):
            await use_case.execute(
                RegisterOrganizationCommand(
                    name="Valid Name", slug="valid-slug", plan="nonexistent"
                )
            )


# ─── GetOrganizationUseCase ───────────────────────────────────────────────────


class TestGetOrganization:
    async def test_get_by_id(self) -> None:
        repo = _repo()
        org = await _seed_org(repo)
        use_case = GetOrganizationUseCase(repo)

        result = await use_case.execute_by_id(str(org.id))

        assert result.id == str(org.id)
        assert result.name == "Acme Corp"

    async def test_get_by_slug(self) -> None:
        repo = _repo()
        await _seed_org(repo, slug="my-org")
        use_case = GetOrganizationUseCase(repo)

        result = await use_case.execute_by_slug("my-org")

        assert result.slug == "my-org"

    async def test_get_by_id_not_found(self) -> None:
        repo = _repo()
        use_case = GetOrganizationUseCase(repo)
        fake_id = str(EntityId.generate())

        with pytest.raises(OrganizationNotFoundError):
            await use_case.execute_by_id(fake_id)

    async def test_get_by_slug_not_found(self) -> None:
        repo = _repo()
        use_case = GetOrganizationUseCase(repo)

        with pytest.raises(OrganizationNotFoundError):
            await use_case.execute_by_slug("nonexistent")

    async def test_get_by_id_invalid_id_raises(self) -> None:
        repo = _repo()
        use_case = GetOrganizationUseCase(repo)

        with pytest.raises(ValueError, match="Invalid EntityId"):
            await use_case.execute_by_id("not-a-ulid")


# ─── RenameOrganizationUseCase ────────────────────────────────────────────────


class TestRenameOrganization:
    async def test_renames_successfully(self) -> None:
        repo = _repo()
        org = await _seed_org(repo, name="Old Name")
        use_case = RenameOrganizationUseCase(repo)

        result, events = await use_case.execute(
            RenameOrganizationCommand(
                organization_id=str(org.id), new_name="New Name"
            )
        )

        assert result.name == "New Name"
        assert len(events) == 1
        assert isinstance(events[0], OrganizationRenamed)

    async def test_persists_rename(self) -> None:
        repo = _repo()
        org = await _seed_org(repo, name="Old Name")
        use_case = RenameOrganizationUseCase(repo)

        await use_case.execute(
            RenameOrganizationCommand(
                organization_id=str(org.id), new_name="New Name"
            )
        )

        stored = await repo.get_by_id(org.id)
        assert stored is not None
        assert str(stored.name) == "New Name"

    async def test_rename_not_found_raises(self) -> None:
        repo = _repo()
        use_case = RenameOrganizationUseCase(repo)
        fake_id = str(EntityId.generate())

        with pytest.raises(OrganizationNotFoundError):
            await use_case.execute(
                RenameOrganizationCommand(
                    organization_id=fake_id, new_name="Whatever"
                )
            )

    async def test_rename_inactive_raises(self) -> None:
        repo = _repo()
        org = await _seed_org(repo)
        org.deactivate()
        org.collect_events()
        await repo.save(org)
        use_case = RenameOrganizationUseCase(repo)

        with pytest.raises(OrganizationInactiveError):
            await use_case.execute(
                RenameOrganizationCommand(
                    organization_id=str(org.id), new_name="New Name"
                )
            )

    async def test_rename_invalid_name_raises(self) -> None:
        repo = _repo()
        org = await _seed_org(repo)
        use_case = RenameOrganizationUseCase(repo)

        with pytest.raises(ValueError, match="at least 2"):
            await use_case.execute(
                RenameOrganizationCommand(
                    organization_id=str(org.id), new_name="X"
                )
            )


# ─── ActivateOrganizationUseCase ──────────────────────────────────────────────


class TestActivateOrganization:
    async def test_activates_inactive_org(self) -> None:
        repo = _repo()
        org = await _seed_org(repo)
        org.deactivate()
        org.collect_events()
        await repo.save(org)
        use_case = ActivateOrganizationUseCase(repo)

        result, events = await use_case.execute(str(org.id))

        assert result.status == "active"
        assert len(events) == 1
        assert isinstance(events[0], OrganizationActivated)

    async def test_activate_not_found_raises(self) -> None:
        repo = _repo()
        use_case = ActivateOrganizationUseCase(repo)
        fake_id = str(EntityId.generate())

        with pytest.raises(OrganizationNotFoundError):
            await use_case.execute(fake_id)

    async def test_activate_already_active_raises(self) -> None:
        repo = _repo()
        org = await _seed_org(repo)
        use_case = ActivateOrganizationUseCase(repo)

        with pytest.raises(InvalidOrganizationTransitionError):
            await use_case.execute(str(org.id))


# ─── DeactivateOrganizationUseCase ────────────────────────────────────────────


class TestDeactivateOrganization:
    async def test_deactivates_active_org(self) -> None:
        repo = _repo()
        org = await _seed_org(repo)
        use_case = DeactivateOrganizationUseCase(repo)

        result, events = await use_case.execute(str(org.id))

        assert result.status == "inactive"
        assert len(events) == 1
        assert isinstance(events[0], OrganizationDeactivated)

    async def test_deactivate_not_found_raises(self) -> None:
        repo = _repo()
        use_case = DeactivateOrganizationUseCase(repo)
        fake_id = str(EntityId.generate())

        with pytest.raises(OrganizationNotFoundError):
            await use_case.execute(fake_id)

    async def test_deactivate_already_inactive_raises(self) -> None:
        repo = _repo()
        org = await _seed_org(repo)
        org.deactivate()
        org.collect_events()
        await repo.save(org)
        use_case = DeactivateOrganizationUseCase(repo)

        with pytest.raises(InvalidOrganizationTransitionError):
            await use_case.execute(str(org.id))


# ─── ChangeOrganizationPlanUseCase ────────────────────────────────────────────


class TestChangeOrganizationPlan:
    async def test_changes_plan_successfully(self) -> None:
        repo = _repo()
        org = await _seed_org(repo, plan=OrganizationPlan.FREE)
        use_case = ChangeOrganizationPlanUseCase(repo)

        result, events = await use_case.execute(
            ChangeOrganizationPlanCommand(
                organization_id=str(org.id), new_plan="enterprise"
            )
        )

        assert result.plan == "enterprise"
        assert len(events) == 1
        assert isinstance(events[0], OrganizationPlanChanged)

    async def test_same_plan_no_event(self) -> None:
        repo = _repo()
        org = await _seed_org(repo, plan=OrganizationPlan.FREE)
        use_case = ChangeOrganizationPlanUseCase(repo)

        result, events = await use_case.execute(
            ChangeOrganizationPlanCommand(
                organization_id=str(org.id), new_plan="free"
            )
        )

        assert result.plan == "free"
        assert len(events) == 0

    async def test_change_plan_not_found_raises(self) -> None:
        repo = _repo()
        use_case = ChangeOrganizationPlanUseCase(repo)
        fake_id = str(EntityId.generate())

        with pytest.raises(OrganizationNotFoundError):
            await use_case.execute(
                ChangeOrganizationPlanCommand(
                    organization_id=fake_id, new_plan="enterprise"
                )
            )

    async def test_change_plan_inactive_raises(self) -> None:
        repo = _repo()
        org = await _seed_org(repo)
        org.deactivate()
        org.collect_events()
        await repo.save(org)
        use_case = ChangeOrganizationPlanUseCase(repo)

        with pytest.raises(OrganizationInactiveError):
            await use_case.execute(
                ChangeOrganizationPlanCommand(
                    organization_id=str(org.id), new_plan="enterprise"
                )
            )

    async def test_change_plan_invalid_plan_raises(self) -> None:
        repo = _repo()
        org = await _seed_org(repo)
        use_case = ChangeOrganizationPlanUseCase(repo)

        with pytest.raises(ValueError):
            await use_case.execute(
                ChangeOrganizationPlanCommand(
                    organization_id=str(org.id), new_plan="invalid"
                )
            )


# ─── OrganizationResult ──────────────────────────────────────────────────────


class TestOrganizationResult:
    async def test_from_entity_maps_all_fields(self) -> None:
        repo = _repo()
        org = await _seed_org(repo, name="Test Org", slug="test-org")

        result = OrganizationResult.from_entity(org)

        assert result.id == str(org.id)
        assert result.name == "Test Org"
        assert result.slug == "test-org"
        assert result.status == "active"
        assert result.plan == "free"
        assert result.created_at == org.timestamps.created_at.isoformat()
        assert result.updated_at == org.timestamps.updated_at.isoformat()
