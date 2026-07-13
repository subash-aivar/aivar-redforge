"""Unit tests for Organization aggregate root behavior."""

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
)
from redforge.domain.organizations.value_objects import (
    OrganizationName,
    OrganizationPlan,
    OrganizationSlug,
    OrganizationStatus,
)


def _create_org(
    name: str = "Acme Corp",
    slug: str = "acme-corp",
    plan: OrganizationPlan = OrganizationPlan.FREE,
) -> Organization:
    """Helper to create a valid Organization for testing."""
    return Organization.create(
        name=OrganizationName(name),
        slug=OrganizationSlug(slug),
        plan=plan,
    )


# ─── Creation ─────────────────────────────────────────────────────────────────


class TestOrganizationCreation:
    def test_create_sets_active_status(self) -> None:
        org = _create_org()
        assert org.status == OrganizationStatus.ACTIVE

    def test_create_sets_name_and_slug(self) -> None:
        org = _create_org(name="Test Org", slug="test-org")
        assert org.name == OrganizationName("Test Org")
        assert org.slug == OrganizationSlug("test-org")

    def test_create_sets_plan(self) -> None:
        org = _create_org(plan=OrganizationPlan.ENTERPRISE)
        assert org.plan == OrganizationPlan.ENTERPRISE

    def test_create_defaults_to_free_plan(self) -> None:
        org = _create_org()
        assert org.plan == OrganizationPlan.FREE

    def test_create_generates_unique_id(self) -> None:
        org1 = _create_org()
        org2 = _create_org(slug="other-org")
        assert org1.id != org2.id

    def test_create_sets_timestamps(self) -> None:
        org = _create_org()
        assert org.timestamps.created_at == org.timestamps.updated_at

    def test_create_is_active(self) -> None:
        org = _create_org()
        assert org.is_active is True

    def test_create_emits_created_event(self) -> None:
        org = _create_org(name="Acme", slug="acme", plan=OrganizationPlan.STARTER)
        events = org.collect_events()
        assert len(events) == 1
        event = events[0]
        assert isinstance(event, OrganizationCreated)
        assert event.organization_id == str(org.id)
        assert event.name == "Acme"
        assert event.slug == "acme"
        assert event.plan == "starter"


# ─── Rename ───────────────────────────────────────────────────────────────────


class TestOrganizationRename:
    def test_rename_changes_name(self) -> None:
        org = _create_org(name="Old Name")
        org.collect_events()  # clear creation event
        org.rename(OrganizationName("New Name"))
        assert org.name == OrganizationName("New Name")

    def test_rename_advances_updated_at(self) -> None:
        org = _create_org()
        original_updated = org.timestamps.updated_at
        org.rename(OrganizationName("New Name"))
        assert org.timestamps.updated_at >= original_updated

    def test_rename_emits_event(self) -> None:
        org = _create_org(name="Old Name")
        org.collect_events()
        org.rename(OrganizationName("New Name"))
        events = org.collect_events()
        assert len(events) == 1
        event = events[0]
        assert isinstance(event, OrganizationRenamed)
        assert event.old_name == "Old Name"
        assert event.new_name == "New Name"

    def test_rename_inactive_raises(self) -> None:
        org = _create_org()
        org.deactivate()
        org.collect_events()
        with pytest.raises(OrganizationInactiveError):
            org.rename(OrganizationName("New Name"))


# ─── Activate ─────────────────────────────────────────────────────────────────


class TestOrganizationActivate:
    def test_activate_inactive_org(self) -> None:
        org = _create_org()
        org.deactivate()
        org.collect_events()
        org.activate()
        assert org.status == OrganizationStatus.ACTIVE
        assert org.is_active is True

    def test_activate_emits_event(self) -> None:
        org = _create_org()
        org.deactivate()
        org.collect_events()
        org.activate()
        events = org.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], OrganizationActivated)

    def test_activate_already_active_raises(self) -> None:
        org = _create_org()
        org.collect_events()
        with pytest.raises(InvalidOrganizationTransitionError):
            org.activate()


# ─── Deactivate ───────────────────────────────────────────────────────────────


class TestOrganizationDeactivate:
    def test_deactivate_active_org(self) -> None:
        org = _create_org()
        org.collect_events()
        org.deactivate()
        assert org.status == OrganizationStatus.INACTIVE
        assert org.is_active is False

    def test_deactivate_emits_event(self) -> None:
        org = _create_org()
        org.collect_events()
        org.deactivate()
        events = org.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], OrganizationDeactivated)

    def test_deactivate_inactive_raises(self) -> None:
        org = _create_org()
        org.deactivate()
        org.collect_events()
        with pytest.raises(InvalidOrganizationTransitionError):
            org.deactivate()

    def test_deactivate_advances_updated_at(self) -> None:
        org = _create_org()
        original_updated = org.timestamps.updated_at
        org.deactivate()
        assert org.timestamps.updated_at >= original_updated


# ─── Change Plan ──────────────────────────────────────────────────────────────


class TestOrganizationChangePlan:
    def test_change_plan(self) -> None:
        org = _create_org(plan=OrganizationPlan.FREE)
        org.collect_events()
        org.change_plan(OrganizationPlan.PROFESSIONAL)
        assert org.plan == OrganizationPlan.PROFESSIONAL

    def test_change_plan_emits_event(self) -> None:
        org = _create_org(plan=OrganizationPlan.FREE)
        org.collect_events()
        org.change_plan(OrganizationPlan.ENTERPRISE)
        events = org.collect_events()
        assert len(events) == 1
        event = events[0]
        assert isinstance(event, OrganizationPlanChanged)
        assert event.old_plan == "free"
        assert event.new_plan == "enterprise"

    def test_change_plan_same_plan_no_op(self) -> None:
        org = _create_org(plan=OrganizationPlan.FREE)
        org.collect_events()
        org.change_plan(OrganizationPlan.FREE)
        events = org.collect_events()
        assert len(events) == 0

    def test_change_plan_inactive_raises(self) -> None:
        org = _create_org()
        org.deactivate()
        org.collect_events()
        with pytest.raises(OrganizationInactiveError):
            org.change_plan(OrganizationPlan.ENTERPRISE)

    def test_change_plan_advances_updated_at(self) -> None:
        org = _create_org(plan=OrganizationPlan.FREE)
        original_updated = org.timestamps.updated_at
        org.change_plan(OrganizationPlan.STARTER)
        assert org.timestamps.updated_at >= original_updated


# ─── Events Collection ────────────────────────────────────────────────────────


class TestOrganizationEvents:
    def test_collect_events_clears_list(self) -> None:
        org = _create_org()
        events = org.collect_events()
        assert len(events) == 1
        assert org.collect_events() == []

    def test_multiple_operations_accumulate_events(self) -> None:
        org = _create_org()
        org.rename(OrganizationName("New Name"))
        org.change_plan(OrganizationPlan.ENTERPRISE)
        events = org.collect_events()
        assert len(events) == 3  # created + renamed + plan_changed


# ─── Equality ─────────────────────────────────────────────────────────────────


class TestOrganizationEquality:
    def test_same_id_equal(self) -> None:
        org = _create_org()
        # Reconstruct with same id
        org2 = Organization(
            id=org.id,
            name=OrganizationName("Different Name"),
            slug=OrganizationSlug("different-slug"),
            status=OrganizationStatus.ACTIVE,
            plan=OrganizationPlan.ENTERPRISE,
            timestamps=org.timestamps,
        )
        assert org == org2

    def test_different_id_not_equal(self) -> None:
        org1 = _create_org(slug="org1")
        org2 = _create_org(slug="org2")
        assert org1 != org2

    def test_not_equal_to_other_types(self) -> None:
        org = _create_org()
        assert org != "not-an-org"

    def test_hashable(self) -> None:
        org = _create_org()
        org_set = {org, org}
        assert len(org_set) == 1
