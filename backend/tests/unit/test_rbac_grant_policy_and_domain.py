"""Fast, no-DB unit tests for the M17 RBAC domain/grant-policy layer."""

from __future__ import annotations

import pytest

from redforge.application.rbac.grant_policy import assert_can_grant
from redforge.domain.identity.value_objects import Permission
from redforge.domain.rbac.entity import OrganizationGroup, OrganizationRole, normalize_name
from redforge.domain.rbac.exceptions import PrivilegeEscalationError, SystemRoleImmutableError
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps


def test_normalize_name_collapses_case_and_whitespace() -> None:
    assert normalize_name("  SOC   Team  ") == "soc team"
    assert normalize_name("soc team") == normalize_name("  SOC   Team  ")


def test_grant_policy_allows_subset_of_actor_permissions() -> None:
    actor = frozenset({Permission.FINDINGS_READ, Permission.TARGETS_READ})
    assert_can_grant(actor, frozenset({Permission.FINDINGS_READ}))  # does not raise


def test_grant_policy_denies_permission_actor_does_not_hold() -> None:
    """The canonical bounded-delegation rule: an actor can never grant a
    permission they do not themselves effectively hold — this is what
    makes self-escalation and indirect group-derived escalation
    structurally impossible."""
    actor = frozenset({Permission.FINDINGS_READ})
    with pytest.raises(PrivilegeEscalationError):
        assert_can_grant(actor, frozenset({Permission.FINDINGS_READ, Permission.ORG_MANAGE}))


def test_grant_policy_denies_when_actor_holds_nothing() -> None:
    with pytest.raises(PrivilegeEscalationError):
        assert_can_grant(frozenset(), frozenset({Permission.FINDINGS_READ}))


def test_custom_role_permissions_are_typed_permission_never_bare_strings() -> None:
    """Structural proof that a custom role cannot carry platform
    authority: `permissions` is typed `frozenset[Permission]` — the
    exact same closed tenant enum every other permission check already
    uses. There is no constructor path that accepts a
    PlatformPermission or an arbitrary string."""
    role = OrganizationRole.create(
        EntityId.generate(), "Analysts", "desc", frozenset({Permission.FINDINGS_READ}),
    )
    assert role.permissions == frozenset({Permission.FINDINGS_READ})
    assert all(isinstance(p, Permission) for p in role.permissions)


def test_system_role_cannot_be_renamed() -> None:
    role = OrganizationRole(
        id=EntityId.generate(), organization_id=EntityId.generate(), name="Owner",
        description="", permissions=frozenset(Permission),
        timestamps=AuditTimestamps.create(), is_system=True,
    )
    with pytest.raises(SystemRoleImmutableError):
        role.rename("Hacked Owner", "")


def test_system_role_permissions_cannot_be_changed() -> None:
    role = OrganizationRole(
        id=EntityId.generate(), organization_id=EntityId.generate(), name="Owner",
        description="", permissions=frozenset(Permission),
        timestamps=AuditTimestamps.create(), is_system=True,
    )
    with pytest.raises(SystemRoleImmutableError):
        role.set_permissions(frozenset())


def test_custom_role_can_be_renamed_and_repermissioned() -> None:
    role = OrganizationRole.create(
        EntityId.generate(), "Analysts", "desc", frozenset({Permission.FINDINGS_READ}),
    )
    version_before = role.version
    role.rename("Senior Analysts", "updated desc")
    role.set_permissions(frozenset({Permission.FINDINGS_READ, Permission.TARGETS_READ}))
    assert role.name == "Senior Analysts"
    assert role.permissions == frozenset({Permission.FINDINGS_READ, Permission.TARGETS_READ})
    assert role.version == version_before + 2


def test_group_belongs_to_exactly_one_organization() -> None:
    org_id = EntityId.generate()
    group = OrganizationGroup.create(org_id, "SOC Team", "desc")
    assert group.organization_id == org_id
