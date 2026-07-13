"""Canonical privilege-grant policy — M17.

The single place that decides whether an actor may grant a given set of
Permissions to a role/user/group. Every RBAC mutation that assigns
permissions (create role, set permissions, and — transitively — any
role assignment, since assigning a role grants its permissions) MUST
route through `assert_can_grant`. Do not duplicate this check inline in
an API handler or another service — that is exactly the "scattered
privilege-escalation logic" this module exists to prevent.

Policy (bounded delegation — the standard enterprise IAM rule):
  An actor may only grant a permission they THEMSELVES effectively
  hold. This makes self-escalation and indirect (group-derived)
  escalation structurally impossible: since granting is bounded by the
  actor's own current effective permission set, no sequence of role/
  group mutations can ever produce a permission set larger than what a
  legitimate OWNER/ADMIN already independently holds.

Platform Super Admin authority is a SEPARATE, unrelated authorization
plane (domain.platform_identity) — this policy never inspects it and a
tenant Permission set can never include a PlatformPermission value (the
type system prevents it), so no organization role can ever grant
platform authority, by construction, not by this policy's diligence.
"""

from __future__ import annotations

from redforge.domain.identity.value_objects import Permission
from redforge.domain.rbac.exceptions import PrivilegeEscalationError


def assert_can_grant(
    actor_permissions: frozenset[Permission], requested: frozenset[Permission],
) -> None:
    """Raise PrivilegeEscalationError if `requested` contains any
    permission the actor does not themselves effectively hold."""
    not_held = requested - actor_permissions
    if not_held:
        raise PrivilegeEscalationError(sorted(p.value for p in not_held)[0])
