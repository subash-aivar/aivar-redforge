"""Role authorization for ioc_intelligence (M51.2 Phase A2) — mirrors
`threat_actor_intel.application._auth`'s established `require_at_least`
shape exactly. Not a new RBAC framework: the same single linear rank
check every other bounded context's application layer already uses.

- `PLATFORM_ADMIN` — required for global IOC observation/mutation
  (`tenant_id=None` in a command means "acting on global intelligence").
- `ANALYST` — required for tenant-scoped IOC observation/mutation.
- `VIEWER` — required for get/list (read-only).

`tenant_id` on a command is trusted context supplied by the caller
(the future API layer), never authority itself — authority comes only
from `actor_roles`. A tenant-scoped command's `tenant_id` value can
never, by construction, be used to satisfy the `PLATFORM_ADMIN` check
a global command requires — this is what prevents a tenant IOC from
promoting itself to global intelligence at the application boundary.
"""

from __future__ import annotations

from enum import StrEnum, unique

from ioc_intelligence.application.exceptions import ApplicationForbiddenError


@unique
class IocIntelRole(StrEnum):
    VIEWER = "ioc_intelligence:viewer"
    ANALYST = "ioc_intelligence:analyst"
    PLATFORM_ADMIN = "ioc_intelligence:platform_admin"


_ROLE_RANK = {
    IocIntelRole.VIEWER.value: 1,
    IocIntelRole.ANALYST.value: 2,
    IocIntelRole.PLATFORM_ADMIN.value: 3,
}


def require_at_least(actor_roles: tuple[str, ...], minimum: IocIntelRole) -> None:
    needed = _ROLE_RANK[minimum.value]
    best = max((_ROLE_RANK.get(r, 0) for r in actor_roles), default=0)
    if best < needed:
        raise ApplicationForbiddenError(minimum.value)
