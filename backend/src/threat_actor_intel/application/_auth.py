"""Role authorization — canonical threat_actor_intel:* roles, mirroring
`exposure.application._auth`'s established `require_at_least` shape.
Not a new RBAC framework: a single linear rank check, identical in
form to the one every other bounded context's application layer
already uses."""

from __future__ import annotations

from threat_actor_intel.application.exceptions import ApplicationForbiddenError
from threat_actor_intel.domain.value_objects.enums import ThreatActorIntelRole

_ROLE_RANK = {
    ThreatActorIntelRole.VIEWER.value: 1,
    ThreatActorIntelRole.ANALYST.value: 2,
    ThreatActorIntelRole.PLATFORM_ADMIN.value: 3,
}


def require_at_least(actor_roles: tuple[str, ...], minimum: ThreatActorIntelRole) -> None:
    needed = _ROLE_RANK[minimum.value]
    best = max((_ROLE_RANK.get(r, 0) for r in actor_roles), default=0)
    if best < needed:
        raise ApplicationForbiddenError(minimum.value)
