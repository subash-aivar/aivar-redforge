"""Role authorization — canonical exposure:* roles."""

from __future__ import annotations

from exposure.application.exceptions import ApplicationForbiddenError
from exposure.domain.value_objects.enums import ExposureRole

_ROLE_RANK = {
    ExposureRole.VIEWER.value: 1,
    ExposureRole.ANALYST.value: 2,
    ExposureRole.ENGINEER.value: 3,
    ExposureRole.ADMIN.value: 4,
}


def require_at_least(actor_roles: tuple[str, ...], minimum: ExposureRole) -> None:
    needed = _ROLE_RANK[minimum.value]
    best = max((_ROLE_RANK.get(r, 0) for r in actor_roles), default=0)
    if best < needed:
        raise ApplicationForbiddenError(minimum.value)
