"""Authorization — canonical exposure:* roles."""

from __future__ import annotations

from exposure_reporting.application.exceptions import ApplicationForbiddenError
from exposure_reporting.domain.value_objects.enums import ReportingRole

_ROLE_RANK = {
    ReportingRole.VIEWER.value: 1,
    ReportingRole.ANALYST.value: 2,
    ReportingRole.ENGINEER.value: 3,
    ReportingRole.ADMIN.value: 4,
}


def require_at_least(actor_roles: tuple[str, ...], minimum: ReportingRole) -> None:
    needed = _ROLE_RANK[minimum.value]
    best = max((_ROLE_RANK.get(r, 0) for r in actor_roles), default=0)
    if best < needed:
        raise ApplicationForbiddenError(minimum.value)
