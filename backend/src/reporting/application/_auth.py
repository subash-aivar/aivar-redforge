"""Authorization — canonical analytics:* roles for reporting BC."""

from __future__ import annotations

from reporting.application.exceptions import ApplicationForbiddenError
from reporting.domain.value_objects.enums import AnalyticsRole

_ROLE_RANK = {
    AnalyticsRole.VIEWER.value: 1,
    AnalyticsRole.ANALYST.value: 2,
    AnalyticsRole.ENGINEER.value: 3,
    AnalyticsRole.ADMIN.value: 4,
}


def require_at_least(actor_roles: tuple[str, ...], minimum: AnalyticsRole) -> None:
    needed = _ROLE_RANK[minimum.value]
    best = max((_ROLE_RANK.get(r, 0) for r in actor_roles), default=0)
    if best < needed:
        raise ApplicationForbiddenError(minimum.value)
