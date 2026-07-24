"""Role authorization — canonical siem_analytics:* roles."""

from __future__ import annotations

from siem_analytics.application.exceptions import ApplicationForbiddenError
from siem_analytics.domain.value_objects.enums import AnalyticsRole

_ROLE_RANK = {
    AnalyticsRole.VIEWER.value: 1,
    AnalyticsRole.ADMIN.value: 2,
}


def require_at_least(actor_roles: tuple[str, ...], minimum: AnalyticsRole) -> None:
    needed = _ROLE_RANK[minimum.value]
    best = max((_ROLE_RANK.get(r, 0) for r in actor_roles), default=0)
    if best < needed:
        raise ApplicationForbiddenError(minimum.value)
