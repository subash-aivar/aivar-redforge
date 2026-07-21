from __future__ import annotations

from ml_pipeline.application.exceptions import ApplicationForbiddenError
from ml_pipeline.domain.value_objects.enums import AnalyticsRole

_ORDER = {
    AnalyticsRole.VIEWER: 1,
    AnalyticsRole.ANALYST: 2,
    AnalyticsRole.ENGINEER: 3,
    AnalyticsRole.ADMIN: 4,
}


def require_at_least(roles: tuple[str, ...], minimum: AnalyticsRole) -> None:
    best = 0
    for r in roles:
        try:
            best = max(best, _ORDER[AnalyticsRole(r)])
        except ValueError:
            continue
    if best < _ORDER[minimum]:
        raise ApplicationForbiddenError(f"requires {minimum.value}")
