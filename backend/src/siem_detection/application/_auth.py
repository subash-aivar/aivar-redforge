"""Role authorization — canonical siem_detection:* roles."""

from __future__ import annotations

from siem_detection.application.exceptions import ApplicationForbiddenError
from siem_detection.domain.value_objects.enums import DetectionRole

_ROLE_RANK = {
    DetectionRole.VIEWER.value: 1,
    DetectionRole.EXECUTOR.value: 2,
    DetectionRole.ADMIN.value: 3,
}


def require_at_least(actor_roles: tuple[str, ...], minimum: DetectionRole) -> None:
    needed = _ROLE_RANK[minimum.value]
    best = max((_ROLE_RANK.get(r, 0) for r in actor_roles), default=0)
    if best < needed:
        raise ApplicationForbiddenError(minimum.value)
