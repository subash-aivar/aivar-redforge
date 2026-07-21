from __future__ import annotations

from lessons_learned.application.exceptions import ApplicationForbiddenError
from lessons_learned.domain.value_objects.enums import LessonsRole

_RANK = {LessonsRole.CONTRIBUTOR.value: 1, LessonsRole.APPROVER.value: 2}


def require_at_least(roles: tuple[str, ...], minimum: LessonsRole) -> None:
    if max((_RANK.get(r, 0) for r in roles), default=0) < _RANK[minimum.value]:
        raise ApplicationForbiddenError(minimum.value)
