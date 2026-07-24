"""Role authorization — canonical siem_ingestion:* roles."""

from __future__ import annotations

from siem_ingestion.application.exceptions import ApplicationForbiddenError
from siem_ingestion.domain.value_objects.enums import IngestionRole

_ROLE_RANK = {
    IngestionRole.VIEWER.value: 1,
    IngestionRole.SUBMITTER.value: 2,
    IngestionRole.ADMIN.value: 3,
}


def require_at_least(actor_roles: tuple[str, ...], minimum: IngestionRole) -> None:
    needed = _ROLE_RANK[minimum.value]
    best = max((_ROLE_RANK.get(r, 0) for r in actor_roles), default=0)
    if best < needed:
        raise ApplicationForbiddenError(minimum.value)
