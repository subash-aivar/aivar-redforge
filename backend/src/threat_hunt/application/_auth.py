from __future__ import annotations

from threat_hunt.application.exceptions import ApplicationForbiddenError


def require_any(roles: tuple[str, ...], *allowed: str) -> None:
    if not any(r in roles for r in allowed):
        raise ApplicationForbiddenError(",".join(allowed))
