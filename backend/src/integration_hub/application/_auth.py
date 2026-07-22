from __future__ import annotations

from integration_hub.application.exceptions import ApplicationForbiddenError


def require_admin(roles: tuple[str, ...]) -> None:
    if "integration:admin" not in roles and "incident:ciso" not in roles:
        raise ApplicationForbiddenError("integration:admin")
