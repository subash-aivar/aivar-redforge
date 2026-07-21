from __future__ import annotations

from regulatory_notification.application.exceptions import ApplicationForbiddenError


def require_submit_role(roles: tuple[str, ...]) -> None:
    if "regulatory:legal" not in roles and "incident:ciso" not in roles:
        raise ApplicationForbiddenError("regulatory:legal or incident:ciso required")


def require_officer(roles: tuple[str, ...]) -> None:
    allowed = {"regulatory:officer", "regulatory:legal", "incident:ciso"}
    if not any(r in allowed for r in roles):
        raise ApplicationForbiddenError("regulatory:officer required")
