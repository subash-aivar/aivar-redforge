"""InvitationNotifier implementations.

- StructlogInvitationNotifier: the production default until a real
  transactional-email provider is wired in (see module docstring below
  for why it deliberately logs the token).
- InMemoryInvitationNotifier: test double capturing sent invitations.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from redforge.core.logging import get_logger

logger = get_logger("redforge.notifications")


class StructlogInvitationNotifier:
    """Emits the invitation (including the acceptance token) as a
    structured log event.

    This is an honest bridge, not a placeholder: RedForge has no
    transactional-email integration yet (see the Enterprise Identity
    Platform sprint's technical debt notes). Until one exists, this is
    the only way an invitation actually reaches anyone — an operator
    retrieves the logged accept-link and delivers it out of band. That is
    a real, if manual, working delivery path; it does not pretend to be
    automatic email. When a real email provider is added, it replaces
    this class behind the same InvitationNotifier protocol, and logging
    the token stops being necessary (or acceptable) at that point.
    """

    async def send_invitation(
        self,
        *,
        email: str,
        organization_name: str,
        role: str,
        token: str,
        expires_at: datetime,
    ) -> None:
        logger.info(
            "invitation_issued",
            email=email,
            organization_name=organization_name,
            role=role,
            invitation_token=token,
            expires_at=expires_at.isoformat(),
        )


@dataclass
class SentInvitation:
    email: str
    organization_name: str
    role: str
    token: str
    expires_at: datetime


class InMemoryInvitationNotifier:
    """In-memory InvitationNotifier for testing — captures sent
    invitations for assertion, including the plaintext token (tests
    need it to exercise the accept/reject flow)."""

    def __init__(self) -> None:
        self.sent: list[SentInvitation] = []

    async def send_invitation(
        self,
        *,
        email: str,
        organization_name: str,
        role: str,
        token: str,
        expires_at: datetime,
    ) -> None:
        self.sent.append(SentInvitation(
            email=email, organization_name=organization_name, role=role,
            token=token, expires_at=expires_at,
        ))

    def clear(self) -> None:
        self.sent.clear()
