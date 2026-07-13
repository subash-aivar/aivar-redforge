"""Notification delivery contracts.

Protocol-based abstraction, same maturity level and pattern as
infrastructure/audit/contracts.py: a real Protocol plus a
structured-logging reference implementation (production-honest — pipes
to log aggregation, does not itself speak SMTP) and an in-memory test
double. A real transactional-email provider (SES, SendGrid, Postmark)
is a follow-up infrastructure task that implements this same Protocol —
nothing in the application layer changes when that lands.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable


@runtime_checkable
class InvitationNotifier(Protocol):
    """Port for delivering an organization invitation to its recipient."""

    async def send_invitation(
        self,
        *,
        email: str,
        organization_name: str,
        role: str,
        token: str,
        expires_at: datetime,
    ) -> None:
        """Deliver the invitation. `token` is the one-time plaintext
        credential the recipient uses to accept — treat it as a secret.
        The reference StructlogInvitationNotifier implementation logs it
        (see that class's docstring for why that is the correct,
        honest behavior for a platform with no email transport yet); a
        real transactional-email implementation should instead embed it
        only in the delivered message and must not log it at all.
        """
        ...
