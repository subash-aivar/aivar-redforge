"""Closed enums for the siem_correlation bounded context (M37 §6)."""

from __future__ import annotations

from enum import StrEnum


class CorrelationSessionStatus(StrEnum):
    """A `CorrelationSession`'s explicitly bounded lifecycle (M37 §6) —
    no status here means "accumulating forever"; every session either
    matches or expires."""

    OPEN = "open"
    MATCHED = "matched"
    EXPIRED = "expired"


class CorrelationKind(StrEnum):
    """M37 §6 — entity correlation joins on a resolved `EntityRef`;
    threat correlation joins against the Attack Library; campaign
    correlation means an *adversary*-observed pattern, never the
    red-team-authored `campaign`/`campaignexecution` meaning (M37 §6)."""

    ENTITY = "entity"
    THREAT = "threat"
    CAMPAIGN = "campaign"


class CorrelationRole(StrEnum):
    """RBAC scopes for siem_correlation's application layer (M37 §16 —
    extends the existing platform RBAC, no parallel model)."""

    VIEWER = "siem_correlation:viewer"
    EXECUTOR = "siem_correlation:execute"
    ADMIN = "siem_correlation:admin"
