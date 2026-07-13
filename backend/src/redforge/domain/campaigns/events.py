"""Domain events for the Campaign bounded context."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime  # noqa: TC003 — used at runtime by _now() and dataclass fields

from redforge.shared.timestamps import utc_now


def _now() -> datetime:
    return utc_now()


@dataclass(frozen=True, slots=True)
class CampaignEvent:
    campaign_id: str
    organization_id: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class CampaignCreated(CampaignEvent):
    campaign_type: str = ""
    policy_id: str = ""
    total_targets: int = 0


@dataclass(frozen=True, slots=True)
class CampaignStarted(CampaignEvent):
    pass


@dataclass(frozen=True, slots=True)
class CampaignPaused(CampaignEvent):
    pass


@dataclass(frozen=True, slots=True)
class CampaignResumed(CampaignEvent):
    pass


@dataclass(frozen=True, slots=True)
class CampaignCancelled(CampaignEvent):
    reason: str = ""


@dataclass(frozen=True, slots=True)
class CampaignCompleted(CampaignEvent):
    total_targets: int = 0
    successful_targets: int = 0
    failed_targets: int = 0
    total_findings: int = 0
    regression_detected: bool = False


@dataclass(frozen=True, slots=True)
class CampaignFailed(CampaignEvent):
    reason: str = ""


@dataclass(frozen=True, slots=True)
class CampaignTargetCompleted(CampaignEvent):
    target_id: str = ""
    run_id: str = ""
    findings_count: int = 0


@dataclass(frozen=True, slots=True)
class CampaignTargetFailed(CampaignEvent):
    target_id: str = ""
    failure_reason: str = ""
