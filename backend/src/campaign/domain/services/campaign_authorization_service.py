"""CampaignAuthorizationService — validates engagement gate before campaign operations."""

from __future__ import annotations

from typing import TYPE_CHECKING

from campaign.domain.exceptions.domain_exceptions import EngagementNotActive

if TYPE_CHECKING:
    from uuid import UUID

    from campaign.domain.aggregates.campaign import Campaign
    from campaign.domain.ports.i_engagement_query_port import IEngagementQueryPort

_ACTIVE_STATE = "Active"
_ARMED_KILL_SWITCH = "Armed"


class CampaignAuthorizationService:
    """Domain service that validates the M29 engagement gate.

    A campaign can only start an instance when the linked engagement is Active
    with an ARMED kill switch. A Suspended, Closed, or kill-switch-triggered
    engagement blocks all new campaign operations.
    """

    async def authorize(
        self,
        campaign: Campaign,
        tenant_id: UUID,
        engagement_port: IEngagementQueryPort,
    ) -> None:
        if campaign.engagement_ref is None:
            raise EngagementNotActive("(none)", "EngagementRef not set on campaign")

        status = await engagement_port.get_engagement_status(
            campaign.engagement_ref.engagement_id,
            tenant_id,
        )
        if status is None:
            raise EngagementNotActive(
                str(campaign.engagement_ref.engagement_id),
                "not found",
            )

        if status.state != _ACTIVE_STATE:
            raise EngagementNotActive(
                str(campaign.engagement_ref.engagement_id),
                status.state,
            )

        if status.kill_switch_state != _ARMED_KILL_SWITCH:
            raise EngagementNotActive(
                str(campaign.engagement_ref.engagement_id),
                f"kill switch is '{status.kill_switch_state}' — must be Armed",
            )
