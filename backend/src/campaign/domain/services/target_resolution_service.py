"""TargetResolutionService — resolves TargetSelectionRules against M22 inventory."""

from __future__ import annotations

from typing import TYPE_CHECKING

from campaign.domain.exceptions.domain_exceptions import TargetResolutionFailed
from campaign.domain.value_objects.campaign_vos import SelectedTargetSet

if TYPE_CHECKING:
    from uuid import UUID

    from campaign.domain.ports.i_engagement_query_port import IEngagementQueryPort
    from campaign.domain.ports.i_inventory_query_port import IInventoryQueryPort
    from campaign.domain.value_objects.campaign_vos import (
        EngagementRef,
        TargetRef,
        TargetSelectionRule,
    )


class TargetResolutionService:
    """Domain service that resolves campaign target selection rules into a concrete TargetSet.

    Resolution happens at instance start time, never at campaign design time.
    The service enforces that all resolved targets are within the engagement scope.
    """

    async def resolve(
        self,
        criteria: list[TargetSelectionRule],
        engagement_ref: EngagementRef,
        tenant_id: UUID,
        inventory_port: IInventoryQueryPort,
        engagement_port: IEngagementQueryPort,
    ) -> SelectedTargetSet:
        if not criteria:
            raise TargetResolutionFailed("No target selection rules provided")

        rules_payload = [
            {"attribute": r.attribute, "operator": r.operator, "value": r.value}
            for r in criteria
        ]
        resolved: list[TargetRef] = await inventory_port.resolve_targets(
            rules_payload, tenant_id
        )

        if not resolved:
            raise TargetResolutionFailed(
                "No targets matched the provided selection rules"
            )

        engagement_status = await engagement_port.get_engagement_status(
            engagement_ref.engagement_id, tenant_id
        )
        if engagement_status is None:
            raise TargetResolutionFailed(
                f"Engagement '{engagement_ref.engagement_id}' not found"
            )

        if engagement_status.allowed_target_ids is not None:
            # Explicit scope list: None = unrestricted, [] = no targets authorized
            in_scope = [
                t for t in resolved if t.asset_id in engagement_status.allowed_target_ids
            ]
            if not in_scope:
                raise TargetResolutionFailed(
                    "All resolved targets are outside the engagement scope"
                )
            resolved = in_scope

        return SelectedTargetSet(targets=tuple(resolved))
