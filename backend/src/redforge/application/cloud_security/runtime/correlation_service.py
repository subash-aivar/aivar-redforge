"""Soft inventory correlation for runtime events — NO detections / attack paths."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from redforge.domain.cloud_security.runtime.entities import RuntimeCorrelationReference
from redforge.domain.cloud_security.runtime.event import CloudRuntimeEvent
from redforge.domain.cloud_security.runtime.value_objects import RuntimeCorrelationRefs
from redforge.domain.cloud_security.value_objects import OrganizationId


class InventoryLookupPort(Protocol):
    """Optional lookups against existing inventory IDs (soft refs only)."""

    async def resolve_cloud_asset_id(
        self, *, organization_id: OrganizationId, provider_resource_id: str
    ) -> UUID | None: ...

    async def resolve_iam_principal_id(
        self, *, organization_id: OrganizationId, principal_id: str
    ) -> UUID | None: ...

    async def resolve_kubernetes_workload_id(
        self, *, organization_id: OrganizationId, workload_ref: str
    ) -> UUID | None: ...


@dataclass
class StaticInventoryLookup:
    """Test/dev lookup table keyed by provider identifiers."""

    assets: dict[str, UUID] | None = None
    principals: dict[str, UUID] | None = None
    workloads: dict[str, UUID] | None = None

    async def resolve_cloud_asset_id(
        self, *, organization_id: OrganizationId, provider_resource_id: str
    ) -> UUID | None:
        _ = organization_id
        return (self.assets or {}).get(provider_resource_id)

    async def resolve_iam_principal_id(
        self, *, organization_id: OrganizationId, principal_id: str
    ) -> UUID | None:
        _ = organization_id
        return (self.principals or {}).get(principal_id)

    async def resolve_kubernetes_workload_id(
        self, *, organization_id: OrganizationId, workload_ref: str
    ) -> UUID | None:
        _ = organization_id
        return (self.workloads or {}).get(workload_ref)


class RuntimeCorrelationService:
    """Binds soft refs to CloudAsset / CloudIAMPrincipal / KubernetesWorkload / account / org."""

    def __init__(self, lookup: InventoryLookupPort | None = None) -> None:
        self._lookup = lookup

    async def correlate(self, event: CloudRuntimeEvent) -> CloudRuntimeEvent:
        refs = event.correlation_refs
        cloud_asset_id = refs.cloud_asset_id
        iam_id = refs.cloud_iam_principal_id
        workload_id = refs.kubernetes_workload_id
        links: list[RuntimeCorrelationReference] = list(event.correlation_links)

        if self._lookup is not None:
            if cloud_asset_id is None and event.target_resource:
                cloud_asset_id = await self._lookup.resolve_cloud_asset_id(
                    organization_id=event.organization_id,
                    provider_resource_id=event.target_resource,
                )
            if iam_id is None and event.identity.principal_id:
                iam_id = await self._lookup.resolve_iam_principal_id(
                    organization_id=event.organization_id,
                    principal_id=event.identity.principal_id,
                )
            workload_ref = event.container.workload_name or event.container.pod_name
            if workload_id is None and workload_ref:
                workload_id = await self._lookup.resolve_kubernetes_workload_id(
                    organization_id=event.organization_id,
                    workload_ref=workload_ref,
                )

        account_id = refs.cloud_account_id or event.cloud_account_id.value
        org_id = refs.organization_id or str(event.organization_id)

        if cloud_asset_id is not None:
            links.append(
                RuntimeCorrelationReference(
                    target_kind="CloudAsset",
                    target_id=str(cloud_asset_id),
                    relationship="observed_on",
                )
            )
        if iam_id is not None:
            links.append(
                RuntimeCorrelationReference(
                    target_kind="CloudIAMPrincipal",
                    target_id=str(iam_id),
                    relationship="associated_with",
                )
            )
        if workload_id is not None:
            links.append(
                RuntimeCorrelationReference(
                    target_kind="KubernetesWorkload",
                    target_id=str(workload_id),
                    relationship="observed_on",
                )
            )
        links.append(
            RuntimeCorrelationReference(
                target_kind="CloudAccount",
                target_id=str(account_id),
                relationship="originated_from",
            )
        )
        links.append(
            RuntimeCorrelationReference(
                target_kind="Organization",
                target_id=org_id,
                relationship="originated_from",
            )
        )

        # Deduplicate links by (kind, id, relationship).
        seen: set[tuple[str, str, str]] = set()
        unique_links: list[RuntimeCorrelationReference] = []
        for link in links:
            key = (link.target_kind, link.target_id, link.relationship)
            if key in seen:
                continue
            seen.add(key)
            unique_links.append(link)

        event.bind_correlation_refs(
            RuntimeCorrelationRefs(
                cloud_asset_id=cloud_asset_id,
                cloud_iam_principal_id=iam_id,
                kubernetes_workload_id=workload_id,
                cloud_account_id=account_id,
                organization_id=org_id,
            )
        )
        event.correlation_links = tuple(unique_links)
        return event

    async def correlate_many(self, events: list[CloudRuntimeEvent]) -> list[CloudRuntimeEvent]:
        return [await self.correlate(event) for event in events]
