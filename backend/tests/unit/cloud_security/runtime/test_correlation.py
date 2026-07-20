"""Correlation soft-ref tests — no detections / attack paths."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from redforge.application.cloud_security.runtime.correlation_service import (
    RuntimeCorrelationService,
    StaticInventoryLookup,
)
from redforge.domain.cloud_security.runtime.entities import RuntimeMetadata
from redforge.domain.cloud_security.runtime.event import CloudRuntimeEvent
from redforge.domain.cloud_security.runtime.value_objects import (
    RuntimeContainer,
    RuntimeEventType,
    RuntimeIdentity,
    RuntimeSource,
)
from redforge.domain.cloud_security.value_objects import CloudAccountId, OrganizationId

ORG = OrganizationId("01HXORG0000000000000000001")
ACCOUNT = CloudAccountId(uuid4())
NOW = datetime(2026, 7, 19, tzinfo=UTC)


def _event(
    *,
    target: str = "",
    principal: str = "",
    workload: str = "",
) -> CloudRuntimeEvent:
    return CloudRuntimeEvent.ingest(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        event_type=RuntimeEventType.API_ACTIVITY,
        source=RuntimeSource.GENERIC,
        event_time=NOW,
        metadata=RuntimeMetadata(provider_event_id=str(uuid4()), event_name="evt"),
        identity=RuntimeIdentity(principal_id=principal, principal_name=principal),
        container=RuntimeContainer(workload_name=workload, pod_name=workload),
        target_resource=target,
        now=NOW,
    )


@pytest.mark.asyncio
async def test_correlate_adds_account_and_org_links() -> None:
    service = RuntimeCorrelationService()
    event = await service.correlate(_event())
    kinds = {link.target_kind for link in event.correlation_links}
    assert "CloudAccount" in kinds
    assert "Organization" in kinds
    assert event.correlation_refs.cloud_account_id == ACCOUNT.value


@pytest.mark.asyncio
async def test_correlate_resolves_inventory_ids() -> None:
    asset_id = uuid4()
    iam_id = uuid4()
    wl_id = uuid4()
    lookup = StaticInventoryLookup(
        assets={"arn:aws:s3:::bucket": asset_id},
        principals={"user-1": iam_id},
        workloads={"web": wl_id},
    )
    service = RuntimeCorrelationService(lookup)
    event = await service.correlate(
        _event(target="arn:aws:s3:::bucket", principal="user-1", workload="web")
    )
    assert event.correlation_refs.cloud_asset_id == asset_id
    assert event.correlation_refs.cloud_iam_principal_id == iam_id
    assert event.correlation_refs.kubernetes_workload_id == wl_id
    kinds = {link.target_kind for link in event.correlation_links}
    assert "CloudAsset" in kinds
    assert "CloudIAMPrincipal" in kinds
    assert "KubernetesWorkload" in kinds


@pytest.mark.asyncio
async def test_correlate_dedupes_links() -> None:
    service = RuntimeCorrelationService()
    event = await service.correlate(_event())
    event = await service.correlate(event)
    account_links = [
        link
        for link in event.correlation_links
        if link.target_kind == "CloudAccount"
    ]
    assert len(account_links) == 1


@pytest.mark.asyncio
async def test_correlate_many() -> None:
    service = RuntimeCorrelationService()
    events = await service.correlate_many([_event(), _event()])
    assert len(events) == 2


@pytest.mark.asyncio
async def test_correlate_no_detection_fields() -> None:
    """Soft refs only — no suspicious/attack/brute-force attributes."""
    service = RuntimeCorrelationService()
    event = await service.correlate(_event(principal="attacker"))
    refs = event.correlation_refs.to_dict()
    assert "suspicious" not in refs
    assert "attack_path" not in refs
    assert "brute_force" not in refs
    for link in event.correlation_links:
        assert link.relationship in {"observed_on", "associated_with", "originated_from", "related_to"}


@pytest.mark.asyncio
async def test_static_lookup_miss_returns_none() -> None:
    lookup = StaticInventoryLookup()
    assert (
        await lookup.resolve_cloud_asset_id(
            organization_id=ORG, provider_resource_id="missing"
        )
        is None
    )
    assert (
        await lookup.resolve_iam_principal_id(organization_id=ORG, principal_id="x") is None
    )
    assert (
        await lookup.resolve_kubernetes_workload_id(organization_id=ORG, workload_ref="x")
        is None
    )
