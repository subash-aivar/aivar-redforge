"""Proves M16 network lifecycle events genuinely appear in the M15
merged operational feed (`fetch_merged_candidates`), not merely that
the events table exists and the endpoint is reachable (already proven
live in scripts/m16_live_api_acceptance.py). Also proves the new
sources remain tenant-safe: a network run event from org A never
appears in org B's feed.

Uses the real orchestrator (not hand-inserted rows) so the FK-linked
`network_validation_run_events` rows are genuinely valid — a denied run
(no authorization) is sufficient since `create_and_run()` always
appends a `run_created` event before the authorization check."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redforge.application.inventory.tenant_asset_service import TenantAssetService
from redforge.application.network_security.orchestrator import NetworkValidationOrchestrator
from redforge.application.security_conditions.service import TenantSecurityConditionService
from redforge.application.security_correlation.rules import CorrelationRuleRegistry
from redforge.application.security_correlation.service import TenantSecurityCorrelationService
from redforge.application.security_operations.stream_service import fetch_merged_candidates
from redforge.domain.inventory.identity import IdentityScheme
from redforge.domain.inventory.value_objects import AssetDiscoverySource, AssetType
from redforge.domain.network_security.value_objects import NetworkValidationProfile
from redforge.shared.identifiers import EntityId

pytestmark = pytest.mark.asyncio

_DB_URL = "postgresql+asyncpg://redforge:redforge@localhost:5432/redforge_test"


@pytest.fixture
async def session_factory():
    engine = create_async_engine(_DB_URL, echo=False)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


def _build_orchestrator(session_factory) -> NetworkValidationOrchestrator:
    asset_service = TenantAssetService(session_factory)
    condition_service = TenantSecurityConditionService(session_factory)
    correlation_service = TenantSecurityCorrelationService(
        session_factory, CorrelationRuleRegistry(),
    )
    return NetworkValidationOrchestrator(
        session_factory, asset_service, condition_service, correlation_service,
    )


async def _run_denied(session_factory, org_id: str) -> str:
    """Creates a real (unauthorized -> DENIED) NetworkValidationRun via
    the real orchestrator, which appends real `run_created`/
    `policy_denied` events satisfying the FK to network_validation_runs."""
    asset_service = TenantAssetService(session_factory)
    asset = await asset_service.resolve_asset(
        organization_id=org_id, asset_type=AssetType.IP_ADDRESS,
        scheme=IdentityScheme.IP_ADDRESS, raw_external_id="203.0.113.230",
        name="203.0.113.230", description="M15 projection test",
        discovery_source=AssetDiscoverySource.API_SCAN,
    )
    orchestrator = _build_orchestrator(session_factory)
    run = await orchestrator.create_and_run(
        organization_id=org_id, target_asset_id=asset.id,
        requester_user_id=str(EntityId.generate()),
        profile=NetworkValidationProfile.NETWORK_BASELINE,
    )
    return run.id


async def test_network_run_event_appears_in_merged_feed(session_factory) -> None:
    org_id = str(EntityId.generate())
    run_id = await _run_denied(session_factory, org_id)

    candidates = await fetch_merged_candidates(
        session_factory, org_id, datetime(1970, 1, 1, tzinfo=UTC), 200,
        apply_visibility_lag=False,
    )
    matching = [c for c in candidates if c.entity_id == run_id]
    assert len(matching) >= 1
    assert all(c.source_domain == "network_security" for c in matching)


async def test_network_events_remain_tenant_safe_in_merged_feed(session_factory) -> None:
    org_a = str(EntityId.generate())
    org_b = str(EntityId.generate())
    run_id = await _run_denied(session_factory, org_a)

    candidates_for_b = await fetch_merged_candidates(
        session_factory, org_b, datetime(1970, 1, 1, tzinfo=UTC), 200,
        apply_visibility_lag=False,
    )
    assert all(c.entity_id != run_id for c in candidates_for_b)
