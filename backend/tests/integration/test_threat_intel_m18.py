"""M18 Threat Intelligence expansion pass — real running app, real
PostgreSQL, real HTTP acceptance over the new /threat-intel/* surface.

Mirrors the exact harness `test_command_center_m18.py` already
established (ASGITransport + the app's own lifespan, real DB, real
invitation/role flow) against a DEDICATED proof database
(`redforge_threat_intel_proof_test`). No external network call is ever
made from this file — every scenario here exercises tenant isolation,
RBAC, egress-gating, and honest-empty-state behavior, none of which
require contacting a real provider. Live provider acceptance is
recorded separately (see docs) since it requires real network access
outside the normal test suite.
"""

from __future__ import annotations

import os
import time

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

pytestmark = pytest.mark.asyncio(loop_scope="module")

_TEST_DB_NAME = "redforge_threat_intel_proof_test"
_DB_URL = os.environ.get(
    "REDFORGE_THREAT_INTEL_TEST_DATABASE_URL",
    f"postgresql+asyncpg://redforge:redforge@localhost:5432/{_TEST_DB_NAME}",
)


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def client():
    from unittest.mock import patch

    from redforge.app import create_app
    from redforge.core.config import Settings
    from redforge.infrastructure.rate_limiting.contracts import RateLimitResult
    from redforge.infrastructure.rate_limiting.sliding_window import (
        InMemorySlidingWindowLimiter,
    )

    async def _always_allow(
        self: object,
        key: str,
        max_requests: int,
        window_seconds: int,
    ) -> RateLimitResult:
        return RateLimitResult(
            allowed=True,
            remaining=max_requests,
            limit=max_requests,
            retry_after_seconds=0,
        )

    with patch.object(InMemorySlidingWindowLimiter, "check", _always_allow):
        app = create_app(settings=Settings(database_url=_DB_URL))
        async with app.router.lifespan_context(app):
            transport = ASGITransport(app=app, raise_app_exceptions=False)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                yield c


def _unique(prefix: str) -> str:
    return f"{prefix}-{time.time_ns()}"


async def _register(client: AsyncClient, email: str) -> str:
    r = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "display_name": "TI Test User", "password": "SecureP@ss123"},
    )
    assert r.status_code == 201, r.text
    return r.json()["access_token"]


async def _create_org_and_select(client: AsyncClient, token: str, slug: str) -> tuple[str, str]:
    r = await client.post(
        "/api/v1/organizations",
        json={"name": "TI Test Org", "slug": slug},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 201, r.text
    org_id = r.json()["id"]
    r = await client.post(
        f"/api/v1/auth/organizations/{org_id}/select",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.text
    return org_id, r.json()["access_token"]


async def _owner_context(client: AsyncClient) -> tuple[str, dict[str, str]]:
    unique = _unique("owner")
    token = await _register(client, f"{unique}@example.test")
    org_id, scoped = await _create_org_and_select(client, token, _unique("org"))
    return org_id, {"Authorization": f"Bearer {scoped}"}


async def _invite_viewer(
    client: AsyncClient,
    owner_headers: dict[str, str],
    org_id: str,
) -> dict[str, str]:
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from redforge.application.invitations import InvitationService
    from redforge.infrastructure.audit.logger import InMemoryAuditLog
    from redforge.infrastructure.events import InMemoryEventPublisher
    from redforge.infrastructure.notifications.logging_notifier import (
        InMemoryInvitationNotifier,
    )

    fixture_engine = create_async_engine(_DB_URL, echo=False)
    fixture_session_factory = async_sessionmaker(fixture_engine, expire_on_commit=False)
    notifier = InMemoryInvitationNotifier()
    invitation_service = InvitationService(
        fixture_session_factory,
        InMemoryEventPublisher(),
        InMemoryAuditLog(),
        notifier,
    )
    r = await client.get("/api/v1/auth/me", headers=owner_headers)
    owner_user_id = r.json()["user_id"]
    unique = _unique("viewer")
    email = f"{unique}@example.test"
    await invitation_service.invite(
        organization_id=org_id,
        invited_by_user_id=owner_user_id,
        email=email,
        role="viewer",
        organization_name="TI Test Org",
    )
    invite_token = notifier.sent[0].token
    await fixture_engine.dispose()

    member_token = await _register(client, email)
    r = await client.post(
        "/api/v1/invitations/accept",
        json={"token": invite_token},
        headers={"Authorization": f"Bearer {member_token}"},
    )
    assert r.status_code == 200, r.text
    r = await client.post(
        f"/api/v1/auth/organizations/{org_id}/select",
        headers={"Authorization": f"Bearer {member_token}"},
    )
    scoped_token = r.json()["access_token"]
    return {"Authorization": f"Bearer {scoped_token}"}


# ─── Provider status closed-set & config ───────────────────────────────────


async def test_list_providers_returns_full_closed_set_all_disabled(client: AsyncClient) -> None:
    _org_id, owner = await _owner_context(client)
    r = await client.get("/api/v1/threat-intel/providers", headers=owner)
    assert r.status_code == 200, r.text
    rows = r.json()
    names = {row["provider_name"] for row in rows}
    assert names == {
        "abuseipdb",
        "alienvault_otx",
        "spamhaus_drop",
        "rdap",
        "maxmind_geolite_local",
        "ipinfo_lite",
        "greynoise_community",
        "abusech",
    }
    assert all(row["enabled"] is False for row in rows)
    # Optional-adapter disclaimer is flagged on exactly the two providers
    # the decision matrix marks as quota/licensing-ambiguous.
    optional = {row["provider_name"] for row in rows if row["is_optional_disclaimer_required"]}
    assert optional == {"greynoise_community", "abusech"}


async def test_configure_unknown_provider_is_422(client: AsyncClient) -> None:
    _org_id, owner = await _owner_context(client)
    r = await client.put(
        "/api/v1/threat-intel/providers/not-a-real-provider",
        json={"enabled": True, "allowed_indicator_types": ["ip"]},
        headers=owner,
    )
    assert r.status_code == 422, r.text


async def test_configure_invalid_indicator_type_is_422(client: AsyncClient) -> None:
    _org_id, owner = await _owner_context(client)
    r = await client.put(
        "/api/v1/threat-intel/providers/abuseipdb",
        json={"enabled": True, "allowed_indicator_types": ["not-a-type"]},
        headers=owner,
    )
    assert r.status_code == 422, r.text


async def test_configure_never_stores_secret_value(client: AsyncClient) -> None:
    """Even if a caller tries to put a secret-shaped key in `config`, it
    is dropped before persistence — same allowlist idiom as M18's
    IntegrationProviderModel."""
    _org_id, owner = await _owner_context(client)
    r = await client.put(
        "/api/v1/threat-intel/providers/abuseipdb",
        json={
            "enabled": True,
            "allowed_indicator_types": ["ip"],
            "credential_ref": "ABUSEIPDB_API_KEY",
            "config": {"api_key": "sk-should-never-be-stored", "description": "prod key"},
        },
        headers=owner,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["credential_ref"] == "ABUSEIPDB_API_KEY"  # reference only
    assert "api_key" not in body["config"]  # secret-shaped key dropped
    assert body["config"].get("description") == "prod key"  # allowlisted key kept


# ─── Tenant isolation ───────────────────────────────────────────────────────


async def test_provider_config_is_tenant_isolated(client: AsyncClient) -> None:
    _org_a, owner_a = await _owner_context(client)
    _org_b, owner_b = await _owner_context(client)

    r = await client.put(
        "/api/v1/threat-intel/providers/spamhaus_drop",
        json={"enabled": True, "allowed_indicator_types": ["ip"]},
        headers=owner_a,
    )
    assert r.status_code == 200, r.text

    r = await client.get("/api/v1/threat-intel/providers", headers=owner_b)
    row = next(x for x in r.json() if x["provider_name"] == "spamhaus_drop")
    assert row["enabled"] is False, "org B must never see org A's provider config"


# ─── RBAC ───────────────────────────────────────────────────────────────────


async def test_viewer_can_read_but_cannot_configure_or_trigger(client: AsyncClient) -> None:
    org_id, owner = await _owner_context(client)
    viewer = await _invite_viewer(client, owner, org_id)

    for path in (
        "/api/v1/threat-intel/providers",
        "/api/v1/threat-intel/health",
        "/api/v1/threat-intel/indicators",
    ):
        r = await client.get(path, headers=viewer)
        assert r.status_code == 200, f"{path}: {r.text}"

    r = await client.put(
        "/api/v1/threat-intel/providers/spamhaus_drop",
        json={"enabled": True, "allowed_indicator_types": ["ip"]},
        headers=viewer,
    )
    assert r.status_code == 403, r.text

    r = await client.post("/api/v1/threat-intel/enrich/ip/8.8.8.8", headers=viewer)
    assert r.status_code == 403, r.text

    r = await client.post("/api/v1/threat-intel/correlate", headers=viewer)
    assert r.status_code == 403, r.text


# ─── Egress gate (private IPs never contact a provider) ────────────────────


async def test_private_ip_enrichment_is_blocked_before_any_provider_call(
    client: AsyncClient,
) -> None:
    _org_id, owner = await _owner_context(client)
    # Enable every provider so a bug in the gate would be maximally
    # visible (any provider dispatch here is a bug).
    for provider in ("abuseipdb", "spamhaus_drop", "rdap", "ipinfo_lite"):
        r = await client.put(
            f"/api/v1/threat-intel/providers/{provider}",
            json={
                "enabled": True,
                "allowed_indicator_types": ["ip"],
                "credential_ref": "SOME_FAKE_ENV_VAR",
            },
            headers=owner,
        )
        assert r.status_code == 200, r.text

    for private_ip in ("10.0.0.5", "192.168.1.1", "127.0.0.1", "169.254.1.1"):
        r = await client.post(f"/api/v1/threat-intel/enrich/ip/{private_ip}", headers=owner)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["egress_decision"] == "blocked_private_address"
        assert body["reputation"] == []
        assert body["geolocation"] is None
        assert body["asn"] is None
        assert body["provider_errors"] == []

    # No indicator should have been created for a blocked private IP —
    # the gate rejects before any indicator/enrichment row is touched.
    r = await client.get("/api/v1/threat-intel/indicators", headers=owner)
    indicators = {row["indicator"] for row in r.json()}
    assert "10.0.0.5" not in indicators
    assert "192.168.1.1" not in indicators


async def test_enrichment_with_all_providers_disabled_is_honest_empty(
    client: AsyncClient,
) -> None:
    """No providers configured at all: a public IP still returns 200
    with an honest, entirely empty result — never a fabricated value,
    never a crash."""
    _org_id, owner = await _owner_context(client)
    r = await client.post("/api/v1/threat-intel/enrich/ip/93.184.216.34", headers=owner)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["egress_decision"] == "allowed"
    assert body["reputation"] == []
    assert body["geolocation"] is None
    assert body["asn"] is None


async def test_correlation_run_with_no_indicators_is_a_safe_no_op(client: AsyncClient) -> None:
    _org_id, owner = await _owner_context(client)
    r = await client.post("/api/v1/threat-intel/correlate", headers=owner)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["indicators_checked"] == 0
    assert body["matches_found"] == 0


# ─── Provider health honest defaults ────────────────────────────────────────


async def test_health_reports_not_configured_for_every_provider_by_default(
    client: AsyncClient,
) -> None:
    _org_id, owner = await _owner_context(client)
    r = await client.get("/api/v1/threat-intel/health", headers=owner)
    assert r.status_code == 200, r.text
    rows = r.json()
    assert len(rows) == 8
    assert all(row["status"] == "not_configured" for row in rows)
    assert all(row["last_success_at"] is None for row in rows)
    assert all(row["last_error_category"] is None for row in rows)
