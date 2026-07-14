"""M18 — real running app, real PostgreSQL, real HTTP adversarial +
correctness acceptance for the Security Operations Command Center.

Runs the actual FastAPI application (redforge.app.create_app, full
production dependency wiring) over httpx.AsyncClient + ASGITransport
with the app's own lifespan_context() — the exact harness M17's own
live-acceptance proof uses (see test_rbac_live_acceptance.py). Every
scenario is a REAL HTTP round trip against a REAL database; nothing is
mocked. Aggregation/behavior fixtures insert real rows directly via a
fixture engine (using the same ORM models the production code reads),
exercising the read/aggregation logic without driving the heavy M16
orchestrator.

Runs against a DEDICATED, isolated proof database
(`redforge_command_center_proof_test`) — NOT the shared `redforge_test`
used by the wider suite — created + `alembic upgrade head`'d before the
run, so the full app's background schedulers can never race against
another test file's leftover due policies.
"""

from __future__ import annotations

import asyncio
import os
import time
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select

from redforge.domain.inventory.entity import AIAsset
from redforge.domain.inventory.value_objects import AssetDiscoverySource, AssetType
from redforge.infrastructure.database.models.command_center import (
    IntegrationProviderModel,
    NetworkZoneAssignmentModel,
)
from redforge.infrastructure.database.models.network_security import (
    NetworkDriftEventModel,
    NetworkMonitoringPolicyModel,
    NetworkObservationModel,
    NetworkValidationRunModel,
)
from redforge.infrastructure.database.models.rbac import OrganizationAdminAuditLogModel
from redforge.infrastructure.database.repositories.asset_repository import SqlAlchemyAssetRepository
from redforge.infrastructure.database.repositories.security_condition_repository import (
    SecurityConditionRepository,
)
from redforge.infrastructure.database.repositories.security_correlation_repository import (
    SecurityCorrelationRepository,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

pytestmark = pytest.mark.asyncio(loop_scope="module")

_TEST_DB_NAME = "redforge_command_center_proof_test"
_DB_URL = os.environ.get(
    "REDFORGE_COMMAND_CENTER_TEST_DATABASE_URL",
    f"postgresql+asyncpg://redforge:redforge@localhost:5432/{_TEST_DB_NAME}",
)


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def client():
    """One shared app/lifespan for the whole module (mirrors M17's
    harness): spinning up one full app instance with its background
    workers, disabling only the per-IP register rate limiter (unit-
    tested elsewhere; not part of M18's surface) so this file's many
    real registrations from one test-process IP are not throttled."""
    from unittest.mock import patch

    from redforge.app import create_app
    from redforge.core.config import Settings
    from redforge.infrastructure.rate_limiting.contracts import RateLimitResult
    from redforge.infrastructure.rate_limiting.sliding_window import (
        InMemorySlidingWindowLimiter,
    )

    async def _always_allow(
        self: object, key: str, max_requests: int, window_seconds: int,
    ) -> RateLimitResult:
        return RateLimitResult(
            allowed=True, remaining=max_requests, limit=max_requests, retry_after_seconds=0,
        )

    with patch.object(InMemorySlidingWindowLimiter, "check", _always_allow):
        app = create_app(settings=Settings(database_url=_DB_URL))
        async with app.router.lifespan_context(app):
            transport = ASGITransport(app=app, raise_app_exceptions=False)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                yield c


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def seed_factory():
    """A fixture-owned async_sessionmaker on the SAME proof DB for
    inserting real rows directly (no HTTP), used to exercise the
    read/aggregation surfaces deterministically."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine(_DB_URL, echo=False)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


# ─── HTTP helpers (verbatim from the proven M17 harness) ───────────────────


def _unique(prefix: str) -> str:
    return f"{prefix}-{time.time_ns()}"


async def _register(client: AsyncClient, email: str) -> str:
    r = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "display_name": "M18 Test User", "password": "SecureP@ss123"},
    )
    assert r.status_code == 201, r.text
    return r.json()["access_token"]


async def _create_org_and_select(client: AsyncClient, token: str, slug: str) -> tuple[str, str]:
    r = await client.post(
        "/api/v1/organizations",
        json={"name": "M18 Test Org", "slug": slug},
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


async def _owner_context(client: AsyncClient) -> tuple[str, str, dict[str, str]]:
    unique = _unique("owner")
    token = await _register(client, f"{unique}@example.test")
    org_id, scoped = await _create_org_and_select(client, token, _unique("org"))
    r = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {scoped}"})
    user_id = r.json()["user_id"]
    return org_id, user_id, {"Authorization": f"Bearer {scoped}"}


async def _invite_member(
    client: AsyncClient, owner_headers: dict[str, str], org_id: str, role: str,
) -> tuple[str, dict[str, str]]:
    """Real invitation -> register -> accept -> role-change flow (mirrors
    the M17 precedent) producing a second real member with the given
    MembershipRole, distinct from the OWNER."""
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
        fixture_session_factory, InMemoryEventPublisher(), InMemoryAuditLog(), notifier,
    )
    r = await client.get("/api/v1/auth/me", headers=owner_headers)
    owner_user_id = r.json()["user_id"]
    unique = _unique("member")
    email = f"{unique}@example.test"
    await invitation_service.invite(
        organization_id=org_id, invited_by_user_id=owner_user_id, email=email,
        role="member", organization_name="M18 Test Org",
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
    r = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {scoped_token}"})
    member_user_id = r.json()["user_id"]

    r = await client.get(f"/api/v1/organizations/{org_id}/members", headers=owner_headers)
    membership_id = next(m["id"] for m in r.json() if m["user_id"] == member_user_id)
    if role != "member":
        r = await client.patch(
            f"/api/v1/organizations/{org_id}/members/{membership_id}/role",
            json={"role": role}, headers=owner_headers,
        )
        assert r.status_code == 200, r.text
        r = await client.post(
            f"/api/v1/auth/organizations/{org_id}/select",
            headers={"Authorization": f"Bearer {member_token}"},
        )
        scoped_token = r.json()["access_token"]

    return member_user_id, {"Authorization": f"Bearer {scoped_token}"}


# ─── Direct-DB seeding helpers (real ORM models on the proof DB) ────────────


async def _seed_asset(
    factory: async_sessionmaker[AsyncSession], org_id: str, name: str,
    asset_type: AssetType = AssetType.HOST,
) -> str:
    asset = AIAsset.discover(
        organization_id=EntityId.from_string(org_id),
        asset_type=asset_type,
        name=name,
        description="seeded for M18 proof",
        fingerprint_fields={"name": name, "nonce": _unique("fp")},
        external_id=_unique("ext"),
        discovery_source=AssetDiscoverySource.MANUAL,
    )
    async with factory() as session:
        await SqlAlchemyAssetRepository(session).save(asset)
        await session.commit()
    return str(asset.id)


async def _seed_condition(
    factory: async_sessionmaker[AsyncSession], org_id: str, asset_id: str,
    severity: str, *, resolved: bool = False,
) -> str:
    condition_id = str(EntityId.generate())
    async with factory() as session:
        repo = SecurityConditionRepository(session)
        model = await repo.upsert(
            condition_id=condition_id, organization_id=org_id, affected_asset_id=asset_id,
            source_category="network_security", stable_rule_id="rule.m18.test",
            qualifier="", identity_key=_unique("cond"), evidence_state="confirmed",
            severity=severity, title="Seeded condition", summary="s", remediation="",
            canonical_references=[], evidence=[{"kind": "seed"}],
        )
        if resolved:
            model.lifecycle = "resolved"
            await session.flush()
        await session.commit()
    return condition_id


async def _seed_correlation(
    factory: async_sessionmaker[AsyncSession], org_id: str, *, resolved: bool = False,
) -> str:
    correlation_id = str(EntityId.generate())
    async with factory() as session:
        repo = SecurityCorrelationRepository(session)
        model = await repo.upsert(
            correlation_id=correlation_id, organization_id=org_id,
            stable_rule_id="corr.m18.test", rule_version=1, identity_key=_unique("corr"),
            evidence_state="confirmed", title="Seeded correlation", summary="s",
            operator_action="", condition_ids=[], entity_ids=[],
        )
        if resolved:
            model.lifecycle = "resolved"
            await session.flush()
        await session.commit()
    return correlation_id


async def _seed_run(
    factory: async_sessionmaker[AsyncSession], org_id: str, target_asset_id: str,
) -> str:
    """A completed NetworkValidationRun row. Both network_observations and
    network_drift_events carry a same-tenant FK to (run_id, organization_id)
    in the migrated schema, so aggregation/drift rows need a real run."""
    run_id = str(EntityId.generate())
    now = utc_now()
    async with factory() as session:
        session.add(
            NetworkValidationRunModel(
                id=run_id, organization_id=org_id, target_asset_id=target_asset_id,
                requester_user_id=str(EntityId.generate()), profile="network_baseline",
                status="completed", trigger="manual", continuous_policy_id=None,
                failure_reason="", cancellation_requested=False,
                created_at=now, updated_at=now,
            )
        )
        await session.commit()
    return run_id


async def _seed_observation(
    factory: async_sessionmaker[AsyncSession], org_id: str, asset_id: str, run_id: str,
    *, observation_type: str, outcome: str, data: dict[str, str], observed_at: datetime,
) -> None:
    async with factory() as session:
        session.add(
            NetworkObservationModel(
                id=str(EntityId.generate()), organization_id=org_id, run_id=run_id,
                asset_id=asset_id, observation_type=observation_type, method="tcp_connect",
                outcome=outcome, schema_version=1, data=data, observed_at=observed_at,
            )
        )
        await session.commit()


async def _seed_policy(
    factory: async_sessionmaker[AsyncSession], org_id: str, target_asset_id: str,
) -> str:
    """A DISABLED monitoring policy (lifecycle != active, no next_due_at)
    so the running app's scheduler never claims it — it exists only to
    satisfy the network_drift_events composite FK."""
    policy_id = str(EntityId.generate())
    now = utc_now()
    async with factory() as session:
        session.add(
            NetworkMonitoringPolicyModel(
                id=policy_id, organization_id=org_id, target_asset_id=target_asset_id,
                requester_user_id=str(EntityId.generate()), profile="network_baseline",
                cadence="daily", lifecycle="disabled", next_due_at=None,
                created_at=now, updated_at=now,
            )
        )
        await session.commit()
    return policy_id


async def _seed_drift(
    factory: async_sessionmaker[AsyncSession], org_id: str, policy_id: str, run_id: str,
    *, category: str, summary: str, detected_at: datetime | None = None,
) -> str:
    drift_id = str(EntityId.generate())
    async with factory() as session:
        session.add(
            NetworkDriftEventModel(
                id=drift_id, organization_id=org_id, policy_id=policy_id,
                run_id=run_id, category=category,
                identity_key=_unique("ik"), summary=summary, detail={"seed": "true"},
                detected_at=detected_at or utc_now(),
            )
        )
        await session.commit()
    return drift_id


async def _seed_audit(
    factory: async_sessionmaker[AsyncSession], org_id: str, actor_id: str, action: str,
) -> str:
    target_id = str(EntityId.generate())
    async with factory() as session:
        session.add(
            OrganizationAdminAuditLogModel(
                id=str(EntityId.generate()), organization_id=org_id, actor_id=actor_id,
                action=action, target_type="seed_target", target_id=target_id,
                metadata_={}, occurred_at=utc_now(),
            )
        )
        await session.commit()
    return target_id


# ─── Overview: deterministic posture, high-risk assets, inventory ──────────


async def test_overview_posture_is_deterministic_and_explainable(
    client: AsyncClient, seed_factory,
) -> None:
    org_id, _uid, owner = await _owner_context(client)
    asset_id = await _seed_asset(seed_factory, org_id, "posture-host")
    # 1 critical + 2 high + 1 medium ACTIVE conditions on one asset (=> high risk),
    # plus one RESOLVED critical (must be excluded), plus one ACTIVE correlation.
    await _seed_condition(seed_factory, org_id, asset_id, "critical")
    await _seed_condition(seed_factory, org_id, asset_id, "high")
    await _seed_condition(seed_factory, org_id, asset_id, "high")
    await _seed_condition(seed_factory, org_id, asset_id, "medium")
    await _seed_condition(seed_factory, org_id, asset_id, "critical", resolved=True)
    await _seed_correlation(seed_factory, org_id)
    await _seed_correlation(seed_factory, org_id, resolved=True)  # excluded

    r = await client.get("/api/v1/command-center/overview", headers=owner)
    assert r.status_code == 200, r.text
    body = r.json()

    # critical 1*15=15, high 2*8=16, medium 1*3=3, correlation 1*10=10 => 44.
    assert body["posture_total_deduction"] == 44
    assert body["posture_score"] == 56
    assert body["posture_band"] == "at_risk"
    assert body["posture_formula_version"] == "1.0.0"
    assert body["active_condition_count"] == 4  # resolved critical excluded
    assert body["active_correlation_count"] == 1  # resolved correlation excluded
    assert body["active_conditions_by_severity"] == {"critical": 1, "high": 2, "medium": 1}

    by_factor = {c["factor"]: c for c in body["posture_contributions"]}
    assert by_factor["active_conditions:critical"]["deduction"] == 15
    assert by_factor["active_conditions:high"]["deduction"] == 16
    assert by_factor["active_conditions:medium"]["deduction"] == 3
    assert by_factor["active_correlations"]["deduction"] == 10

    # High-risk asset with its real active-condition count; inventory reflects the asset.
    hra = {a["asset_id"]: a for a in body["high_risk_assets"]}
    assert asset_id in hra
    assert hra[asset_id]["active_condition_count"] == 4
    assert hra[asset_id]["asset_type"] == "host"
    assert body["asset_inventory_by_type"].get("host") == 1
    assert body["total_assets"] == 1
    assert isinstance(body["zone_counts"], dict)


async def test_overview_tenant_isolation(client: AsyncClient, seed_factory) -> None:
    org_a, _uid_a, owner_a = await _owner_context(client)
    _org_b, _uid_b, owner_b = await _owner_context(client)
    asset_a = await _seed_asset(seed_factory, org_a, "a-host")
    # Org A: two criticals on one asset (high-risk). Org B: nothing.
    await _seed_condition(seed_factory, org_a, asset_a, "critical")
    await _seed_condition(seed_factory, org_a, asset_a, "critical")

    ra = await client.get("/api/v1/command-center/overview", headers=owner_a)
    rb = await client.get("/api/v1/command-center/overview", headers=owner_b)
    body_a, body_b = ra.json(), rb.json()

    assert body_a["active_condition_count"] == 2
    assert asset_a in {a["asset_id"] for a in body_a["high_risk_assets"]}

    # Org B is pristine: perfect score, no conditions, no high-risk assets, no assets.
    assert body_b["posture_score"] == 100
    assert body_b["active_condition_count"] == 0
    assert body_b["high_risk_assets"] == []
    assert asset_a not in {a["asset_id"] for a in body_b["high_risk_assets"]}
    assert body_b["total_assets"] == 0


# ─── Behavior analytics (UEBA / HBA / NBA) ─────────────────────────────────


async def test_behavior_ueba_volume_and_privilege_signals(
    client: AsyncClient, seed_factory,
) -> None:
    org_id, _uid, owner = await _owner_context(client)
    actor = str(EntityId.generate())
    # 12 privilege-change actions by one actor: fires BOTH the per-actor
    # volume rule (>=10 => warning) and the org-wide privilege rule (>=5).
    target_ids = []
    for _ in range(12):
        target_ids.append(
            await _seed_audit(seed_factory, org_id, actor, "rbac.group_member_added")
        )

    r = await client.get("/api/v1/command-center/behavior?domain=user", headers=owner)
    assert r.status_code == 200, r.text
    signals = r.json()

    volume = [s for s in signals if s["signal_type"] == "elevated_admin_action_volume"]
    assert len(volume) == 1
    v = volume[0]
    assert v["domain"] == "user"
    assert v["subject"] == actor
    assert v["severity"] == "warning"  # 12 < 25 (HIGH band)
    assert v["evidence_count"] == 12
    assert len(v["evidence"]) > 0
    assert all(e["source"] == "organization_admin_audit_log" for e in v["evidence"])
    assert all(e["source_id"] for e in v["evidence"])
    assert {e["source_id"] for e in v["evidence"]} <= set(target_ids)

    priv = [s for s in signals if s["signal_type"] == "elevated_privilege_change_activity"]
    assert len(priv) == 1
    p = priv[0]
    assert p["subject"] == org_id
    assert p["severity"] == "warning"
    assert p["evidence_count"] == 12
    assert len(p["evidence"]) > 0
    assert all(e["source_id"] for e in p["evidence"])


async def test_behavior_thresholds_are_strict(client: AsyncClient, seed_factory) -> None:
    """Below the documented thresholds NOTHING is emitted (no fabricated
    signal): 9 non-privilege actions by one actor (< volume 10) and 4
    privilege actions org-wide (< privilege 5) => zero user signals."""
    org_id, _uid, owner = await _owner_context(client)
    actor_b = str(EntityId.generate())
    actor_c = str(EntityId.generate())
    for _ in range(9):
        await _seed_audit(seed_factory, org_id, actor_b, "provider.registered")  # not privilege
    for _ in range(4):
        await _seed_audit(seed_factory, org_id, actor_c, "rbac.role_created")  # privilege, < 5

    r = await client.get("/api/v1/command-center/behavior?domain=user", headers=owner)
    assert r.status_code == 200, r.text
    assert r.json() == []


async def test_behavior_hba_nba_signals_link_to_drift(
    client: AsyncClient, seed_factory,
) -> None:
    org_id, _uid, owner = await _owner_context(client)
    asset_id = await _seed_asset(seed_factory, org_id, "drift-host")
    policy_id = await _seed_policy(seed_factory, org_id, asset_id)
    run_id = await _seed_run(seed_factory, org_id, asset_id)
    # HBA (host domain): 2 port_became_reachable. NBA (network): 1 tls change.
    d1 = await _seed_drift(
        seed_factory, org_id, policy_id, run_id,
        category="port_became_reachable", summary="443 open",
    )
    d2 = await _seed_drift(
        seed_factory, org_id, policy_id, run_id,
        category="port_became_reachable", summary="8443 open",
    )
    d3 = await _seed_drift(
        seed_factory, org_id, policy_id, run_id,
        category="tls_certificate_changed", summary="cert rotated",
    )

    # HOST domain
    r = await client.get("/api/v1/command-center/behavior?domain=host", headers=owner)
    assert r.status_code == 200, r.text
    host_signals = r.json()
    appeared = [s for s in host_signals if s["signal_type"] == "service_appeared"]
    assert len(appeared) == 1
    s = appeared[0]
    assert s["domain"] == "host"
    assert s["subject"] == "port_became_reachable"
    assert s["severity"] == "warning"
    assert s["evidence_count"] == 2
    assert all(e["source"] == "network_drift_events" for e in s["evidence"])
    assert {e["source_id"] for e in s["evidence"]} == {d1, d2}

    # NETWORK domain
    r = await client.get("/api/v1/command-center/behavior?domain=network", headers=owner)
    net_signals = r.json()
    tls = [s for s in net_signals if s["signal_type"] == "tls_certificate_changed"]
    assert len(tls) == 1
    assert tls[0]["evidence_count"] == 1
    assert tls[0]["evidence"][0]["source_id"] == d3

    # No-domain query merges all three lenses; every signal has real evidence.
    r = await client.get("/api/v1/command-center/behavior", headers=owner)
    all_signals = r.json()
    domains = {s["domain"] for s in all_signals}
    assert {"host", "network"} <= domains
    assert all(s["evidence_count"] > 0 for s in all_signals)
    assert all(len(s["evidence"]) > 0 for s in all_signals)


async def test_behavior_tenant_isolation(client: AsyncClient, seed_factory) -> None:
    org_a, _a, owner_a = await _owner_context(client)
    _org_b, _b, owner_b = await _owner_context(client)
    actor_a = str(EntityId.generate())
    for _ in range(11):
        await _seed_audit(seed_factory, org_a, actor_a, "rbac.role_created")

    ra = await client.get("/api/v1/command-center/behavior?domain=user", headers=owner_a)
    rb = await client.get("/api/v1/command-center/behavior?domain=user", headers=owner_b)

    subjects_a = {s["subject"] for s in ra.json()}
    assert actor_a in subjects_a
    # Org B never sees org A's actor volume signal.
    assert rb.json() == []
    assert actor_a not in {s["subject"] for s in rb.json()}


# ─── Integration boundaries ─────────────────────────────────────────────────


async def test_integrations_fresh_org_all_six_not_configured(client: AsyncClient) -> None:
    _org, _uid, owner = await _owner_context(client)
    r = await client.get("/api/v1/command-center/integrations", headers=owner)
    assert r.status_code == 200, r.text
    rows = r.json()
    assert len(rows) == 6
    types = {row["integration_type"] for row in rows}
    assert types == {
        "firewall", "network_telemetry", "connectivity",
        "backup_dr", "threat_intel", "geolocation",
    }
    assert all(row["status"] == "not_configured" for row in rows)
    assert all(row["provider_name"] is None for row in rows)
    assert all(row["last_telemetry_at"] is None for row in rows)


async def test_integration_register_strips_secrets_and_is_never_active(
    client: AsyncClient, seed_factory,
) -> None:
    org_id, _uid, owner = await _owner_context(client)
    r = await client.put(
        "/api/v1/command-center/integrations/firewall",
        json={
            "provider_name": "PaloAlto",
            "config": {
                "endpoint": "https://fw.example",
                "region": "us-east-1",
                "account_ref": "acct-1",
                "api_token": "SUPERSEKRET",
                "password": "hunter2",
                "unexpected": "dropme",
            },
        },
        headers=owner,
    )
    assert r.status_code == 200, r.text
    dto = r.json()
    # NEVER active on registration — only ever awaiting_telemetry.
    assert dto["status"] == "awaiting_telemetry"
    assert dto["provider_name"] == "PaloAlto"
    assert dto["last_telemetry_at"] is None

    # GET reflects the new state; the other five remain not_configured.
    r = await client.get("/api/v1/command-center/integrations", headers=owner)
    rows = {row["integration_type"]: row for row in r.json()}
    assert rows["firewall"]["status"] == "awaiting_telemetry"
    assert rows["firewall"]["provider_name"] == "PaloAlto"
    assert rows["network_telemetry"]["status"] == "not_configured"

    # The persisted config dropped every secret/unknown key — verify at the DB.
    async with seed_factory() as session:
        model = (
            await session.execute(
                select(IntegrationProviderModel).where(
                    IntegrationProviderModel.organization_id == org_id,
                    IntegrationProviderModel.integration_type == "firewall",
                )
            )
        ).scalar_one()
    assert model.config == {
        "endpoint": "https://fw.example", "region": "us-east-1", "account_ref": "acct-1",
    }
    serialized = str(model.config)
    assert "SUPERSEKRET" not in serialized
    assert "hunter2" not in serialized
    assert "dropme" not in serialized
    # Status persisted is never active.
    assert model.status == "awaiting_telemetry"


async def test_integration_delete_returns_to_not_configured(client: AsyncClient) -> None:
    _org, _uid, owner = await _owner_context(client)
    r = await client.put(
        "/api/v1/command-center/integrations/threat_intel",
        json={"provider_name": "VirusTotal", "config": None}, headers=owner,
    )
    assert r.status_code == 200 and r.json()["status"] == "awaiting_telemetry"

    r = await client.delete("/api/v1/command-center/integrations/threat_intel", headers=owner)
    assert r.status_code == 200
    assert r.json() == {"removed": True}

    r = await client.get("/api/v1/command-center/integrations", headers=owner)
    rows = {row["integration_type"]: row for row in r.json()}
    assert rows["threat_intel"]["status"] == "not_configured"
    assert rows["threat_intel"]["provider_name"] is None

    # Deleting an already-absent integration is a safe no-op, not a 500.
    r = await client.delete("/api/v1/command-center/integrations/threat_intel", headers=owner)
    assert r.status_code == 200
    assert r.json() == {"removed": False}


async def test_integration_unknown_type_is_422(client: AsyncClient) -> None:
    _org, _uid, owner = await _owner_context(client)
    r = await client.put(
        "/api/v1/command-center/integrations/quantum_teleporter",
        json={"provider_name": "Acme"}, headers=owner,
    )
    assert r.status_code == 422, r.text


# ─── Network zones / DMZ ─────────────────────────────────────────────────────


async def test_zones_assign_list_overview_and_unassign(
    client: AsyncClient, seed_factory,
) -> None:
    org_id, _uid, owner = await _owner_context(client)
    asset_id = await _seed_asset(seed_factory, org_id, "dmz-host")
    # Give the asset an active condition so the DMZ overview shows the real count.
    await _seed_condition(seed_factory, org_id, asset_id, "high")

    r = await client.post(
        "/api/v1/command-center/zones",
        json={"asset_id": asset_id, "zone_type": "dmz", "note": "edge web server"},
        headers=owner,
    )
    assert r.status_code == 201, r.text
    assign = r.json()
    assert assign["zone_type"] == "dmz"
    assert assign["asset_id"] == asset_id
    assert assign["note"] == "edge web server"
    assert assign["asset_name"] == "dmz-host"

    # /zones list reflects it.
    r = await client.get("/api/v1/command-center/zones?zone_type=dmz", headers=owner)
    assert r.status_code == 200
    rows = r.json()
    assert any(row["asset_id"] == asset_id and row["zone_type"] == "dmz" for row in rows)

    # /zones/overview: all 7 keys present, dmz count 1, dmz_assets carries condition count.
    r = await client.get("/api/v1/command-center/zones/overview", headers=owner)
    assert r.status_code == 200
    overview = r.json()
    assert set(overview["counts_by_zone"].keys()) == {
        "internet_edge", "dmz", "internal", "management", "cloud", "restricted", "unknown",
    }
    assert overview["counts_by_zone"]["dmz"] == 1
    assert overview["counts_by_zone"]["internal"] == 0
    dmz = {a["asset_id"]: a for a in overview["dmz_assets"]}
    assert asset_id in dmz
    assert dmz[asset_id]["active_condition_count"] == 1

    # Unassign works and returns to unknown.
    r = await client.delete(f"/api/v1/command-center/zones/{asset_id}", headers=owner)
    assert r.status_code == 200 and r.json() == {"removed": True}
    r = await client.get("/api/v1/command-center/zones/overview", headers=owner)
    assert r.json()["counts_by_zone"]["dmz"] == 0
    # Idempotent no-op on second unassign.
    r = await client.delete(f"/api/v1/command-center/zones/{asset_id}", headers=owner)
    assert r.status_code == 200 and r.json() == {"removed": False}


async def test_zones_reassignment_updates_in_place(client: AsyncClient, seed_factory) -> None:
    """An asset is in at most one zone; re-assigning replaces, never
    duplicates (the (organization_id, asset_id) unique row)."""
    org_id, _uid, owner = await _owner_context(client)
    asset_id = await _seed_asset(seed_factory, org_id, "reassign-host")

    r = await client.post(
        "/api/v1/command-center/zones",
        json={"asset_id": asset_id, "zone_type": "internal", "note": ""}, headers=owner,
    )
    assert r.status_code == 201
    r = await client.post(
        "/api/v1/command-center/zones",
        json={"asset_id": asset_id, "zone_type": "management", "note": ""}, headers=owner,
    )
    assert r.status_code == 201

    async with seed_factory() as session:
        count = (
            await session.execute(
                select(func.count(NetworkZoneAssignmentModel.id)).where(
                    NetworkZoneAssignmentModel.organization_id == org_id,
                    NetworkZoneAssignmentModel.asset_id == asset_id,
                )
            )
        ).scalar_one()
    assert count == 1
    r = await client.get("/api/v1/command-center/zones", headers=owner)
    rows = [row for row in r.json() if row["asset_id"] == asset_id]
    assert len(rows) == 1
    assert rows[0]["zone_type"] == "management"


async def test_zones_unknown_zone_type_is_422(client: AsyncClient, seed_factory) -> None:
    org_id, _uid, owner = await _owner_context(client)
    asset_id = await _seed_asset(seed_factory, org_id, "bad-zone-host")
    r = await client.post(
        "/api/v1/command-center/zones",
        json={"asset_id": asset_id, "zone_type": "outer_space", "note": ""}, headers=owner,
    )
    assert r.status_code == 422, r.text


async def test_zones_nonexistent_asset_is_404(client: AsyncClient) -> None:
    _org, _uid, owner = await _owner_context(client)
    r = await client.post(
        "/api/v1/command-center/zones",
        json={"asset_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV", "zone_type": "dmz", "note": ""},
        headers=owner,
    )
    assert r.status_code == 404, r.text


async def test_zones_cross_tenant_asset_is_404(client: AsyncClient, seed_factory) -> None:
    """Org B cannot zone-classify org A's asset — the composite FK makes
    it invisible; the service resolves it to a 404, never a leak."""
    org_a, _a, _owner_a = await _owner_context(client)
    _org_b, _b, owner_b = await _owner_context(client)
    asset_a = await _seed_asset(seed_factory, org_a, "a-only-host")

    r = await client.post(
        "/api/v1/command-center/zones",
        json={"asset_id": asset_a, "zone_type": "dmz", "note": ""}, headers=owner_b,
    )
    assert r.status_code == 404, r.text


async def test_zones_tenant_isolation(client: AsyncClient, seed_factory) -> None:
    org_a, _a, owner_a = await _owner_context(client)
    org_b, _b, owner_b = await _owner_context(client)
    asset_a = await _seed_asset(seed_factory, org_a, "iso-a-host")
    asset_b = await _seed_asset(seed_factory, org_b, "iso-b-host")
    await client.post(
        "/api/v1/command-center/zones",
        json={"asset_id": asset_a, "zone_type": "dmz", "note": ""}, headers=owner_a,
    )
    await client.post(
        "/api/v1/command-center/zones",
        json={"asset_id": asset_b, "zone_type": "restricted", "note": ""}, headers=owner_b,
    )

    ra = await client.get("/api/v1/command-center/zones", headers=owner_a)
    rb = await client.get("/api/v1/command-center/zones", headers=owner_b)
    ids_a = {row["asset_id"] for row in ra.json()}
    ids_b = {row["asset_id"] for row in rb.json()}
    assert asset_a in ids_a and asset_b not in ids_a
    assert asset_b in ids_b and asset_a not in ids_b

    ov_a = await client.get("/api/v1/command-center/zones/overview", headers=owner_a)
    assert ov_a.json()["counts_by_zone"]["dmz"] == 1
    assert ov_a.json()["counts_by_zone"]["restricted"] == 0


# ─── Network exposure: top-ports + service-exposure aggregation ────────────


async def test_top_ports_aggregation_correctness(client: AsyncClient, seed_factory) -> None:
    org_id, _uid, owner = await _owner_context(client)
    asset1 = await _seed_asset(seed_factory, org_id, "ports-host-1")
    asset2 = await _seed_asset(seed_factory, org_id, "ports-host-2")
    run_id = await _seed_run(seed_factory, org_id, asset1)
    base = utc_now()

    # Port 443: asset1 x2, asset2 x1 => asset_count 2, observation_count 3.
    await _seed_observation(
        seed_factory, org_id, asset1, run_id, observation_type="tcp_reachability",
        outcome="reachable", data={"port": "443", "reachable": "true"}, observed_at=base,
    )
    await _seed_observation(
        seed_factory, org_id, asset1, run_id, observation_type="tcp_reachability",
        outcome="reachable", data={"port": "443", "reachable": "true"},
        observed_at=base + timedelta(minutes=5),
    )
    await _seed_observation(
        seed_factory, org_id, asset2, run_id, observation_type="tcp_reachability",
        outcome="reachable", data={"port": "443", "reachable": "true"},
        observed_at=base + timedelta(minutes=2),
    )
    # Port 22: asset1 x1 => asset_count 1, observation_count 1.
    await _seed_observation(
        seed_factory, org_id, asset1, run_id, observation_type="tcp_reachability",
        outcome="reachable", data={"port": "22", "reachable": "true"},
        observed_at=base + timedelta(minutes=1),
    )

    r = await client.get("/api/v1/network-security/top-ports", headers=owner)
    assert r.status_code == 200, r.text
    rows = r.json()
    by_port = {row["port"]: row for row in rows}
    assert 443 in by_port and 22 in by_port
    assert by_port[443]["asset_count"] == 2
    assert by_port[443]["observation_count"] == 3
    assert by_port[443]["transport"] == "tcp"
    assert by_port[22]["asset_count"] == 1
    assert by_port[22]["observation_count"] == 1
    # Ordered by asset_count desc => 443 (2) before 22 (1).
    ports_in_order = [row["port"] for row in rows]
    assert ports_in_order.index(443) < ports_in_order.index(22)

    # Drill-down: which assets have port 443 reachable, and their counts.
    r = await client.get("/api/v1/network-security/top-ports/443/assets", headers=owner)
    assert r.status_code == 200
    drill = {row["asset_id"]: row for row in r.json()}
    assert set(drill.keys()) == {asset1, asset2}
    assert drill[asset1]["observation_count"] == 2
    assert drill[asset2]["observation_count"] == 1


async def test_top_ports_excludes_unreachable_and_other_types(
    client: AsyncClient, seed_factory,
) -> None:
    org_id, _uid, owner = await _owner_context(client)
    asset = await _seed_asset(seed_factory, org_id, "excl-host")
    run_id = await _seed_run(seed_factory, org_id, asset)
    now = utc_now()
    # An unreachable tcp probe and a non-tcp_reachability observation must
    # both be excluded from the open-ports aggregate.
    await _seed_observation(
        seed_factory, org_id, asset, run_id, observation_type="tcp_reachability",
        outcome="unreachable", data={"port": "9999", "reachable": "false"}, observed_at=now,
    )
    await _seed_observation(
        seed_factory, org_id, asset, run_id, observation_type="protocol_validation",
        outcome="validated",
        data={"port": "8443", "validated_protocol": "https", "validator_id": "http"},
        observed_at=now,
    )

    r = await client.get("/api/v1/network-security/top-ports", headers=owner)
    ports = {row["port"] for row in r.json()}
    assert 9999 not in ports  # unreachable excluded
    assert 8443 not in ports  # wrong observation_type excluded

    r = await client.get("/api/v1/network-security/top-ports/9999/assets", headers=owner)
    assert r.status_code == 200 and r.json() == []


async def test_service_exposure_groups_by_validated_protocol(
    client: AsyncClient, seed_factory,
) -> None:
    org_id, _uid, owner = await _owner_context(client)
    asset1 = await _seed_asset(seed_factory, org_id, "svc-host-1")
    asset2 = await _seed_asset(seed_factory, org_id, "svc-host-2")
    run_id = await _seed_run(seed_factory, org_id, asset1)
    now = utc_now()
    # ssh: asset1 x2, asset2 x1 => asset_count 2, obs 3. http: asset1 x1.
    for i, asset in enumerate([asset1, asset1, asset2]):
        await _seed_observation(
            seed_factory, org_id, asset, run_id, observation_type="protocol_validation",
            outcome="validated",
            data={"validator_id": "ssh_validator", "validated_protocol": "ssh"},
            observed_at=now + timedelta(minutes=i),
        )
    await _seed_observation(
        seed_factory, org_id, asset1, run_id, observation_type="protocol_validation",
        outcome="validated",
        data={"validator_id": "http_validator", "validated_protocol": "http"}, observed_at=now,
    )
    # A protocol_validation with empty validated_protocol must be excluded.
    await _seed_observation(
        seed_factory, org_id, asset2, run_id, observation_type="protocol_validation",
        outcome="failed", data={"validator_id": "x", "validated_protocol": ""}, observed_at=now,
    )

    r = await client.get("/api/v1/network-security/service-exposure", headers=owner)
    assert r.status_code == 200, r.text
    by_service = {row["service"]: row for row in r.json()}
    assert set(by_service.keys()) == {"ssh", "http"}
    assert by_service["ssh"]["asset_count"] == 2
    assert by_service["ssh"]["observation_count"] == 3
    assert by_service["ssh"]["validator_id"] == "ssh_validator"
    assert by_service["http"]["asset_count"] == 1
    assert by_service["http"]["observation_count"] == 1


async def test_exposure_and_drift_tenant_isolation(client: AsyncClient, seed_factory) -> None:
    org_a, _a, owner_a = await _owner_context(client)
    org_b, _b, owner_b = await _owner_context(client)
    asset_a = await _seed_asset(seed_factory, org_a, "expo-a")
    asset_b = await _seed_asset(seed_factory, org_b, "expo-b")
    run_a = await _seed_run(seed_factory, org_a, asset_a)
    run_b = await _seed_run(seed_factory, org_b, asset_b)
    now = utc_now()
    await _seed_observation(
        seed_factory, org_a, asset_a, run_a, observation_type="tcp_reachability",
        outcome="reachable", data={"port": "8081", "reachable": "true"}, observed_at=now,
    )
    await _seed_observation(
        seed_factory, org_b, asset_b, run_b, observation_type="tcp_reachability",
        outcome="reachable", data={"port": "3389", "reachable": "true"}, observed_at=now,
    )
    policy_a = await _seed_policy(seed_factory, org_a, asset_a)
    policy_b = await _seed_policy(seed_factory, org_b, asset_b)
    drift_a = await _seed_drift(
        seed_factory, org_a, policy_a, run_a, category="protocol_changed", summary="A drift",
    )
    drift_b = await _seed_drift(
        seed_factory, org_b, policy_b, run_b, category="protocol_changed", summary="B drift",
    )

    ra = await client.get("/api/v1/network-security/top-ports", headers=owner_a)
    rb = await client.get("/api/v1/network-security/top-ports", headers=owner_b)
    ports_a = {row["port"] for row in ra.json()}
    ports_b = {row["port"] for row in rb.json()}
    assert 8081 in ports_a and 3389 not in ports_a
    assert 3389 in ports_b and 8081 not in ports_b

    da = await client.get("/api/v1/network-security/drift", headers=owner_a)
    db = await client.get("/api/v1/network-security/drift", headers=owner_b)
    ids_a = {row["id"] for row in da.json()}
    ids_b = {row["id"] for row in db.json()}
    assert drift_a in ids_a and drift_b not in ids_a
    assert drift_b in ids_b and drift_a not in ids_b


# ─── Network drift feed + M15 live-feed merge ──────────────────────────────


async def test_network_drift_feed_and_live_feed_merge(
    client: AsyncClient, seed_factory,
) -> None:
    org_id, _uid, owner = await _owner_context(client)
    asset_id = await _seed_asset(seed_factory, org_id, "merge-host")
    policy_id = await _seed_policy(seed_factory, org_id, asset_id)
    run_id = await _seed_run(seed_factory, org_id, asset_id)
    drift_id = await _seed_drift(
        seed_factory, org_id, policy_id, run_id, category="port_became_reachable",
        summary="port 443 became reachable",
    )

    # 1) Dedicated org drift feed.
    r = await client.get("/api/v1/network-security/drift", headers=owner)
    assert r.status_code == 200, r.text
    feed = r.json()
    match = [row for row in feed if row["id"] == drift_id]
    assert len(match) == 1
    assert match[0]["category"] == "port_became_reachable"
    assert match[0]["policy_id"] == policy_id
    assert match[0]["summary"] == "port 443 became reachable"

    # 2) Merged into the M15 live operations feed as source_domain network_security.
    r = await client.get("/api/v1/security-operations/changes", headers=owner)
    assert r.status_code == 200, r.text
    changes = r.json()
    merged = [
        e for e in changes
        if e["source_domain"] == "network_security" and e["event_id"] == f"network_drift:{drift_id}"
    ]
    assert len(merged) == 1
    assert merged[0]["entity_id"] == policy_id

    # Same event is reachable through the source_domain filter.
    r = await client.get(
        "/api/v1/security-operations/changes?source_domain=network_security", headers=owner,
    )
    assert any(e["event_id"] == f"network_drift:{drift_id}" for e in r.json())


# ─── RBAC enforcement ───────────────────────────────────────────────────────


async def test_viewer_can_read_everything_but_cannot_manage(
    client: AsyncClient, seed_factory,
) -> None:
    org_id, _uid, owner = await _owner_context(client)
    _viewer_id, viewer = await _invite_member(client, owner, org_id, "viewer")
    asset_id = await _seed_asset(seed_factory, org_id, "viewer-host")

    # VIEWER (SECURITY_OPERATIONS_READ + NETWORK_SECURITY_READ) can read all.
    for path in (
        "/api/v1/command-center/overview",
        "/api/v1/command-center/behavior",
        "/api/v1/command-center/integrations",
        "/api/v1/command-center/zones",
        "/api/v1/command-center/zones/overview",
        "/api/v1/network-security/top-ports",
        "/api/v1/network-security/service-exposure",
        "/api/v1/network-security/drift",
    ):
        r = await client.get(path, headers=viewer)
        assert r.status_code == 200, f"{path} -> {r.status_code}: {r.text}"

    # VIEWER cannot manage: POST /zones needs NETWORK_SECURITY_MANAGE.
    r = await client.post(
        "/api/v1/command-center/zones",
        json={"asset_id": asset_id, "zone_type": "dmz", "note": ""}, headers=viewer,
    )
    assert r.status_code == 403, r.text
    # DELETE /zones needs NETWORK_SECURITY_MANAGE.
    r = await client.delete(f"/api/v1/command-center/zones/{asset_id}", headers=viewer)
    assert r.status_code == 403
    # PUT /integrations needs ORG_MANAGE.
    r = await client.put(
        "/api/v1/command-center/integrations/firewall",
        json={"provider_name": "X"}, headers=viewer,
    )
    assert r.status_code == 403
    # DELETE /integrations needs ORG_MANAGE.
    r = await client.delete("/api/v1/command-center/integrations/firewall", headers=viewer)
    assert r.status_code == 403


async def test_owner_can_manage_zones_and_integrations(
    client: AsyncClient, seed_factory,
) -> None:
    org_id, _uid, owner = await _owner_context(client)
    asset_id = await _seed_asset(seed_factory, org_id, "owner-host")
    r = await client.post(
        "/api/v1/command-center/zones",
        json={"asset_id": asset_id, "zone_type": "cloud", "note": "prod"}, headers=owner,
    )
    assert r.status_code == 201, r.text
    r = await client.put(
        "/api/v1/command-center/integrations/backup_dr",
        json={"provider_name": "Veeam"}, headers=owner,
    )
    assert r.status_code == 200 and r.json()["status"] == "awaiting_telemetry"


async def test_suspended_member_loses_command_center_access(
    client: AsyncClient,
) -> None:
    org_id, _uid, owner = await _owner_context(client)
    member_id, member = await _invite_member(client, owner, org_id, "member")

    r = await client.get("/api/v1/command-center/overview", headers=member)
    assert r.status_code == 200, r.text

    r = await client.get(f"/api/v1/organizations/{org_id}/members", headers=owner)
    membership_id = next(m["id"] for m in r.json() if m["user_id"] == member_id)
    r = await client.post(
        f"/api/v1/organizations/{org_id}/members/{membership_id}/suspend", headers=owner,
    )
    assert r.status_code == 200, r.text

    # The suspended member's already-issued token loses access immediately
    # (live is_membership_active check), on a command-center read.
    r = await client.get("/api/v1/command-center/overview", headers=member)
    assert r.status_code in (401, 403), (
        f"suspended member must lose command-center access, got {r.status_code}"
    )


# ─── Malformed inputs / pagination bounds never 500 ────────────────────────


async def test_pagination_and_filter_bounds_are_422(client: AsyncClient) -> None:
    _org, _uid, owner = await _owner_context(client)
    # limit above the FastAPI Query cap.
    r = await client.get("/api/v1/network-security/top-ports?limit=9999", headers=owner)
    assert r.status_code == 422
    r = await client.get("/api/v1/network-security/drift?limit=9999", headers=owner)
    assert r.status_code == 422
    r = await client.get("/api/v1/command-center/zones?limit=9999", headers=owner)
    assert r.status_code == 422
    # limit below the floor.
    r = await client.get("/api/v1/network-security/drift?limit=0", headers=owner)
    assert r.status_code == 422
    # negative offset.
    r = await client.get("/api/v1/command-center/zones?offset=-1", headers=owner)
    assert r.status_code == 422
    r = await client.get("/api/v1/network-security/drift?offset=-5", headers=owner)
    assert r.status_code == 422


async def test_malformed_ids_and_values_never_500(client: AsyncClient) -> None:
    _org, _uid, owner = await _owner_context(client)
    # Unknown zone filter value on a read -> 422 (validated), never 500.
    r = await client.get("/api/v1/command-center/zones?zone_type=nonsense", headers=owner)
    assert r.status_code == 422, r.text
    # Deleting a never-assigned asset zone -> handled no-op.
    r = await client.delete(
        "/api/v1/command-center/zones/01ARZ3NDEKTSV4RRFFQ69G5FAV", headers=owner,
    )
    assert r.status_code == 200 and r.json() == {"removed": False}
    # Drill-down on a port with no observations -> empty list.
    r = await client.get("/api/v1/network-security/top-ports/65000/assets", headers=owner)
    assert r.status_code == 200 and r.json() == []
    # asset_id far exceeding the request-model max_length -> 422 (pydantic), never 500.
    r = await client.post(
        "/api/v1/command-center/zones",
        json={"asset_id": "x" * 100, "zone_type": "dmz", "note": ""}, headers=owner,
    )
    assert r.status_code == 422


# ─── Real PostgreSQL concurrency proof ─────────────────────────────────────


async def test_concurrent_zone_assignment_converges_on_one_row(
    client: AsyncClient, seed_factory,
) -> None:
    org_id, _uid, owner = await _owner_context(client)
    asset_id = await _seed_asset(seed_factory, org_id, "race-host")

    async def attempt():
        return await client.post(
            "/api/v1/command-center/zones",
            json={"asset_id": asset_id, "zone_type": "dmz", "note": ""}, headers=owner,
        )

    results = await asyncio.gather(*(attempt() for _ in range(8)), return_exceptions=True)
    statuses = [r.status_code for r in results if not isinstance(r, BaseException)]
    assert not any(isinstance(r, BaseException) for r in results), (
        f"no attempt may raise; got {[r for r in results if isinstance(r, BaseException)]}"
    )

    # The real Postgres unique constraint (organization_id, asset_id) DOES
    # its job: the assignment converges on exactly one row, never a duplicate.
    async with seed_factory() as session:
        count = (
            await session.execute(
                select(func.count(NetworkZoneAssignmentModel.id)).where(
                    NetworkZoneAssignmentModel.organization_id == org_id,
                    NetworkZoneAssignmentModel.asset_id == asset_id,
                )
            )
        ).scalar_one()
    assert count == 1, f"expected exactly one zone assignment row, found {count}"
    r = await client.get("/api/v1/command-center/zones", headers=owner)
    matching = [row for row in r.json() if row["asset_id"] == asset_id]
    assert len(matching) == 1

    # ...but every concurrent attempt must be a HANDLED outcome — a 2xx, or
    # at worst a controlled 409 (the codebase's own pattern for concurrent
    # unique-constraint contention, e.g. RBAC role/group creation). An
    # unhandled 500 is a crash and violates the M18 concurrency contract.
    assert all(s != 500 for s in statuses), f"unhandled 500(s) on concurrent assign: {statuses}"
    assert all(s in (201, 409) for s in statuses), f"unexpected statuses: {statuses}"
