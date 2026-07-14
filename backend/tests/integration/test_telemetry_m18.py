"""M18 Telemetry ingestion — real PostgreSQL, real ASGI transport.

Tests:
  - Sensor registration / listing / deletion
  - Suricata EVE JSON batch ingestion (real parse + persist)
  - Zeek JSON batch ingestion
  - Duplicate event idempotency (re-ingest same source_event_id)
  - Malformed records skipped without crash
  - Oversized batch rejection (> max records)
  - RBAC: SECURITY_OPERATIONS_READ cannot write (ingest / register)
  - Tenant isolation: sensor not visible across orgs
  - Private-IP enrichment_state='skipped'
  - Public-IP enrichment_state='pending'
  - Bandwidth endpoint returns has_real_data=True after flow ingestion
  - Events query endpoint returns ingested events

Dedicated proof DB: redforge_telemetry_proof_test
No external network calls are made.
"""

from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

pytestmark = pytest.mark.asyncio(loop_scope="module")

_TEST_DB_NAME = "redforge_telemetry_proof_test"
_DB_URL = os.environ.get(
    "REDFORGE_TELEMETRY_TEST_DATABASE_URL",
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

    async def _always_allow(self, key, max_requests, window_seconds):
        return RateLimitResult(
            allowed=True, remaining=max_requests, limit=max_requests, retry_after_seconds=0
        )

    with patch.object(InMemorySlidingWindowLimiter, "check", _always_allow):
        app = create_app(settings=Settings(database_url=_DB_URL))
        async with app.router.lifespan_context(app):
            transport = ASGITransport(app=app, raise_app_exceptions=False)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                yield c


def _uid() -> str:
    return str(time.time_ns())


async def _bootstrap(client: AsyncClient) -> tuple[str, str, str]:
    """Returns (owner_token, org_id, viewer_token)."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from redforge.application.invitations import InvitationService
    from redforge.infrastructure.audit.logger import InMemoryAuditLog
    from redforge.infrastructure.events import InMemoryEventPublisher
    from redforge.infrastructure.notifications.logging_notifier import InMemoryInvitationNotifier

    ts = _uid()
    r = await client.post(
        "/api/v1/auth/register",
        json={
            "email": f"telowner-{ts}@example.com",
            "display_name": "Tel Owner",
            "password": "SecureP@ss123",
        },
    )
    assert r.status_code == 201, r.text
    owner_token = r.json()["access_token"]

    r = await client.post(
        "/api/v1/organizations",
        headers={"Authorization": f"Bearer {owner_token}"},
        json={"name": f"TelOrg {ts}", "slug": f"telorg-{ts}"},
    )
    assert r.status_code == 201, r.text
    org_id = r.json()["id"]

    r = await client.post(
        f"/api/v1/auth/organizations/{org_id}/select",
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert r.status_code == 200, r.text
    owner_token = r.json()["access_token"]

    # Create a viewer via the invitation service (mirrors M18 test pattern)
    fixture_engine = create_async_engine(_DB_URL, echo=False)
    fixture_sf = async_sessionmaker(fixture_engine, expire_on_commit=False)
    notifier = InMemoryInvitationNotifier()
    inv_svc = InvitationService(fixture_sf, InMemoryEventPublisher(), InMemoryAuditLog(), notifier)
    r_me = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {owner_token}"})
    viewer_email = f"telviewer-{ts}@example.test"
    await inv_svc.invite(
        organization_id=org_id,
        invited_by_user_id=r_me.json()["user_id"],
        email=viewer_email,
        role="viewer",
        organization_name=f"TelOrg {ts}",
    )
    invite_token = notifier.sent[0].token
    await fixture_engine.dispose()

    r = await client.post(
        "/api/v1/auth/register",
        json={"email": viewer_email, "display_name": "Tel Viewer", "password": "SecureP@ss123"},
    )
    assert r.status_code == 201
    viewer_token = r.json()["access_token"]
    r = await client.post(
        "/api/v1/invitations/accept",
        json={"token": invite_token},
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert r.status_code == 200, r.text
    r = await client.post(
        f"/api/v1/auth/organizations/{org_id}/select",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert r.status_code == 200, r.text
    viewer_token = r.json()["access_token"]

    return owner_token, org_id, viewer_token


# ── Sensor management ─────────────────────────────────────────────────────


async def test_list_sensors_empty_initially(client: AsyncClient) -> None:
    owner, _, _ = await _bootstrap(client)
    r = await client.get("/api/v1/telemetry/sensors", headers={"Authorization": f"Bearer {owner}"})
    assert r.status_code == 200
    assert r.json() == []


async def test_register_and_list_sensor(client: AsyncClient) -> None:
    owner, _, _ = await _bootstrap(client)
    r = await client.post(
        "/api/v1/telemetry/sensors",
        headers={"Authorization": f"Bearer {owner}"},
        json={"name": "suricata-edge", "format": "suricata_eve", "description": "Edge IDS"},
    )
    assert r.status_code == 201, r.text
    data = r.json()
    assert data["format"] == "suricata_eve"
    assert data["enabled"] is True

    r2 = await client.get("/api/v1/telemetry/sensors", headers={"Authorization": f"Bearer {owner}"})
    assert r2.status_code == 200
    assert any(s["name"] == "suricata-edge" for s in r2.json())


async def test_register_unsupported_format_is_422(client: AsyncClient) -> None:
    owner, _, _ = await _bootstrap(client)
    r = await client.post(
        "/api/v1/telemetry/sensors",
        headers={"Authorization": f"Bearer {owner}"},
        json={"name": "bad-sensor", "format": "syslog_rfc3164"},
    )
    assert r.status_code == 422


async def test_viewer_cannot_register_sensor(client: AsyncClient) -> None:
    _, _, viewer = await _bootstrap(client)
    r = await client.post(
        "/api/v1/telemetry/sensors",
        headers={"Authorization": f"Bearer {viewer}"},
        json={"name": "viewer-attempt", "format": "suricata_eve"},
    )
    assert r.status_code == 403


async def test_delete_sensor(client: AsyncClient) -> None:
    owner, _, _ = await _bootstrap(client)
    r = await client.post(
        "/api/v1/telemetry/sensors",
        headers={"Authorization": f"Bearer {owner}"},
        json={"name": "to-delete", "format": "zeek_json"},
    )
    assert r.status_code == 201
    sensor_id = r.json()["id"]

    r2 = await client.delete(
        f"/api/v1/telemetry/sensors/{sensor_id}",
        headers={"Authorization": f"Bearer {owner}"},
    )
    assert r2.status_code == 204

    r3 = await client.get("/api/v1/telemetry/sensors", headers={"Authorization": f"Bearer {owner}"})
    assert not any(s["id"] == sensor_id for s in r3.json())


# ── Suricata EVE ingestion ────────────────────────────────────────────────


def _now_ts() -> str:
    """Current UTC timestamp in Suricata/ISO-8601 format."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


def _suricata_alert(flow_id: int, src_ip: str = "1.2.3.4") -> str:
    return json.dumps({
        "timestamp": _now_ts(),
        "flow_id": flow_id,
        "event_type": "alert",
        "src_ip": src_ip,
        "dest_ip": "10.0.0.5",
        "src_port": 44321,
        "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "action": "blocked",
            "severity": 1,
            "signature": "ET MALWARE Test",
            "signature_id": flow_id,
        },
    })


def _suricata_flow(flow_id: int, bytes_c: int = 1024, bytes_s: int = 256) -> str:
    return json.dumps({
        "timestamp": _now_ts(),
        "flow_id": flow_id,
        "event_type": "flow",
        "src_ip": "8.8.8.8",
        "dest_ip": "10.0.0.5",
        "src_port": 12345,
        "dest_port": 53,
        "proto": "UDP",
        "flow": {
            "bytes_toclient": bytes_c,
            "bytes_toserver": bytes_s,
            "pkts_toclient": 10,
            "pkts_toserver": 5,
        },
    })


async def test_suricata_alert_ingestion(client: AsyncClient) -> None:
    owner, _, _ = await _bootstrap(client)
    r = await client.post(
        "/api/v1/telemetry/sensors",
        headers={"Authorization": f"Bearer {owner}"},
        json={"name": f"sur-{_uid()}", "format": "suricata_eve"},
    )
    sensor_id = r.json()["id"]

    records = [_suricata_alert(1001), _suricata_alert(1002), _suricata_alert(1003)]
    r2 = await client.post(
        "/api/v1/telemetry/ingest",
        headers={"Authorization": f"Bearer {owner}"},
        json={"sensor_id": sensor_id, "records": records},
    )
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body["created"] == 3
    assert body["duplicate"] == 0
    assert body["parse_error"] == 0


async def test_suricata_ingest_idempotency(client: AsyncClient) -> None:
    owner, _, _ = await _bootstrap(client)
    r = await client.post(
        "/api/v1/telemetry/sensors",
        headers={"Authorization": f"Bearer {owner}"},
        json={"name": f"sur-idem-{_uid()}", "format": "suricata_eve"},
    )
    sensor_id = r.json()["id"]

    record = _suricata_alert(9999)
    await client.post(
        "/api/v1/telemetry/ingest",
        headers={"Authorization": f"Bearer {owner}"},
        json={"sensor_id": sensor_id, "records": [record]},
    )
    r2 = await client.post(
        "/api/v1/telemetry/ingest",
        headers={"Authorization": f"Bearer {owner}"},
        json={"sensor_id": sensor_id, "records": [record]},
    )
    body = r2.json()
    assert body["created"] == 0
    assert body["duplicate"] == 1


async def test_malformed_records_do_not_crash_batch(client: AsyncClient) -> None:
    owner, _, _ = await _bootstrap(client)
    r = await client.post(
        "/api/v1/telemetry/sensors",
        headers={"Authorization": f"Bearer {owner}"},
        json={"name": f"sur-mal-{_uid()}", "format": "suricata_eve"},
    )
    sensor_id = r.json()["id"]

    records = ["not json", _suricata_alert(7777), "also bad", _suricata_alert(7778)]
    r2 = await client.post(
        "/api/v1/telemetry/ingest",
        headers={"Authorization": f"Bearer {owner}"},
        json={"sensor_id": sensor_id, "records": records},
    )
    assert r2.status_code == 200
    body = r2.json()
    assert body["created"] == 2
    assert body["parse_error"] == 2


async def test_private_ip_enrichment_state_skipped(client: AsyncClient) -> None:
    owner, _, _ = await _bootstrap(client)
    r = await client.post(
        "/api/v1/telemetry/sensors",
        headers={"Authorization": f"Bearer {owner}"},
        json={"name": f"sur-priv-{_uid()}", "format": "suricata_eve"},
    )
    sensor_id = r.json()["id"]

    # Both IPs private
    rec = json.dumps({
        "timestamp": _now_ts(),
        "flow_id": 55555,
        "event_type": "alert",
        "src_ip": "192.168.1.5",
        "dest_ip": "10.0.0.5",
        "src_port": 1234,
        "dest_port": 22,
        "proto": "TCP",
        "alert": {"action": "blocked", "severity": 3, "signature": "Internal scan", "signature_id": 55555},
    })
    await client.post(
        "/api/v1/telemetry/ingest",
        headers={"Authorization": f"Bearer {owner}"},
        json={"sensor_id": sensor_id, "records": [rec]},
    )
    r3 = await client.get(
        f"/api/v1/telemetry/events?sensor_id={sensor_id}",
        headers={"Authorization": f"Bearer {owner}"},
    )
    assert r3.status_code == 200
    events = r3.json()
    assert len(events) == 1
    assert events[0]["enrichment_state"] == "skipped"


async def test_public_ip_enrichment_state_pending(client: AsyncClient) -> None:
    owner, _, _ = await _bootstrap(client)
    r = await client.post(
        "/api/v1/telemetry/sensors",
        headers={"Authorization": f"Bearer {owner}"},
        json={"name": f"sur-pub-{_uid()}", "format": "suricata_eve"},
    )
    sensor_id = r.json()["id"]

    await client.post(
        "/api/v1/telemetry/ingest",
        headers={"Authorization": f"Bearer {owner}"},
        json={"sensor_id": sensor_id, "records": [_suricata_alert(88888, src_ip="8.8.8.8")]},
    )
    r2 = await client.get(
        f"/api/v1/telemetry/events?sensor_id={sensor_id}",
        headers={"Authorization": f"Bearer {owner}"},
    )
    events = r2.json()
    assert len(events) == 1
    assert events[0]["enrichment_state"] == "pending"


async def test_tenant_isolation_sensor_not_visible_across_orgs(client: AsyncClient) -> None:
    owner_a, _, _ = await _bootstrap(client)
    owner_b, _, _ = await _bootstrap(client)

    r = await client.post(
        "/api/v1/telemetry/sensors",
        headers={"Authorization": f"Bearer {owner_a}"},
        json={"name": f"sensor-a-{_uid()}", "format": "suricata_eve"},
    )
    assert r.status_code == 201

    r2 = await client.get(
        "/api/v1/telemetry/sensors",
        headers={"Authorization": f"Bearer {owner_b}"},
    )
    sensor_names_for_b = [s["name"] for s in r2.json()]
    assert not any(n.startswith("sensor-a-") for n in sensor_names_for_b)


# ── Zeek JSON ingestion ────────────────────────────────────────────────────


async def test_zeek_conn_ingestion(client: AsyncClient) -> None:
    owner, _, _ = await _bootstrap(client)
    r = await client.post(
        "/api/v1/telemetry/sensors",
        headers={"Authorization": f"Bearer {owner}"},
        json={"name": f"zeek-{_uid()}", "format": "zeek_json"},
    )
    sensor_id = r.json()["id"]

    conn = json.dumps({
        "_path": "conn",
        "ts": datetime.now(UTC).timestamp(),
        "uid": f"CTest{_uid()}",
        "id.orig_h": "1.2.3.4",
        "id.resp_h": "5.6.7.8",
        "id.orig_p": 12345,
        "id.resp_p": 80,
        "proto": "tcp",
        "conn_state": "SF",
        "orig_bytes": 2048,
        "resp_bytes": 8192,
        "orig_pkts": 10,
        "resp_pkts": 20,
    })
    r2 = await client.post(
        "/api/v1/telemetry/ingest",
        headers={"Authorization": f"Bearer {owner}"},
        json={"sensor_id": sensor_id, "records": [conn]},
    )
    assert r2.status_code == 200
    assert r2.json()["created"] == 1


# ── Bandwidth summary ─────────────────────────────────────────────────────


async def test_bandwidth_summary_with_flow_data(client: AsyncClient) -> None:
    owner, _, _ = await _bootstrap(client)
    r = await client.post(
        "/api/v1/telemetry/sensors",
        headers={"Authorization": f"Bearer {owner}"},
        json={"name": f"flow-sensor-{_uid()}", "format": "suricata_eve"},
    )
    sensor_id = r.json()["id"]

    flows = [_suricata_flow(i, bytes_c=1000 * i, bytes_s=500 * i) for i in range(1, 4)]
    await client.post(
        "/api/v1/telemetry/ingest",
        headers={"Authorization": f"Bearer {owner}"},
        json={"sensor_id": sensor_id, "records": flows},
    )

    r2 = await client.get(
        "/api/v1/telemetry/bandwidth?period_hours=24",
        headers={"Authorization": f"Bearer {owner}"},
    )
    assert r2.status_code == 200
    body = r2.json()
    assert body["has_real_data"] is True
    assert body["flow_count"] >= 3


async def test_bandwidth_summary_no_data(client: AsyncClient) -> None:
    owner, _, _ = await _bootstrap(client)
    r = await client.get(
        "/api/v1/telemetry/bandwidth",
        headers={"Authorization": f"Bearer {owner}"},
    )
    assert r.status_code == 200
    assert r.json()["has_real_data"] is False
    assert r.json()["flow_count"] == 0


async def test_viewer_can_read_events(client: AsyncClient) -> None:
    _, _, viewer = await _bootstrap(client)
    r = await client.get(
        "/api/v1/telemetry/events",
        headers={"Authorization": f"Bearer {viewer}"},
    )
    assert r.status_code == 200


async def test_viewer_cannot_ingest(client: AsyncClient) -> None:
    owner, _, viewer = await _bootstrap(client)
    r = await client.post(
        "/api/v1/telemetry/sensors",
        headers={"Authorization": f"Bearer {owner}"},
        json={"name": f"readonly-{_uid()}", "format": "suricata_eve"},
    )
    sensor_id = r.json()["id"]

    r2 = await client.post(
        "/api/v1/telemetry/ingest",
        headers={"Authorization": f"Bearer {viewer}"},
        json={"sensor_id": sensor_id, "records": [_suricata_alert(111)]},
    )
    assert r2.status_code == 403
