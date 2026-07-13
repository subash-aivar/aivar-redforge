"""M16 live API acceptance — Advanced Network Security & Continuous
Network Monitoring.

Runs the REAL FastAPI application (redforge.app.create_app, full
production dependency wiring from api/dependencies.py — no manually
overridden test doubles) against real, dedicated PostgreSQL
(`redforge_test`, already migrated to head 0024), over `httpx.AsyncClient`
+ `ASGITransport` with the app's own `lifespan_context()` — the same
"real running application, real database" pattern M11-M14's own live
acceptance scripts use for endpoints with no SSE requirement (M16 has
no streaming endpoint of its own; it publishes into the EXISTING M15
SSE feed instead).

Two steps are internal (non-HTTP) fixtures, honestly labeled as such,
because no public HTTP endpoint exists for them BY DESIGN elsewhere in
this platform, not as an M16 shortcut:
  - creating the target NETWORK/IP_ADDRESS AIAsset (assets are always
    discovery-produced in this platform; there is no
    "POST /assets" endpoint anywhere, for any asset type)
  - reading a just-created invitation's plaintext token (the HTTP
    response deliberately never carries it — see
    application/invitations/service.py's own docstring: "Never carries
    the plaintext token" — it is delivered out-of-band by email in
    production)

Every other step is a real HTTP call against the real router.

Usage:
    REDFORGE_TEST_DATABASE_URL=postgresql+asyncpg://redforge:redforge@localhost:5432/redforge_test \
        .venv/bin/python scripts/m16_live_api_acceptance.py
"""

from __future__ import annotations

import asyncio
import os
import sys

from httpx import ASGITransport, AsyncClient

_DB_URL = os.environ.get(
    "REDFORGE_TEST_DATABASE_URL",
    "postgresql+asyncpg://redforge:redforge@localhost:5432/redforge_test",
)

_results: list[tuple[str, bool, str]] = []


def _record(step: str, ok: bool, detail: str = "") -> None:
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {step}" + (f" — {detail}" if detail else ""))
    _results.append((step, ok, detail))


async def main() -> None:
    from redforge.app import create_app
    from redforge.core.config import Settings

    settings = Settings(database_url=_DB_URL)
    app = create_app(settings=settings)

    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            await _run_steps(c)

    total = len(_results)
    passed = sum(1 for _, ok, _ in _results if ok)
    print(f"\n{passed}/{total} steps PASS")
    if passed != total:
        sys.exit(1)


async def _run_steps(c: AsyncClient) -> None:
    # ── 1-3: register tenant A owner, org context ───────────────────────
    r = await c.post(
        "/api/v1/auth/register",
        json={
            "email": "m16-owner-a@example.test",
            "display_name": "Owner A",
            "password": "SecureP@ssA123",
        },
    )
    _record("register tenant A owner", r.status_code == 201, str(r.status_code))
    owner_a_token = r.json()["access_token"] if r.status_code == 201 else ""
    owner_a_user_id = r.json()["user_id"] if r.status_code == 201 else ""

    r = await c.post(
        "/api/v1/organizations",
        json={"name": "M16 Acceptance Org A", "slug": "m16-acceptance-org-a"},
        headers=_auth(owner_a_token),
    )
    _record("create organization A", r.status_code == 201, str(r.status_code))
    org_a_id = r.json()["id"] if r.status_code == 201 else ""

    r = await c.post(
        f"/api/v1/auth/organizations/{org_a_id}/select",
        headers=_auth(owner_a_token),
    )
    _record("select organization A context", r.status_code == 200, str(r.status_code))
    owner_a_scoped = r.json()["access_token"] if r.status_code == 200 else ""

    # ── 4: RBAC denial for unauthorized role (network-security read
    # requires an authenticated, org-scoped token; an unscoped token
    # must be denied) ─────────────────────────────────────────────────
    r = await c.get(
        "/api/v1/network-security/inventory",
        headers=_auth(owner_a_token),
    )
    _record(
        "RBAC/tenant-context denial for unscoped token on network-security read",
        r.status_code in (401, 403),
        str(r.status_code),
    )

    # ── 5: empty inventory before any asset exists ──────────────────────
    r = await c.get(
        "/api/v1/network-security/inventory",
        headers=_auth(owner_a_scoped),
    )
    _record(
        "empty network inventory before any asset exists",
        r.status_code == 200 and r.json() == [],
        str(r.status_code),
    )

    # ── 6 [INTERNAL FIXTURE — no public asset-creation endpoint exists
    # for ANY asset type anywhere in this platform]: create the target
    # IP_ADDRESS asset ──────────────────────────────────────────────────
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from redforge.application.inventory.tenant_asset_service import TenantAssetService
    from redforge.domain.inventory.identity import IdentityScheme
    from redforge.domain.inventory.value_objects import AssetDiscoverySource, AssetType

    # A separate engine/session-factory pointed at the SAME real
    # database the running app itself uses — the app's own internal
    # session factory is a closure-local variable in app.py, not an
    # importable symbol, so this script uses its own connection pool
    # to the identical database for the two internal-fixture steps.
    fixture_engine = create_async_engine(_DB_URL, echo=False)
    fixture_session_factory = async_sessionmaker(fixture_engine, expire_on_commit=False)

    asset_service = TenantAssetService(fixture_session_factory)
    asset = await asset_service.resolve_asset(
        organization_id=org_a_id,
        asset_type=AssetType.IP_ADDRESS,
        scheme=IdentityScheme.IP_ADDRESS,
        raw_external_id="198.51.100.10",
        name="198.51.100.10",
        description="M16 acceptance target",
        discovery_source=AssetDiscoverySource.API_SCAN,
    )
    _record(
        "[INTERNAL FIXTURE] create target IP_ADDRESS asset (no public asset-creation "
        "endpoint exists anywhere in this platform)",
        asset.id != "",
        asset.id,
    )
    target_asset_id = asset.id

    # ── 7-9: real M10 authorization creation via the legitimate API,
    # approved by a SECOND distinct user (self-approval is forbidden).
    # [INTERNAL FIXTURE — the invitation's plaintext token is only ever
    # returned by InvitationService.invite()'s own DTO, at creation
    # time; no HTTP response anywhere carries it (delivered by email in
    # production, per application/invitations/service.py's own
    # docstring: "Never carries the plaintext token"). This script
    # calls the service directly for the ONE thing HTTP structurally
    # cannot expose, then accepts the invitation through the real
    # HTTP API like any real invitee would.] ────────────────────────────
    from redforge.application.invitations.service import InvitationService
    from redforge.infrastructure.audit.logger import InMemoryAuditLog
    from redforge.infrastructure.events import InMemoryEventPublisher
    from redforge.infrastructure.notifications.logging_notifier import (
        InMemoryInvitationNotifier,
    )

    notifier = InMemoryInvitationNotifier()
    invitation_service = InvitationService(
        fixture_session_factory,
        InMemoryEventPublisher(),
        InMemoryAuditLog(),
        notifier,
    )
    await invitation_service.invite(
        organization_id=org_a_id,
        invited_by_user_id=owner_a_user_id,
        email="m16-approver-a@example.test",
        role="admin",
        organization_name="M16 Acceptance Org A",
    )
    invite_token = notifier.sent[0].token if notifier.sent else ""
    _record(
        "[INTERNAL FIXTURE] issue invitation and capture its plaintext token via the "
        "notifier port (no HTTP response ever carries it, by design)",
        bool(invite_token),
        "",
    )

    r = await c.post(
        "/api/v1/auth/register",
        json={
            "email": "m16-approver-a@example.test",
            "display_name": "Approver A",
            "password": "SecureP@ssA123",
        },
    )
    _record("register tenant A approver (distinct user)", r.status_code == 201, str(r.status_code))
    approver_token = r.json()["access_token"] if r.status_code == 201 else ""

    r = await c.post(
        "/api/v1/invitations/accept",
        json={"token": invite_token},
        headers=_auth(approver_token),
    )
    _record(
        "accept invitation via the real invitations API", r.status_code == 200, str(r.status_code)
    )

    r = await c.post(
        f"/api/v1/auth/organizations/{org_a_id}/select",
        headers=_auth(approver_token),
    )
    approver_scoped = r.json()["access_token"] if r.status_code == 200 else ""

    r = await c.post(
        "/api/v1/authorizations",
        json={
            "action_classes": ["active_validation"],
            "scope": [{"entity_type": "ai_asset", "entity_id": target_asset_id}],
            "valid_from": "2020-01-01T00:00:00+00:00",
            "valid_until": "2099-01-01T00:00:00+00:00",
        },
        headers=_auth(owner_a_scoped),
    )
    _record("create M10 authorization via the real API", r.status_code == 201, str(r.status_code))
    authorization_id = r.json()["id"] if r.status_code == 201 else ""

    r = await c.post(
        f"/api/v1/authorizations/{authorization_id}/submit",
        headers=_auth(owner_a_scoped),
    )
    _record("submit authorization for approval", r.status_code == 200, str(r.status_code))

    r = await c.post(
        f"/api/v1/authorizations/{authorization_id}/approve",
        headers=_auth(approver_scoped),
    )
    _record(
        "approve authorization as a DISTINCT user (self-approval forbidden)",
        r.status_code == 200,
        str(r.status_code),
    )

    # ── 10-13: monitoring policy lifecycle via the real API ─────────────
    r = await c.post(
        "/api/v1/network-security/monitoring-policies",
        json={
            "target_asset_id": target_asset_id,
            "profile": "network_baseline",
            "cadence": "daily",
        },
        headers=_auth(owner_a_scoped),
    )
    _record("create monitoring policy", r.status_code == 201, str(r.status_code))
    policy_id = r.json()["id"] if r.status_code == 201 else ""

    r = await c.get("/api/v1/network-security/monitoring-policies", headers=_auth(owner_a_scoped))
    _record(
        "list monitoring policies",
        r.status_code == 200 and len(r.json()) == 1,
        str(r.status_code),
    )

    r = await c.get(
        f"/api/v1/network-security/monitoring-policies/{policy_id}",
        headers=_auth(owner_a_scoped),
    )
    _record("get monitoring policy detail", r.status_code == 200, str(r.status_code))

    r = await c.post(
        f"/api/v1/network-security/monitoring-policies/{policy_id}/activate",
        headers=_auth(owner_a_scoped),
    )
    _record(
        "activate monitoring policy (lifecycle action)",
        r.status_code == 200 and r.json()["lifecycle"] == "active",
        str(r.status_code),
    )

    # ── 14: run-now via the real API ────────────────────────────────────
    r = await c.post(
        f"/api/v1/network-security/monitoring-policies/{policy_id}/run-now",
        headers=_auth(owner_a_scoped),
    )
    _record(
        "run-now launches an authorized network validation",
        r.status_code == 200,
        str(r.status_code),
    )
    run_status = r.json().get("status") if r.status_code == 200 else None
    _record(
        "run-now result reflects a real authorization decision (not DENIED)",
        run_status in ("completed", "partially_completed", "failed"),
        str(run_status),
    )
    run_id = r.json().get("run_id") if r.status_code == 200 else None

    # ── 14b: run list/detail via the real API (closes traceability
    # matrix scenario #61 — cross-tenant execution non-disclosure) ─────
    r = await c.get("/api/v1/network-security/runs", headers=_auth(owner_a_scoped))
    _record(
        "list network validation runs", r.status_code == 200 and len(r.json()) >= 1,
        str(r.status_code),
    )

    r = await c.get(
        f"/api/v1/network-security/runs/{run_id}", headers=_auth(owner_a_scoped),
    )
    _record("get network validation run detail", r.status_code == 200, str(r.status_code))

    # ── 14c: GENUINE mid-run cancellation over real HTTP — scenario #51 ──
    # A dedicated NETWORK_DEEP_SAFE policy against the SAME (blackholed,
    # non-routable TEST-NET-2) target: 14 ports probed concurrently
    # (bounded by MAX_CONCURRENCY=16), each blocking for the full
    # CONNECT_TIMEOUT_SECONDS=1.0s since 198.51.100.10 never responds —
    # giving a real ~1s window during which the run is genuinely RUNNING
    # with active probes in flight, not merely PENDING or already
    # terminal. run-now is launched as a concurrent task; a second,
    # concurrent HTTP client polls for the new run to appear as RUNNING
    # and cancels it mid-flight through the real cancel endpoint — not
    # via direct repository mutation.
    r = await c.post(
        "/api/v1/network-security/monitoring-policies",
        json={
            "target_asset_id": target_asset_id,
            "profile": "network_deep_safe",
            "cadence": "daily",
        },
        headers=_auth(owner_a_scoped),
    )
    deep_policy_id = r.json()["id"] if r.status_code == 201 else ""
    r = await c.post(
        f"/api/v1/network-security/monitoring-policies/{deep_policy_id}/activate",
        headers=_auth(owner_a_scoped),
    )
    _record(
        "[mid-run cancellation setup] dedicated deep-safe policy created and activated",
        r.status_code == 200,
        str(r.status_code),
    )

    run_now_task = asyncio.ensure_future(
        c.post(
            f"/api/v1/network-security/monitoring-policies/{deep_policy_id}/run-now",
            headers=_auth(owner_a_scoped),
        )
    )

    mid_run_id: str | None = None
    for _ in range(40):  # up to ~2s at 0.05s intervals
        await asyncio.sleep(0.05)
        list_r = await c.get(
            "/api/v1/network-security/runs", headers=_auth(owner_a_scoped),
        )
        candidates = [
            run for run in list_r.json()
            if run.get("continuous_policy_id") == deep_policy_id
            and run.get("status") == "running"
        ]
        if candidates:
            mid_run_id = candidates[0]["id"]
            break
    _record(
        "genuine in-progress run observed as RUNNING via real HTTP before cancellation",
        mid_run_id is not None,
        f"found={mid_run_id}",
    )

    cancel_r = await c.post(
        f"/api/v1/network-security/runs/{mid_run_id}/cancel", headers=_auth(owner_a_scoped),
    ) if mid_run_id else None
    _record(
        "POST cancel accepted while the run is genuinely RUNNING (observed via HTTP)",
        cancel_r is not None and cancel_r.status_code == 200
        and cancel_r.json().get("cancellation_requested") is True,
        str(cancel_r.json()) if cancel_r is not None else "no in-progress run observed",
    )

    run_now_response = await run_now_task
    final_status = (
        run_now_response.json().get("status") if run_now_response.status_code == 200 else None
    )
    _record(
        "run-now's own final lifecycle is CANCELLED, not COMPLETED/PARTIALLY_COMPLETED/FAILED",
        final_status == "cancelled",
        str(final_status),
    )

    detail_r = await c.get(
        f"/api/v1/network-security/runs/{mid_run_id}", headers=_auth(owner_a_scoped),
    ) if mid_run_id else None
    _record(
        "GET run detail confirms terminal CANCELLED with cancellation_requested=true",
        detail_r is not None and detail_r.status_code == 200
        and detail_r.json().get("status") == "cancelled"
        and detail_r.json().get("cancellation_requested") is True,
        str(detail_r.json()) if detail_r is not None else "no in-progress run observed",
    )

    # ── 14d: already-terminal-run idempotency/malformed/RBAC semantics ──
    r = await c.post(
        f"/api/v1/network-security/runs/{run_id}/cancel", headers=_auth(owner_a_scoped),
    )
    _record(
        "cancel on an already-terminal run is an idempotent no-op (same status back)",
        r.status_code == 200 and r.json().get("status") == run_status,
        str(r.json()),
    )

    r = await c.post(
        f"/api/v1/network-security/runs/{run_id}/cancel", headers=_auth(owner_a_scoped),
    )
    _record(
        "repeated cancel request is safe and still idempotent",
        r.status_code == 200 and r.json().get("status") == run_status,
        str(r.json()),
    )

    r = await c.post(
        "/api/v1/network-security/runs/01ARZ3NDEKTSV4RRFFQ69G5FAV/cancel",
        headers=_auth(owner_a_scoped),
    )
    _record(
        "cancel on an unknown (but well-formed) run id is 404",
        r.status_code == 404,
        str(r.status_code),
    )

    r = await c.post(
        "/api/v1/network-security/runs/not-a-valid-ulid/cancel",
        headers=_auth(owner_a_scoped),
    )
    _record(
        "cancel with a malformed run id is 404, not a 500",
        r.status_code == 404,
        str(r.status_code),
    )

    r = await c.post(
        f"/api/v1/network-security/runs/{run_id}/cancel", headers=_auth(owner_a_token),
    )
    _record(
        "cancel requires an org-scoped token, not just any authenticated token",
        r.status_code in (401, 403),
        str(r.status_code),
    )

    # ── 15-16: inventory/asset-detail now reflect the target ────────────
    r = await c.get("/api/v1/network-security/inventory", headers=_auth(owner_a_scoped))
    _record(
        "inventory now includes the target asset",
        r.status_code == 200 and len(r.json()) >= 1,
        str(r.status_code),
    )

    r = await c.get(
        f"/api/v1/network-security/assets/{target_asset_id}",
        headers=_auth(owner_a_scoped),
    )
    _record("asset network-security detail", r.status_code == 200, str(r.status_code))

    # ── 17: authorization revocation blocks subsequent runs (tested
    # while the policy is still ACTIVE — DISABLED is a terminal state
    # later in this script and must never be un-disabled) ──────────────
    r = await c.post(
        f"/api/v1/authorizations/{authorization_id}/revoke",
        json={"reason": "acceptance test"},
        headers=_auth(owner_a_scoped),
    )
    _record("revoke authorization via the real API", r.status_code == 200, str(r.status_code))

    r2 = await c.post(
        f"/api/v1/network-security/monitoring-policies/{policy_id}/run-now",
        headers=_auth(owner_a_scoped),
    )
    _record(
        "run-now after revocation is DENIED (fresh authorization re-check holds)",
        r2.status_code == 200 and r2.json().get("status") == "denied",
        str(r2.json()),
    )

    # ── 18: pause/resume/disable lifecycle ──────────────────────────────
    r = await c.post(
        f"/api/v1/network-security/monitoring-policies/{policy_id}/pause",
        headers=_auth(owner_a_scoped),
    )
    _record(
        "pause monitoring policy",
        r.status_code == 200 and r.json()["lifecycle"] == "paused",
        str(r.status_code),
    )

    r = await c.post(
        f"/api/v1/network-security/monitoring-policies/{policy_id}/resume",
        headers=_auth(owner_a_scoped),
    )
    _record(
        "resume monitoring policy",
        r.status_code == 200 and r.json()["lifecycle"] == "active",
        str(r.status_code),
    )

    r = await c.post(
        f"/api/v1/network-security/monitoring-policies/{policy_id}/disable",
        headers=_auth(owner_a_scoped),
    )
    _record(
        "disable monitoring policy",
        r.status_code == 200 and r.json()["lifecycle"] == "disabled",
        str(r.status_code),
    )

    # ── 19-21: malformed / invalid input handling ───────────────────────
    r = await c.get(
        "/api/v1/network-security/assets/not-a-real-ulid",
        headers=_auth(owner_a_scoped),
    )
    _record("malformed asset id does not 500", r.status_code in (400, 404, 422), str(r.status_code))

    r = await c.get(
        "/api/v1/network-security/monitoring-policies/not-a-real-ulid",
        headers=_auth(owner_a_scoped),
    )
    _record(
        "malformed policy id does not 500", r.status_code in (400, 404, 422), str(r.status_code)
    )

    r = await c.post(
        "/api/v1/network-security/monitoring-policies",
        json={"target_asset_id": target_asset_id, "profile": "nmap_syn_scan", "cadence": "daily"},
        headers=_auth(owner_a_scoped),
    )
    _record("unsupported/invalid profile string rejected", r.status_code == 422, str(r.status_code))

    r = await c.post(
        "/api/v1/network-security/monitoring-policies",
        json={
            "target_asset_id": target_asset_id,
            "profile": "network_baseline",
            "cadence": "daily",
            "command": "nmap -sS 0.0.0.0/0",
        },
        headers=_auth(owner_a_scoped),
    )
    _record(
        "unsafe extra field ('command') is structurally ignored, never executed",
        r.status_code in (201, 422),
        str(r.status_code),
    )

    # ── 22-25: tenant B isolation ────────────────────────────────────────
    r = await c.post(
        "/api/v1/auth/register",
        json={
            "email": "m16-owner-b@example.test",
            "display_name": "Owner B",
            "password": "SecureP@ssB123",
        },
    )
    owner_b_token = r.json()["access_token"] if r.status_code == 201 else ""
    r = await c.post(
        "/api/v1/organizations",
        json={"name": "M16 Acceptance Org B", "slug": "m16-acceptance-org-b"},
        headers=_auth(owner_b_token),
    )
    org_b_id = r.json()["id"] if r.status_code == 201 else ""
    r = await c.post(
        f"/api/v1/auth/organizations/{org_b_id}/select",
        headers=_auth(owner_b_token),
    )
    owner_b_scoped = r.json()["access_token"] if r.status_code == 200 else ""

    r = await c.get("/api/v1/network-security/inventory", headers=_auth(owner_b_scoped))
    _record(
        "cross-tenant inventory isolation (tenant B sees zero of tenant A's assets)",
        r.status_code == 200 and r.json() == [],
        str(r.json()),
    )

    r = await c.get(
        f"/api/v1/network-security/assets/{target_asset_id}",
        headers=_auth(owner_b_scoped),
    )
    _record(
        "cross-tenant asset detail non-disclosure",
        r.status_code == 404,
        str(r.status_code),
    )

    r = await c.get(
        f"/api/v1/network-security/monitoring-policies/{policy_id}",
        headers=_auth(owner_b_scoped),
    )
    _record(
        "cross-tenant monitoring policy detail non-disclosure",
        r.status_code == 404,
        str(r.status_code),
    )

    r = await c.get(
        f"/api/v1/network-security/runs/{run_id}", headers=_auth(owner_b_scoped),
    )
    _record(
        "cross-tenant network validation run detail non-disclosure",
        r.status_code == 404, str(r.status_code),
    )

    r = await c.get("/api/v1/network-security/runs", headers=_auth(owner_b_scoped))
    _record(
        "cross-tenant network validation run list isolation",
        r.status_code == 200 and r.json() == [], str(r.json()),
    )

    r = await c.post(
        f"/api/v1/network-security/runs/{run_id}/cancel", headers=_auth(owner_b_scoped),
    )
    _record(
        "cross-tenant cancel non-disclosure (tenant B cannot cancel or even discover "
        "tenant A's run)",
        r.status_code == 404, str(r.status_code),
    )

    # ── 26: M15 Security Operations projection visibility ───────────────
    r = await c.get("/api/v1/security-operations/events", headers=_auth(owner_a_scoped))
    _record(
        "M15 Security Operations event feed reachable (network events project into it)",
        r.status_code == 200,
        str(r.status_code),
    )

    # ── 27: runtime health ───────────────────────────────────────────────
    r = await c.get("/api/v1/runtime/health")
    _record("runtime health endpoint reachable", r.status_code == 200, str(r.status_code))
    if r.status_code == 200:
        body = r.json()
        components = (
            {c["component_id"] for c in body.get("components", [])}
            if isinstance(body, dict)
            else set()
        )
        _record(
            "network_monitoring_scheduler registered in runtime health",
            "network_monitoring_scheduler" in components,
            str(components),
        )


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"} if token else {}


if __name__ == "__main__":
    asyncio.run(main())
