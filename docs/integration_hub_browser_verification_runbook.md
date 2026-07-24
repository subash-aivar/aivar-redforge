# Integration Hub — Browser Verification Runbook

Status: **not executed**. This is a documentation deliverable only. Docker
is unavailable in the environment this pass was performed in
(`docker`/`docker compose` not found), and there is no documented
non-Docker path to run backend + PostgreSQL + frontend together for this
project that matches production topology. Spinning up a bare
`uvicorn` + SQLite substitute was deliberately avoided — it would exercise
a different persistence stack than what's deployed (SQLite lacks JSONB,
has different migration behavior, etc.) and any "pass" against it would be
misleading. A human, or a future agent with Docker access, should execute
the steps below and record actual results.

## 1. Bring up the stack

From the repo root:

```bash
make dev
# equivalent to: docker compose up --build
```

This starts three services (`docker-compose.yml`):

| Service  | Port | Notes |
|----------|------|-------|
| postgres | 5432 | `redforge`/`redforge`/`redforge`, healthcheck-gated |
| backend  | 8000 | FastAPI, `REDFORGE_ENVIRONMENT=development`, waits on postgres health |
| frontend | 3000 | Next.js, `NEXT_PUBLIC_API_URL=http://localhost:8000` |

Wait for `docker compose ps` to show all three `healthy`/`running` before
proceeding. Tear down afterward with `make down` (or `make clean` to also
drop the `postgres_data` volume for a clean re-run).

## 2. Page under test

Navigate to: **`http://localhost:3000/integrations`**

Log in first via `http://localhost:3000/login` with whatever seed/dev
credentials the `backend` container's startup seeding provides (check
`backend/src/redforge/infrastructure/database/migrations` seed data or
the dev-login bypass if `REDFORGE_ENVIRONMENT=development` short-circuits
auth — verify at execution time, not assumed here).

## 3. Verification items

For each item: exact steps, then the expected result. Record actual
result, pass/fail, and any deviation.

### 3.1 Connector Registration
1. On the **Connectors** tab, locate the **Integration Catalog** panel.
2. Click **Configure** on any listed plugin (e.g. OpenAI).
3. Fill in display name, the credential field(s) (a placeholder API key
   is fine for a dev environment), and any config fields.
4. Click **Register Connector**.

**Expected:** Wizard shows "Registering & testing connection…", then
closes. The new connector appears in **Registered Connectors** with a
status pill (`HEALTHY`/`DEGRADED`/`UNHEALTHY` depending on whether the
placeholder credential passes the plugin's `health_check`).

### 3.2 Credential Resolution
1. Open the connector detail drawer (click the row from 3.1).
2. Click **Test Connection**.

**Expected:** A new entry appears under **Recent Health Checks** with a
timestamp. In backend logs (`docker compose logs backend`), confirm the
credential was resolved via `CredentialVaultAdapter.resolve` (structlog
line for `integration_hub.discovery.retry_attempt` or the health-check
path) — no `ResolveCredentialCommand` import errors, no plaintext secret
in logs.

### 3.3 Discovery
1. Switch to the **Asset Inventory** tab.
2. Under **Run Discovery**, click the button for the connector from 3.1
   — only enabled if its plugin declares the `"discovery"` capability
   (verify catalog response's `capabilities` field for that connector,
   e.g. via `GET /api/v1/integration-hub/catalog`).

**Expected:** Button shows "Running…", then the **Discovered Assets**
table populates with rows (or stays empty with the "No assets discovered
yet" message if the plugin's `discover()` legitimately returns nothing
for the placeholder credential/config).

### 3.4 Sync
1. Repeat 3.3 a second time on the same connector (an incremental/manual
   re-run).

**Expected:** No duplicate assets are created; `last_synced_at` on
existing asset rows advances. Check the **Discovery Timeline** tab (3.7)
for a second `SyncRun` entry with `items_updated`/`items_created` counts
reflecting a diff, not a full re-import.

### 3.5 Pagination
1. If the connector/plugin under test paginates (check
   `plugin.discover`'s cursor behavior — OpenAI/Anthropic/Azure OpenAI
   model lists return a single page today per `domain/plugin.py`'s
   `DiscoverFn` docstring), trigger a discovery run against a data source
   large enough to produce `has_more=True` on at least one page.

**Expected:** `SyncRunDTO.pages_processed` > 1 in the Discovery Timeline
row's detail, and all pages' assets appear in inventory (no silent
truncation at page 1).

### 3.6 Asset Inventory
1. On **Asset Inventory**, use the category/vendor filter chips and the
   search box (name / external id / tag).

**Expected:** Filtering narrows the table correctly; clearing filters
restores the full list. Click a row to open the asset detail drawer.

### 3.7 Relationship Graph
1. In the asset detail drawer, scroll to **Relationships**.

**Expected:** If the underlying connector/normalizer populates
relationships (check the plugin's normalizer in
`integration_hub/infrastructure/normalizers/`), rows render as
`RELATIONSHIP_TYPE → target_external_id`. If none exist, the drawer shows
"No relationships found." — this is the genuine empty state (see the
code comment in `AssetDetailDrawer` in
`frontend/src/app/(app)/integrations/page.tsx`: the backend DTO carries
no signal distinguishing "never checked" from "checked, found none" per
asset, so an empty list is always rendered as a real empty result today).

### 3.8 Capability-driven UI
1. Compare two connectors backed by plugins with different
   `capabilities` sets (check `GET /api/v1/integration-hub/catalog`
   response) — e.g. one with `["health_check", "discovery"]` and one with
   only `["health_check"]`.

**Expected:** The **Run Discovery** button is enabled for the first,
disabled (with a "This connector does not support discovery" tooltip)
for the second. No connector-id/vendor-specific branching should be
visible in the rendered behavior — confirm by inspecting
`frontend/src/lib/integrations.ts`'s `CAPABILITY_ACTIONS`/`hasCapability`
and `page.tsx`'s use of them.

### 3.9 Error Handling
1. Attempt to register a connector with an invalid/empty credential
   field, or disable a connector then try **Test Connection** on it via
   direct API call.

**Expected:** Wizard/drawer surfaces the error message inline (red text)
rather than throwing an unhandled exception or leaving the UI stuck on
a spinner.

### 3.10 Loading States
1. Throttle network (Chrome DevTools → Network → Slow 3G) and reload
   `/integrations`.

**Expected:** `AsyncContent`'s loading state (`LoadingRow`) renders while
catalog/connectors/assets fetch, not a blank page or layout shift once
data arrives.

### 3.11 Permission Enforcement
1. Log in as a non-admin user (or a token without the `admin` role) and
   attempt to register a connector or disable one.

**Expected:** `require_admin` rejects the action server-side (403); the
UI surfaces this as an error state (check `ForbiddenRow` primitive in
`cc.tsx` is reachable from this flow, or that the inline error text
reflects the 403).

### 3.12 Tenant Isolation
1. Using two different tenant contexts (two logins / two `tenant_id`
   headers), register a connector under tenant A.
2. Switch to tenant B and load `/integrations`.

**Expected:** Tenant B sees zero connectors/assets from tenant A — every
repository call in `integration_hub` is tenant-scoped
(`registrations.get(ConnectorId, tenant)`, etc.); confirm no cross-tenant
leakage in the **Registered Connectors** or **Asset Inventory** tables.

## 4. Reporting results

For each of the 12 items above, record: pass/fail, actual screenshot or
network trace, and any backend log excerpt relevant to a failure. File
any defects found separately — this runbook does not itself constitute a
verification pass.
