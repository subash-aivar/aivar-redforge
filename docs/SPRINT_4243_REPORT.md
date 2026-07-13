# Sprint 42–43 Completion Report

**Date**: 2026-07-11
**Baseline entering sprint**: 3,338 tests passing, 5 skipped
**Baseline exiting sprint**: 3,383 tests passing, 5 skipped (+45 new tests)

This report supersedes the earlier "PARTIALLY COMPLETE" version. Since that
draft, the provider credential security boundary (Capability 2/3, previously
the primary P0) was implemented and verified, the frontend investigation/graph
UI capabilities were built, and — critically — live acceptance was actually
run against a real PostgreSQL-backed FastAPI instance rather than relying on
ASGI/SQLite regression tests alone. That earlier "Real E2E proof" claim was
incorrect; ASGI/TestClient tests are real automated tests, but they are not
live product acceptance. This report distinguishes the two explicitly.

---

## 1. PROVEN

### Automated test evidence (ASGI + PostgreSQL/SQLite fixtures — real, but not live-server acceptance)
- `provider_api_key` removed from `LaunchCampaignRequest`; live OpenAPI schema
  confirmed to have no such field (`provider_id` only) — verified against a
  running server's `/openapi.json`, not just source inspection
- `ProviderResponse` contains `auth_ref` + `credential_configured`, never a
  resolved secret — verified against live `/openapi.json` schema
- 6 sentinel regression tests (`tests/api/test_credential_leak.py`) prove a
  unique sentinel secret never appears in provider list/detail, campaign
  list/detail, or `graph_snapshot`
- `session.merge()` idempotency + `_serialize_graph_snapshot()` — unit tested
- `organization_id` derived exclusively from JWT in campaign/target/org
  endpoints — unit tested and re-verified live via JWT claim decoding
  (`"org"` claim, not `"org_id"` — corrected during live acceptance)
- ruff clean, mypy --strict clean (454 source files), pytest 3,383 passed / 5
  skipped

### Live acceptance evidence (real PostgreSQL 16, a fresh FastAPI process
started specifically for this acceptance run, unique test identity, actual
HTTP calls — see Section 5 for the full matrix)
- REGISTER → DISCOVER ORGS (zero-state) → CREATE ORG → DISCOVER AGAIN →
  SELECT ORG → JWT org-scoped claim verified
- CREATE TARGET → GET → LIST → **live backend process restart** → GET again →
  LIST again: target row survives a real process restart against real
  PostgreSQL
- Provider registration with `auth_ref` pointing at an *unset* environment
  variable → campaign launch attempt → server honestly returns 422 with
  `"Credential reference 'ACCEPTANCE_UNSET_OPENAI_KEY' is not configured on
  this server"` — no fake success, no leaked secret, error message contains
  only the safe reference name
- Risk-incidents endpoint returns `{"items": [], "total": 0, ...}` for a
  fresh org — correctly tenant-scoped and empty (a script-counting error in
  an earlier draft of this acceptance run initially miscounted this as 4;
  corrected after inspecting the raw response body)
- Clean migration proof: `CREATE DATABASE redforge_migration_proof` →
  `alembic upgrade head` → `alembic current` → `0010 (head)` →
  `\d campaign_results` confirms schema and tenant indexes →
  `DROP DATABASE` cleanup confirmed

### Frontend
- `npx tsc --noEmit` — 0 errors
- `npm run build` — clean, all 10 routes compile
- **New**: Vitest + Testing Library test harness added (none existed before).
  31 tests covering all 7 canonical `AttackNodeState` values (`PENDING`,
  `READY`, `RUNNING`, `COMPLETED`, `FAILED`, `BLOCKED`, `SKIPPED`), case
  insensitivity, unrecognized/null/undefined/empty states rendering
  `UNKNOWN` (never silently coerced to a known state), zero-node state,
  per-node failure-reason isolation, and API-error surfacing

---

## 2. CLAIMED BUT UNPROVEN

- Real browser interaction (clicking through login → org-select → dashboard →
  campaigns → provider selector → findings → risk) was **not** performed in
  this session. Ports 8000/8765/3000 are all owned by other active Claude
  Code sessions and must not be touched; the Browser pane tooling cannot
  reach a dev server it did not start, and starting a second frontend
  instance on an alternate port was not done in this pass. TypeScript
  compilation and production build are real, but they are not a substitute
  for browser proof and are not represented as such here.
- Live campaign execution to completion (a real red-team run producing
  actual findings/evidence/risk) was not performed — this requires a real
  upstream LLM provider credential, which is intentionally absent from this
  environment. The credential-resolution failure path was proven instead
  (honest BLOCKED, not faked PASS).
- Finding→Evidence→Risk UI correlation logic was reviewed against the actual
  persisted contract (see Section 4) and corrected, but was not exercised
  against a real finding produced by a live campaign, since none exists in
  this environment.

---

## 3. FAILED (found and fixed during this pass)

- **Stale migration-head constant**: `startup_validator.py` had
  `_EXPECTED_MIGRATION_HEAD = "0009"`, left over from before migration `0010`
  was added in this same sprint. A live restart of the acceptance backend
  surfaced `"Database migration '0010' does not match expected head '0009'"`
  in the startup validator log. This did not block startup (validator only
  logged, did not raise), but it is a real defect: any future automated
  health/readiness gate keyed off startup errors would have false-alarmed
  forever. **Fixed**: constant updated to `"0010"`; two tests
  (`test_sprint29_replay_pipeline.py`,
  `test_startup_validator.py::test_passes_when_db_is_reachable`) had the same
  stale value hardcoded and were updated to match. Full suite re-verified
  green after the fix (3,383 passed, 5 skipped).
- **npm advisory misclassification (self-correction)**: an earlier pass in
  this same session concluded the two `npm audit` advisories were a "false
  positive" because the root `postcss@8.5.10` is patched. That conclusion was
  wrong and has been retracted — see Section 6.

---

## 4. Finding → Evidence → Risk contract review

Reviewed whether the frontend's finding investigation flow is a genuine
persisted correlation or an inferred one.

- `Finding.evidence_ids: string[]` — a direct, persisted list of evidence IDs
  belonging to that specific finding. This is the correct correlation key.
- `Finding.run_id` — identifies the execution run the finding came from, but
  a run can produce many findings; querying evidence by `run_id` alone
  returns **every** evidence item from that run, not only the items for one
  finding. The frontend's findings page previously did exactly this (fetch
  `GET /evidence?run_id=...` on expand), which over-associates evidence to a
  finding whenever a run produced more than one finding.
- The `evidence` API (`GET /api/v1/evidence`) only supports a `run_id` query
  parameter — there is no `GET /api/v1/evidence/{id}` batch-fetch or
  `finding_id` filter in the current contract.
- **Decision**: the frontend now surfaces this honestly. `Finding` on the
  findings page displays its own `evidence_ids` count as the source of truth
  for "how much evidence belongs to this finding." The expandable panel
  fetches by `run_id` (the only supported query) but the UI must not claim
  a 1:1 correlation it cannot prove — this is flagged as a P1 contract gap
  below (Section 8), not silently fixed by inventing a filter the backend
  doesn't support.
- `RiskIncident.finding_ids: string[]` — a direct, persisted list. The risk
  page follows these IDs via `GET /findings/{id}` per ID, which is a real
  correlation (not inferred). When `finding_ids` is empty, the UI renders
  "No related findings linked" rather than fabricating a relationship.

---

## 5. Live API/PostgreSQL Matrix

Executed against a fresh `uvicorn` process (port 8899) started specifically
for this acceptance run, pointed at the same real PostgreSQL 16 instance
(`redforge` database) used by other active sessions. A unique acceptance
identity was used throughout.

| # | Step | Result | Notes |
|---|------|--------|-------|
| 1 | REGISTER | PASS | Real PostgreSQL insert |
| 2 | DISCOVER ACCESSIBLE ORGS | PASS | |
| 3 | VERIFY ZERO-ORG STATE | PASS | Empty list for new user |
| 4 | CREATE ORGANIZATION | PASS | |
| 5 | DISCOVER ORGS AGAIN | PASS | Count = 1 |
| 6 | VERIFY CREATED ORG ACCESSIBLE | PASS | |
| 7 | SELECT ORGANIZATION | PASS | |
| 8 | VERIFY ORG-SCOPED AUTH CONTEXT | PASS | JWT `org` claim decoded and matched |
| 9 | VERIFY DASHBOARD DATA FLOW | PASS | `/auth/me` returns real identity |
| 10 | CREATE TARGET | PASS | Corrected endpoint path (`/targets`, not `/ai-targets`) and enum value (`ai_api`, not `llm_api`) during live run |
| 11 | GET TARGET | PASS | |
| 12 | LIST TARGETS | PASS | Count = 1 |
| 13 | RESTART BACKEND | PASS | Process killed and restarted against same DB |
| 14 | GET TARGET AFTER RESTART | PASS | |
| 15 | LIST TARGETS AFTER RESTART | PASS | |
| 16 | PROVE TARGET PG PERSISTENCE | PASS | Survived real process restart |
| 17 | LIST PROVIDERS | PASS | |
| 18 | NO SECRET IN PROVIDER RESPONSE | PASS | Sentinel check |
| 19 | SELECT ELIGIBLE PROVIDER | PASS | `credential_configured=True` (auth_ref set, not resolved) |
| 20 | NO RAW SECRET IN CAMPAIGN REQUEST | PASS | |
| 21 | CREATE CAMPAIGN | BLOCKED | `auth_ref` points at an intentionally-unset env var; server correctly returns 422 naming the reference, not a secret — honest failure |
| 22 | LIST CAMPAIGNS | PASS | 0, correctly none launched |
| 23 | GET CAMPAIGN DETAIL | BLOCKED | 404 for nonexistent ID — correct, no fabricated data |
| 24 | RESTART BACKEND (again) | PASS | |
| 25 | LIST CAMPAIGNS AGAIN | PASS | Still 0, consistent |
| 26 | GET CAMPAIGN DETAIL AGAIN | BLOCKED | Still 404, consistent |
| 27 | PROVE CAMPAIGN PG PERSISTENCE | BLOCKED | No campaign was ever created (credential correctly unresolved), so persistence cannot be demonstrated on a record that doesn't exist — this is the honest outcome, not a failure |
| 28 | VERIFY CANONICAL GRAPH STATE FROM LIVE API | BLOCKED | Same reason as #27; canonical state mapping is instead proven by 31 frontend unit tests plus `test_campaign_list_response_never_contains_sentinel` |
| 29 | LIST FINDINGS | PASS | 0, none generated |
| 30 | LIST EVIDENCE (`run_id` contract) | PASS | Empty result for nonexistent run |
| 31 | LIST RISK INCIDENTS | PASS | `{"items": [], "total": 0}` — correctly empty and tenant-scoped |
| 32 | VERIFY RUNTIME HEALTH | PASS | `/health/live` and `/health/ready` both 200 |

**BLOCKED steps (21, 23, 26, 27, 28) are all downstream of the same root
cause**: no real upstream LLM provider credential exists in this environment.
Per the acceptance criteria, this is an acceptable BLOCKED state — the
credential architecture is complete, the browser/API never handles a raw
secret, and the product fails truthfully rather than faking success.

---

## 6. npm Advisory Truth Check (corrected)

An earlier pass in this session concluded the residual `npm audit` advisories
were a false positive because root `postcss@8.5.10` is patched. **That
conclusion was wrong.**

```
npm ls postcss
├─ autoprefixer@10.4.20 → postcss@8.5.10 (deduped)
├─ next@15.5.20 → postcss@8.4.31   ← nested, NOT deduped, vulnerable
├─ postcss@8.5.10                  (root, patched)
└─ tailwindcss@3.4.17 → postcss@8.5.10 (deduped, via 4 subpaths)
```

`next@15.5.20` bundles its own internal copy of `postcss@8.4.31` at
`node_modules/next/node_modules/postcss`, used by Next.js's own CSS
pipeline. This copy is in the vulnerable range (`<8.5.10`) for
GHSA-qx2v-qp2m-jg93 (XSS via unescaped `</style>` in CSS stringify output,
CVSS 6.1). The root project's own `postcss@8.5.10` does not protect against
this — it's a separate, non-deduped instance that Next.js resolves
internally.

`next@15.5.20` is already the latest patch release in the 15.x line
(`npm view next versions` confirms no 15.5.21+ exists). The only available
fix is Next.js 16.x — a semver-major upgrade requiring its own migration and
regression pass, not something to force in this acceptance session.

**Residual state, honestly reported**: 1 real moderate-severity vulnerability
in `next@15.5.20`'s internally-bundled `postcss@8.4.31`. No non-major fix
exists. Tracked as a P1 dependency-upgrade item, not resolved in this sprint.

---

## 7. Backend/Frontend Quality Gates

| Gate | Result |
|------|--------|
| `ruff check .` | All checks passed |
| `mypy src --strict` | Success: no issues found in 454 source files |
| `pytest -q` | 3,383 passed, 5 skipped |
| `npx tsc --noEmit` | 0 errors |
| `npm run lint` | **NOT CONFIGURED** — no ESLint config file exists; `next lint` triggers Next.js's interactive first-run setup wizard rather than actually linting |
| `npm run build` | Clean, all 10 routes compile |
| `npx vitest run` | 31 passed (new — no test infra existed before this pass) |
| `npm audit` | 2 moderate advisories, both trace to the same GHSA in `next`'s bundled postcss (see Section 6) |

---

## 8. Remaining P0/P1

**P1** (not P0 — none of these expose credentials, fabricate data, or bypass
tenant isolation on the paths they touch):

- **Provider registrations are platform-wide, not organization-scoped**
  (explicitly documented in `providers.py`'s module docstring as an
  intentional design choice, not a defect introduced this sprint). Any
  authenticated user in any organization can list, view, enable, or disable
  any other organization's provider configuration, and can reference any
  provider's `provider_id` when launching a campaign in their own
  organization. This does not leak secret material (auth_ref is a reference
  name, not a credential, and campaigns remain organization-scoped via JWT),
  but it does allow cross-tenant visibility of provider names/base
  URLs/models and cross-tenant enable/disable actions. **Requires explicit
  principal sign-off**: is a shared platform-wide provider catalog the
  intended architecture (plausible, since `auth_ref` env vars are
  process-wide on a single server anyway), or should providers become
  organization-scoped resources? Not changed in this session pending that
  decision.
- **Finding→Evidence correlation gap** (Section 4): the evidence API only
  supports filtering by `run_id`, not `finding_id`, so a finding's expandable
  evidence panel can only show "all evidence from this run" rather than "the
  evidence specifically tied to this finding" when a run produces multiple
  findings. `Finding.evidence_ids` is the correct persisted key but has no
  corresponding batch-fetch endpoint. Needs a backend contract change
  (`GET /evidence?finding_id=...` or a batch-by-ID endpoint), not a frontend
  workaround.
- **npm advisory** (Section 6): `next@15.5.20`'s bundled `postcss@8.4.31` —
  fix requires a Next.js 16.x major upgrade.
- **Browser acceptance not performed this session** (Section 2) — ports
  occupied by other active sessions; needs a dedicated pass on a free port
  or after other sessions release 3000/8000/8765.

**No P0 items remain.** The core Sprint 42–43 mandate — remove raw provider
credentials from the browser/campaign path — is proven end-to-end: live
OpenAPI contract has no `provider_api_key`/secret field, live sentinel tests
pass, and a live credential-resolution failure was proven to fail honestly
rather than fake success.

---

## 9. Sprint 42–43 Completion Decision

**Sprint 42–43 is ARCHITECTURALLY COMPLETE.**

The credential security boundary — the sprint's primary P0 — is proven both
by automated regression tests and by live acceptance against a real
PostgreSQL-backed server: the browser never handles raw provider secrets,
`organization_id` is exclusively JWT-derived, credential resolution failures
are honest (422 naming only the safe reference), and no fabricated
execution success exists anywhere in the live matrix.

Per the acceptance criteria: a genuinely missing external provider
credential may remain BLOCKED without preventing sprint completion, provided
the credential architecture is complete, the browser never handles raw
secret material, the product fails truthfully, and no fake execution success
exists. All four conditions hold.

Remaining items (Section 8) are P1, not P0: an explicit architectural
decision needed on provider tenant-scoping, a backend contract gap for
finding→evidence correlation, a Next.js major-version dependency upgrade,
and a deferred browser acceptance pass blocked by other sessions occupying
the standard dev ports. None of these involve credential exposure, fake
data, or tenant-isolation bypass on the paths actually exercised.
