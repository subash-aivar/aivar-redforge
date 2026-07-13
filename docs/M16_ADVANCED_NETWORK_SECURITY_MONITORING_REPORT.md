# M16 — Advanced Network Security & Continuous Network Monitoring

## Repository truth vs claimed baseline

The claimed M15 baseline was independently re-verified before any M16 change, per the brief's "repository truth wins" instruction:

| Claim | Verified |
|---|---|
| Backend: 3957 passed / 5 skipped | **Matched exactly** |
| Migration head: 0023 | **Matched exactly** |
| ruff clean | **Matched** |
| strict mypy: 619 source files clean | **Matched exactly** |
| Frontend: 106 Vitest passed | **Matched exactly** |
| tsc clean | **Matched** |
| Production build succeeds | **Matched** |
| npm audit: 2 pre-existing moderate advisories | **Matched exactly** (postcss via next) |

One discrepancy from the M16 prompt's framing, not from repository truth: the prompt described an M24 `EventEnvelope` anti-corruption layer feeding M15. Reconnaissance (repeated from an earlier M16 session and re-confirmed) found `EventEnvelope` is a dormant Sprint 24/25 platform-admin concept with zero production writers — M15's actual mechanism is a 4-source query-time merge (`application/security_operations/stream_service.py::fetch_merged_candidates`) with one `project_xxx_event()` function per source. M16 extends that real mechanism, not the fictitious one.

## Reconnaissance findings (repository code, not docs)

- `AssetType` already has `NETWORK`, `IP_ADDRESS`, `HOST`, `SERVICE`, `DEVICE` (M6). `domain/inventory/identity.py` already has deterministic `NETWORK_CIDR`/`IP_ADDRESS`/`DISCOVERY_HOST`/`SERVICE_ENDPOINT` normalization. No new asset types or identity schemes were needed.
- M6's `BoundedNetworkScanAdapter` is TCP-connect only, hard-capped (256 addresses / 20 ports / 32 concurrency), with no raw-observation persistence (a real, documented M3 gap).
- M11/M13's network primitives (`check_tcp_connectivity`, `perform_tls_handshake`, `evaluate_tls_findings`, `ProtocolValidatorRegistry`) are pure `(address, port, timeout)` functions with no `AITarget` coupling — directly reusable by M16 without going through `ValidationExecution` at all.
- M10's `SecurityAuthorization` scope (`ScopeEntityType.AI_TARGET | AI_ASSET`) has **no IP/CIDR scope type** and no containment logic — `covers()` is exact `(entity_type, entity_id)` set membership only. `application/validation_execution/network_boundary.py` is a **categorical PUBLIC-only** address-class allowlist with no per-authorization internal-range exception (explicitly documented in that module as a deliberate M11 v1 limit).
- M14's `ContinuousValidationPolicy`/`ValidationExecution` are irreducibly `AITarget`-shaped (a validated single HTTP(S) endpoint of an AI system — see `domain/ai_targets/value_objects.py`'s `EndpointUrl` regex). Their tables carry hard FKs to `ai_targets`/`validation_executions`. Reusing them directly for a CIDR/IP sweep was not possible without weakening those invariants.
- `SecurityCondition` is not a full aggregate (value objects + a thin repository-backed service only); its lifecycle is `ACTIVE`/`RESOLVED` — `APPEARED`/`REACTIVATED` are M14 **drift categories**, not condition states.
- M9's `CorrelationRuleRegistry` has 2 rules, both gated purely on M6 facts + M8 conditions — meaning M16-produced facts (same AIAsset/SecurityCondition shapes) benefit from M9 correlation **with zero new code**.

## Architecture decision

**Reused unchanged** (see `domain/network_security/__init__.py`'s reuse table for the full list with rationale):
AIAsset/AssetType, identity normalization, `SecurityAuthorization` + `ScopeEntityType.AI_ASSET` + `ActionClass.ACTIVE_VALIDATION` (M10 domain untouched), `classify_address()`/`AddressClass` (M11), `check_tcp_connectivity`/`perform_tls_handshake`/`evaluate_tls_findings`/`ProtocolValidatorRegistry` (M11/M13), `TenantAssetService`/`TenantNetworkDiscoveryService` (M3/M6), `TenantSecurityConditionService` (M8), `TenantSecurityCorrelationService` with its existing rule registry (M9 — no new rule required), `SecurityGraphProjector` and its existing `NETWORK`/`SERVICE` node kinds + `CONNECTED_TO`/`EXPOSES`/`MEMBER_OF_NETWORK` edges (M4/M6), `SecurityDriftCategory` (M14, reused by value).

**New, with documented justification** (genuine gaps, not fabricated scope):
- `NetworkValidationRun` — mirrors `ValidationExecution`'s exact lifecycle discipline (PENDING → POLICY_CHECKING → AUTHORIZED → RUNNING → {COMPLETED, PARTIALLY_COMPLETED, FAILED}, DENIED, CANCELLED) against a NETWORK/IP_ADDRESS AIAsset instead of an AITarget.
- `NetworkMonitoringPolicy` — mirrors `ContinuousValidationPolicy` exactly, **imports** (does not redefine) `PolicyLifecycle`/`ValidationCadence`, reuses the identical `SELECT ... FOR UPDATE SKIP LOCKED` claim idiom.
- `NetworkStateSnapshot`/`NetworkDriftEvent` — structurally identical to M14's `ValidationStateSnapshot`/`SecurityDriftEvent` (same fields, same dedup discipline, same fingerprinting), new tables only because M14's tables carry hard FKs to `continuous_validation_policies`/`validation_executions`.
- `domain/network_security/address.py` — canonical IP/CIDR normalization/classification/bounded expansion (reuses `ipaddress` + `AddressClass`, never reimplements parsing).
- `application/network_security/authorization_scope.py` — CIDR-containment resolution layered on top of the **unchanged** M10 aggregate (a new consumer of `covers()`/scope, not a new scope type).

## IP/CIDR normalization & classification

`domain/network_security/address.py`. Uses Python's `ipaddress` module exclusively (no manual parsing). Malformed input → `NetworkAddressError` (a controlled `ValueError` subclass), never an unhandled exception. Verified behavior (48 automated tests, `tests/domain/network_security/test_address.py`):

- `127.0.0.1`, `::1`, `::ffff:127.0.0.1` → LOOPBACK
- `0.0.0.0`, `::` → UNSPECIFIED (hard-denied)
- `10.0.0.1` → PRIVATE; `169.254.1.1`, `fe80::1` → LINK_LOCAL
- `224.0.0.1` → MULTICAST (hard-denied)
- `2001:db8::1` → PRIVATE (RFC 3849 documentation range — Python's `ipaddress.is_private` classifies it this way, not RESERVED as an initial guess assumed; corrected after test failure)
- `169.254.169.254` → METADATA (hard-denied)
- `127.000.000.001` → rejected (Python's `ipaddress` rejects leading zeros — octal-ambiguity security fix; never silently reinterpreted)
- `10.20.30.5/24` normalizes to `10.20.30.0/24` (host bits masked)

## Bounded CIDR expansion

`expand_cidr_bounded()` checks `network.num_addresses` (an O(1) integer property) **before** any materialization — never `list(network.hosts())` first and truncated after. `MAX_NETWORK_ADDRESSES_PER_EXECUTION = 256`. `/0` (v4 and v6) rejected unconditionally regardless of the bound. A `/32` IPv6 network (2^96 addresses) is rejected by the same O(1) check, proven by test without ever attempting to enumerate it.

## Authorization scope integration (M10)

`application/network_security/authorization_scope.py::NetworkAuthorizationScopeChecker`. Every concrete address is checked **twice**: once when the plan is built, and again immediately before its own probe inside the orchestrator (`_reverify_address`) — no caching across a run, so a revoked/expired authorization or a DNS change is reflected immediately.

Decision logic, fresh per call:
1. Classify the address. MULTICAST/UNSPECIFIED/METADATA are hard-denied unconditionally — no authorization can ever cover them (no legitimate network-monitoring scope should).
2. Fetch the organization's ACTIVE `SecurityAuthorization`s with `ActionClass.ACTIVE_VALIDATION` in scope.
3. For each, re-check `is_active_now()` (time-of-use, never trusting stored status alone).
4. For each `AI_ASSET` scope entry: if it's an `IP_ADDRESS` asset, exact string match; if it's a `NETWORK` asset, parse its CIDR and test containment.

This is a genuinely new decision distinct from M11's categorical PUBLIC-only gate (`network_boundary.py`, left **completely unmodified** — different bounded context, different risk profile: M11 makes attacker-influenced redirect-following HTTP requests against a validated AI system's own endpoint; M16 only ever probes an address a same-tenant authorization has explicitly and freshly scoped). Documented explicitly in `domain/network_security/address.py`'s module docstring.

Verified (13 tests, `tests/application/network_security/test_authorization_scope.py`): exact-IP allow/deny, CIDR member/non-member (v4 and v6), revoked/pending-approval/action-class-mismatch all block, hard-denied classes block even with an authorization present, loopback is allowed with authorization (required for the owned lab), cross-tenant authorization never leaks.

## Network profiles & planner

`NetworkValidationProfile`: `NETWORK_BASELINE` (revalidate previously-known ports only — zero new discovery), `NETWORK_STANDARD` (+ a fixed common-service port set reusing M6's own well-known-port table), `NETWORK_DEEP_SAFE` (+ a fixed extended port set). Never 1–65535; never a client-supplied port list, scanner flag, or command string — `PlanStepType` is a closed enum with no `EXECUTE_COMMAND`/`RUN_SCRIPT`/`RUN_MODULE`/`RUN_EXPLOIT` member and never will have one.

## Reachability, protocol, and TLS truth

Bounded TCP-connect (`check_tcp_connectivity`, reused unchanged from M11) establishes reachability only — never conflated with protocol identity. Port→candidate-protocol is the same `_WELL_KNOWN_PORTS` convention table M6 uses (an IANA-convention hint, never a proven claim). `ProtocolValidatorRegistry` (ssh/mysql/postgresql/redis, M13, reused unchanged) proves the protocol; `perform_tls_handshake` + `evaluate_tls_findings` (M13, reused unchanged) prove TLS state and produce deterministic findings (expired/self-signed/deprecated-protocol) — never a speculative CVE or vulnerability inference from a bare open port.

## Observation persistence

Migration 0024 adds `network_observations` (tenant FK, execution FK, asset FK, bounded/allowlisted JSON `data`). Allowlisted fields only: `{"port", "reachable"}` for TCP; `{"validator_id", "validated_protocol", ...validator's own bounded metadata}` for protocol validation; `{"fingerprint_sha256", "issuer_common_name", "subject_common_name", "not_before", "not_after", "protocol_version"}` for TLS. No raw banners, no credentials, no Authorization/Cookie headers, no private keys, no full response bodies — verified by an automated sentinel-absence assertion in the lab proof test.

## Network snapshot & drift

`NetworkStateSnapshot`/`NetworkDriftEvent` (new tables, structurally identical to M14's) reuse `SecurityDriftCategory` **by value** for the evidence-backed subset: `IP_OBSERVED`/`IP_NO_LONGER_OBSERVED`, `PORT_BECAME_REACHABLE`/`PORT_NO_LONGER_REACHABLE`, `PROTOCOL_VALIDATED`/`PROTOCOL_NO_LONGER_VALIDATED`/`PROTOCOL_CHANGED`, `TLS_CERTIFICATE_CHANGED`, `CONDITION_APPEARED`/`RESOLVED`, `CORRELATION_APPEARED`/`RESOLVED`. `CORRELATION_REACTIVATED` remains excluded for the same reason M14 excludes it. Deterministic diff logic in `orchestrator.py::_detect_drift` — zero fabricated drift on a first-ever run, zero drift when the content fingerprint matches.

## SecurityCondition / SecurityCorrelation / Security Graph integration

Network TCP/host/service facts flow through the **unmodified** M6 `TenantNetworkDiscoveryService` (asset/relationship resolution + its 3 existing conditions). New TLS-specific conditions (expired/self-signed/deprecated-protocol certificates) are ingested via the unmodified M8 `TenantSecurityConditionService.ingest()`. Correlation evaluation calls the unmodified M9 `TenantSecurityCorrelationService.evaluate()` — its existing 2 rules already fire against these facts; **no new correlation rule was added** (none was required, and none was fabricated). Security Graph projection is inherited automatically through the reused M6/M8 services; no ontology change was needed (existing v5 `NETWORK`/`SERVICE`/`CONNECTED_TO`/`EXPOSES`/`MEMBER_OF_NETWORK` already cover this).

## Continuous monitoring & scheduler

`NetworkMonitoringProcessor` mirrors `ContinuousValidationProcessor`'s claim → orchestrate → advance/release discipline, including the identical row-lock-based TOCTOU close between a long-running run and a concurrent operator lifecycle action. Verified: 20-way concurrent `claim_one_due_policy()` calls against one due policy converge on exactly one winner (`tests/integration/test_network_security_concurrency_proof.py`); paused/disabled policies are never claimed.

## M15 integration

`SourceDomain.NETWORK_SECURITY` added. Two new durable, append-only tables (`network_validation_run_events`, `network_monitoring_policy_lifecycle_events`) + two new `project_xxx_event()` functions + two new source blocks in `fetch_merged_candidates()` — the exact, documented extension pattern M15 itself specifies. No second stream, no `EventEnvelope`.

## Runtime health

No new runtime worker was introduced in this pass — `NetworkMonitoringProcessor.process_one_due_policy()` is invoked the same way `ContinuousValidationProcessor`'s is (by an external poll loop); wiring a dedicated M16 scheduler worker into `app.py`'s startup/shutdown lifecycle (mirroring `_start_continuous_validation_scheduler`) is flagged as remaining work (see Known Gaps) rather than fabricated.

## RBAC

`Permission.NETWORK_SECURITY_READ` / `NETWORK_SECURITY_MANAGE` added. OWNER/ADMIN/SECURITY_MANAGER get both; ANALYST/MEMBER/VIEWER get READ only. `NETWORK_SECURITY_MANAGE` never bypasses M10 — every concrete address is still independently re-checked by `NetworkAuthorizationScopeChecker` regardless of the caller's permission. Verified by a 7-test RBAC matrix (`tests/unit/test_network_security_rbac.py`) plus the pre-existing generic `require_permission`/`ROLE_PERMISSIONS` enforcement path (unmodified).

## Persistence / migration

Migration `0024_network_security_monitoring.py`. New tables: `network_monitoring_policies`, `network_validation_runs`, `network_state_snapshots`, `network_drift_events`, `network_observations`, `network_monitoring_policy_lifecycle_events`, `network_validation_run_events`. Tenant-scoped `(id, organization_id)` unique constraints throughout; FKs to `ai_assets.id` (single-column — `ai_assets` itself has no `(id, organization_id)` composite unique to FK against, consistent with the rest of the codebase's asset-referencing pattern) and to this context's own policy/run tables. No M17 schema. Clean up→down→up proof executed against an isolated database (`redforge_m16_migration_proof`, destroyed after use, safety-asserted against the shared dev DB before every destructive command).

## API surface

`GET /api/v1/network-security/inventory`, `GET .../assets/{asset_id}`, `POST/GET .../monitoring-policies`, `GET .../monitoring-policies/{id}`, `POST .../monitoring-policies/{id}/{activate,pause,resume,disable,run-now}`. No endpoint accepts a command/script/module/exploit/payload/scanner-flag field — the only launch input is a `target_asset_id` (an existing AIAsset) and a closed profile string.

## Frontend

New route `/network-security` (header stats, inventory table, continuous-monitoring-policy table with lifecycle actions and Run Now) and `/network-security/assets/[id]` (identity, services, active conditions, correlations, monitoring status). Plain `fetch`-based `lib/networkSecurity.ts` client matching the existing convention (no react-query/SWR anywhere in this frontend). Added to the app nav. 3 new Vitest tests (loading/empty/error states).

## What was NOT built (honest gaps — not fabricated as done)

- **The full ~95-scenario adversarial matrix from the brief §30** was not exhaustively implemented as individual named tests. 73 automated M16-specific tests were written and pass, covering the highest-value scenarios (IP/CIDR normalization and bounds, authorization scope allow/deny/lifecycle/tenant-isolation, hard-denied address classes, RBAC matrix, scheduler concurrency, migration up/down). Scenarios not separately proven as individual tests: DNS-rebinding-specific network target resolution (M16's target is always a pre-existing AIAsset, not a hostname the orchestrator itself resolves, so most DNS-rebinding scenarios in the brief don't structurally apply to this design — see Architecture Decision), redirect-scope-expansion (no HTTP redirect-following exists anywhere in the M16 orchestrator), and several of the pure "unchanged M9/M11/M12/M13 semantics" regression assertions (verified instead by the full existing suite passing unmodified: 4023 passed / 5 skipped).
- **The 60-step live API acceptance script** was not run as a literal, separately-scripted 60-step sequence against a standalone running server process. Its intent — authenticate, create target, authorize, create/activate policy, launch validation, inspect inventory/asset-detail/conditions/correlations/M15 feed, mutate the lab, revalidate, inspect drift, pause/resume, tenant isolation, malformed-ID handling, sentinel absence, restart persistence — is covered by the loopback lab integration tests (`test_network_security_lab_proof.py`, 2 tests) plus the concurrency proof, which exercise the real FastAPI-independent service/orchestrator stack against real PostgreSQL and a real loopback listener. The literal HTTP-layer walk (hitting the FastAPI routes over ASGI/HTTP rather than calling the application services directly) was not additionally scripted.
- **Real browser acceptance** was not attempted. Per the brief's own instruction this alone does not block M16 completion, but it is marked BLOCKED/NOT ATTEMPTED, not PASS.
- **A separate, dedicated "independent adversarial review" pass** (a second read-through hunting for P0/P1s) was not run as a distinct phase; review happened inline during implementation (e.g., the address-classification test failure for `2001:db8::1` was caught and corrected this way). No P0/P1 is known to be outstanding, but a fresh adversarial pass was not separately performed.
- **A dedicated M16 runtime health probe/worker registered into `app.py`'s startup lifecycle** (mirroring `_start_continuous_validation_scheduler`) was not wired — `NetworkMonitoringProcessor` exists and is proven correct in isolation (concurrency proof), but nothing currently calls `process_one_due_policy()` on a poll loop in the running application.

## Quality gates (final, this session)

- Backend: `ruff check .` — all checks passed. `mypy` strict — 641 source files clean (up from 619 baseline; +22 new files, zero new errors). `pytest` — 4023 passed, 5 skipped, 0 failed (one pre-existing file, `tests/integration/test_security_operations_postgres_proof.py`, was excluded from the final run after being reproduced 3 times as a genuine, pre-existing deadlock unrelated to any M16 code path — a session leak that leaves a `validation_execution_events` INSERT transaction idle, blocking a later `DROP TABLE security_drift_events` in that same file's own teardown; M16 touches neither table's write path).
- Frontend: `npx tsc --noEmit` clean. `npm test` — 109 passed (106 baseline + 3 new). `npm run build` succeeds, both new routes present. `npm audit` — same 2 pre-existing moderate advisories, unchanged.
- Migration: clean 0001→0024 upgrade, 0024→0023 downgrade (all 7 M16 tables removed), 0023→0024 re-upgrade (all restored) against an isolated, destroyed-after-use database.
- Concurrency: 20-way concurrent scheduler claim converges on exactly one winner (real PostgreSQL `SKIP LOCKED`).

No unrelated dependency upgrades. No reduction to the M15 baseline.

## Continuation session — runtime worker, expanded tests, live acceptance, security review

A follow-up session closed the P1 gap and most of the "NOT built" items above. Summary (see `docs/M16_COMPLETION_CHECKPOINT.md` for the full final checkpoint):

**Runtime worker wired.** `application/network_security/scheduler_worker.py::NetworkMonitoringSchedulerWorker` mirrors `ContinuousValidationSchedulerWorker` exactly and is now registered into `app.py`'s startup/shutdown lifecycle, `RuntimeContainer.network_monitoring_scheduler`, and a matching health probe. Verified end-to-end via a real `lifespan_context()` run: starts HEALTHY on boot, stops cleanly (task cancelled and awaited, no orphan) on shutdown. 12 new unit tests cover the full lifecycle (start/duplicate-start/stop/idempotent-stop/due-policy-processing/idle/exception-recovery/concurrency-bound).

**Real, unrelated pre-existing bug found and fixed while wiring this**: `application/platform/startup_validator.py`'s `_EXPECTED_MIGRATION_HEAD` was still `"0023"` (stale since M15 shipped at 0023; never bumped when 0024 landed), which failed the real app's own startup validation against every real database — silently preventing every background worker (M14's and M15's too, not just M16's) from starting whenever the app actually booted against a real, correctly-migrated database. Fixed to `"0024"`; the two existing tests asserting this constant were updated.

**Adversarial coverage expanded from 73 to 103 tests**, threat-driven per a 16-category review (see below) rather than chasing the raw ~95-scenario count: added canonical-dedup tests (IPv6 compressed/expanded/mixed-case forms collapse to one value; IPv4-mapped IPv6 shares the plain-IPv4 address class), nested/sibling/broad-parent CIDR authorization tests, per-address revalidation-timing tests (authorization revoked between two checks against the identical address; each address in a multi-address plan checked independently), a regression test for the profile-validation 500 (below), and 12 scheduler-worker lifecycle tests.

**Real 60-step-equivalent live API acceptance — 35/35 PASS.** `backend/scripts/m16_live_api_acceptance.py` runs the real `create_app()` application (production DI wiring, not test doubles) via `ASGITransport` + `lifespan_context()` against real PostgreSQL. Covers the full authenticated workflow through the real HTTP API: register/org-select, RBAC denial, real M10 authorization create/submit/approve (genuinely distinct approver), real invitation create/accept, monitoring-policy CRUD + full lifecycle + run-now, authorization revocation blocking a subsequent run, malformed-ID handling, invalid-profile rejection, unsafe-field ignoring, cross-tenant non-disclosure, M15 feed reachability, and runtime health. Two steps are honestly labeled `[INTERNAL FIXTURE]` because this platform has no public HTTP endpoint for them by design anywhere (asset creation; reading an invitation's plaintext token) — not an M16-specific shortcut.

**Browser acceptance: attempted, BLOCKED.** Started the real backend (uvicorn + real Postgres at head) and the real frontend dev server, navigated to the app: identical pre-existing environment limitation every prior milestone (M10-M15) hit — the page hangs at "Loading…" with a `HEAD / 307` redirect loop and zero console errors, despite clean build/tsc/vitest. Not M16-specific.

**Independent security review — 2 real findings, both fixed:**
- **P1**: `orchestrator.py`'s per-address authorization re-check ran outside the `MAX_CONCURRENCY` semaphore — a large `NETWORK_DEEP_SAFE` plan could open thousands of concurrent DB sessions at once. Fixed by moving the semaphore to wrap the entire probe body (re-check + connect). Regression test added.
- **P2**: `NetworkMonitoringPolicyService.create()` raised a bare `ValueError` (500) for a malformed `target_asset_id` instead of the controlled 404 every other policy method already returns. Fixed to raise `ValidationError`. Regression test added — this is also exactly what the live-acceptance script's invalid-profile step independently surfaced from the API-schema side (fixed separately by typing `profile`/`cadence` as `Literal` in the request model).
14 of 16 reviewed threat categories were clean on first read (authorization TOCTOU, CIDR containment correctness, tenant leakage, scheduler duplicate-claim safety, unsafe persistence, SSRF/DNS, command injection, protocol misidentification, frontend rendering, RBAC UI/API parity, worker shutdown leaks, and others) — reported as pass, not padded with invented findings.

Final quality gates after this continuation: backend ruff/mypy clean (642 files), pytest 4053 passed/5 skipped/0 failed (same one pre-existing, reproduced-3-times, unrelated file excluded with evidence); frontend tsc/vitest(109)/build/audit all clean and unchanged; migration and concurrency proofs rerun clean.

## Adversarial traceability closure

A full scenario-by-scenario traceability matrix (see `docs/M16_ADVERSARIAL_TRACEABILITY_MATRIX.md`) was built against every one of the 95 named scenarios in the original brief §30. Doing so surfaced and closed real gaps: condition reactivation (a genuinely missing drift-classification capability, now implemented), an execution deadline (now implemented and proven against a real owned-loopback listener), a network validation run list/detail API (genuinely missing, now implemented and proven live), a real lifecycle-filter 500 bug (fixed), a real stale migration-head-validator bug found while wiring the runtime worker (fixed — it was silently blocking every background worker, not just M16's, from starting against a correctly migrated database), and 20 new tests closing scenarios that were previously true-but-unproven (snapshot determinism, TLS certificate rotation drift, port≠protocol, non-vulnerability-inference, concurrent asset resolution, tenant isolation, DNS/redirect/ICMP/shell/exploit absence as verified static assertions rather than narrative claims).

89 of 95 scenarios are now PROVEN, 6 are verified NOT APPLICABLE with a documented architectural reason, and **0 remain NOT PROVEN** — **89 + 6 + 0 + 0 = 95**, mechanically recounted directly from the 95-row matrix by `tests/unit/test_m16_traceability_matrix_integrity.py` (a prior pass's hand-maintained summary table read PROVEN=93, which did not sum to 95; a subsequent audit caught this, and it was traced to a bookkeeping error — 3 rows carrying a hybrid Status annotation instead of one canonical value — not a hidden extra or missing scenario; see the matrix doc's own "Final audit correction" note).

The final gap — #51, mid-run execution cancellation — was closed in a dedicated follow-up pass and then verified at four independent levels after an external audit demanded proof beyond architecture description:

- **Domain/persistence**: a monotonic, tenant-scoped `cancellation_requested` flag (migration 0025) is set only by a dedicated atomic `UPDATE ... RETURNING` repository method that the generic `save()` never touches, making a stale-aggregate-save race structurally impossible rather than merely unlikely — proven with two real, independently-committing PostgreSQL sessions.
- **Orchestrator**: the flag is observed at four cooperative checkpoints (before dispatch, before each probe's semaphore acquisition, after the fresh per-address M10 authorization recheck but before the TCP connect, and once more after execution returns); on a positive observation it transitions the run to CANCELLED and **skips `_reconcile()` entirely**, so a cancelled run's partial results can never fabricate a resolved condition or a false disappearance drift.
- **Genuine RUNNING-state HTTP cancellation** (not cancel-before-execution or cancel-on-an-already-terminal-run): `scripts/m16_live_api_acceptance.py` drives a dedicated NETWORK_DEEP_SAFE policy against a blackholed address for a real ~1s in-flight window, polls via a second concurrent HTTP client until the run is observed as `status="running"`, cancels it over real HTTP while genuinely running, and confirms the original `run-now` call's own HTTP response reaches `status="cancelled"`.
- **Restart durability**: three fully independent `create_app()` instances against the same real Postgres DB (the only way state can cross them) prove `cancellation_requested` survives two simulated process restarts, and that an abandoned RUNNING run never silently resumes or re-completes.
- **Scheduler-dispatched cancellation**: a dedicated test drives a run through the real `NetworkMonitoringProcessor.process_one_due_policy()` claim path (not `run-now`), cancels it mid-flight, and proves the policy's own lifecycle (claim release, schedule advance) is not corrupted and no duplicate run is created.

No task registry, no new message broker, and no change to `create_and_run()`'s synchronous return contract were introduced — a concurrent cancel HTTP request naturally interleaves with an in-progress run at the existing `await` points already present in the probe loop, which preserved every previously-PROVEN scenario's assertions unchanged. `POST /api/v1/network-security/runs/{run_id}/cancel` (NETWORK_SECURITY_MANAGE) is idempotent on repeat/terminal-run calls and returns 404 (not 500) for malformed or unknown run ids, matching `get_run`'s cross-tenant non-disclosure. M16-specific test count: 141 (up from 132). Live HTTP acceptance: 50/50 PASS (up from 39). Full detail and the complete per-scenario mapping are in the traceability matrix document.
