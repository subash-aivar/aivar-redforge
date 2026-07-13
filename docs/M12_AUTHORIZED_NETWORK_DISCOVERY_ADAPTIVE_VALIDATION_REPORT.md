# M12 — Authorized Network Discovery & Adaptive Validation Orchestration

Full detail report. See [M12_COMPLETION_CHECKPOINT.md](M12_COMPLETION_CHECKPOINT.md)
for the concise summary.

## 1. Architecture decision

M12 evolves M11 from a fixed, single-profile validation baseline into an
adaptive pipeline: AUTHORIZED TARGET → POLICY GATE → BOUNDED NETWORK
DISCOVERY → CANONICAL ASSET/SERVICE ENRICHMENT → SERVER-CONTROLLED
ADAPTIVE VALIDATION PLAN → REAL VALIDATION → LIVE EVENTS → SECURITY
CONDITIONS → M9 CORRELATION RE-EVALUATION → CRISP PT-STYLE RESULT.

This is a reconnaissance-first extension of M11's own
`domain/validation_execution/` bounded context, not a new one. Explicit
anti-patterns honored: no second `AIAsset` model, no second
service-inventory model, no separate network-scanner engine, no second
execution aggregate, no second condition model, no second correlation
engine, no Security Graph ontology bump. Every M12 capability is either a
genuine extension of the M11 `ValidationExecution` aggregate or a direct
reuse of an existing M6/M8/M9 service.

Every explicit prohibition in the brief was honored by construction: no
exploit payloads, no reverse shells/C2, no credential theft, no password
spraying/brute force, no persistence/privilege-escalation/lateral-movement,
no destructive actions, no malware behavior, no arbitrary shell execution,
no unrestricted Nmap/Nuclei/Metasploit, no internet-wide scanning. The
server can only ever run one of a small, closed set of read-only
observation steps (DNS resolution, bounded port discovery over 8 named
ports, TLS handshake, HTTP metadata, HTTP security headers) against one
canonical, already-authorized target — the client can never submit a step,
port, adaptive rule, or scan command.

Adaptive validation semantics: DISCOVER FACT → MATCH CLOSED RULE → ADD
ALLOWED STEP. Never LLM-driven, never browser-driven, never
user-script-driven — every rule is a hand-written Python class reading a
closed `DiscoveryFacts` snapshot and proposing steps only from the same
`StepType` taxonomy M11 already established.

## 2. Reuse decisions

- **M6's `BoundedNetworkScanAdapter`** (`application/network_discovery/scan_adapter.py`)
  deliberately NOT reused for per-target discovery — it serves a different
  product surface (arbitrary CIDR ranges via registered connectors, no
  M10/M11 authorization boundary, no M11 SSRF/network-boundary checks).
  M12 instead builds `discover_ports()` directly on M11's own
  `check_tcp_connectivity()`.
- **M6's sensitive-service port truth** (`_SENSITIVE_PORTS`) made public
  (`SENSITIVE_PORTS`) and imported directly into the new
  `discovery_port_policy.py` rather than duplicating the "which port is
  sensitive" judgment.
- **M6's `TenantAssetService.resolve_asset()`/`add_relationship_for_org()`**
  reused unchanged for canonical IP/HOST/SERVICE asset enrichment
  (race-safe get-or-create, established by M6).
- **M9's `TenantSecurityCorrelationService.evaluate()`** given its first-ever
  automatic caller — previously only invoked manually via
  `POST /security-correlations/evaluate`.
- **M9's `CorrelationRuleRegistry` collision discipline** mirrored exactly
  by the new `AdaptiveRuleRegistry` (register by `(rule_id, rule_version)`,
  reject duplicates).
- **Security Graph ontology stays at v5** — one new
  `AssetRelationshipType.TARGET_RESOLVES_TO_IP` mapped to the pre-existing
  `EdgeKind.CUSTOM` escape hatch, documented in `ontology.py` as existing
  precisely for real-but-not-yet-dedicated relationship types.

## 3. Discovery profile & port policy

`NETWORK_DISCOVERY_BASELINE_V1` — initial plan deliberately minimal:
`DNS_RESOLUTION` + `PORT_DISCOVERY` only. Every other step (TLS/HTTP
validation) is appended ADAPTIVELY afterward, never scheduled upfront.

`DISCOVERY_PORT_POLICY_V1 = (22, 80, 443, 3306, 3389, 5432, 8080, 8443)` —
small, explicit, versioned (`DISCOVERY_PORT_POLICY_VERSION = 1`). Never
1-65535, never a client-supplied port list. Each port has a fixed
expected-service hint (`DISCOVERY_PORT_HINTS`) — ssh/http/https/mysql/rdp/
postgresql/http-alt/https-alt.

Discovery outcomes are a closed `DiscoveryPortOutcome` ladder: REACHABLE,
UNREACHABLE, TIMEOUT, NETWORK_ERROR, POLICY_BLOCKED. A port number alone is
only ever an `EXPECTED_SERVICE_HINT`, never `SERVICE_VALIDATED`.

## 4. Canonical asset/service enrichment

`enrich_discovered_assets()` resolves one IP_ADDRESS asset per discovered
address (linked to the target via `TARGET_RESOLVES_TO_IP`), one HOST asset
(`DISCOVERY_HOST` identity scheme, `"{target_id}:{ip}"`), and one SERVICE
asset per reachable port (`SERVICE_ENDPOINT` scheme), linked via
`IP_ASSIGNED_TO_HOST`/`HOST_EXPOSES_SERVICE`. All resolution goes through
M6's existing `TenantAssetService`, so dedup and cross-tenant separation
are inherited, not reimplemented. `AssetDiscoverySource.VALIDATION_DISCOVERY`
(a pre-existing enum value) is reused for M12's discovery-created assets.

## 5. Adaptive rule engine

`AdaptiveRuleRegistry` — closed, server-controlled, plain Python objects,
no LLM, no arbitrary expressions. Minimum rule set:

- `PORT_443_TLS_HTTPS` (v1) — reachable 443 or 8443 → TLS_HANDSHAKE +
  HTTP_METADATA + HTTP_SECURITY_HEADERS.
- `PORT_80_HTTP` (v1) — reachable 80 or 8080 → HTTP_METADATA +
  HTTP_SECURITY_HEADERS.
- Unknown/unrecognized port → no rule matches, no probe.

Duplicate-resistant by construction: when two rules would propose the same
step type, only the first-registered rule's steps are appended — the
second rule still genuinely "matches" (real reachability) but contributes
zero net-new steps. Proven both in a dedicated unit test
(`test_rule_never_duplicates_an_already_planned_step_type`) and against
real dispatch in the PostgreSQL proof
(`test_adaptive_rules_fire_for_both_web_ports_with_real_dispatch`).

`ValidationStep` gained genuine new domain fields — `source` (INITIAL/
ADAPTIVE StrEnum), `adaptive_rule_id`, `adaptive_rule_version`,
`source_fact_ref` — not evidence-blob-encoded, justifying migration 0020.
`ValidationExecution.append_adaptive_step()` enforces: execution must be
RUNNING, no duplicate (step_type, rule_id) pair, bounded by both
`max_steps` and a new `max_adaptive_steps` limit.

## 6. Service-truth ladder

`ServiceEvidenceState`: PORT_REACHABLE → SERVICE_HINTED → SERVICE_VALIDATED.
A reachable port with a known hint (e.g. 443/https) is SERVICE_HINTED
until a real protocol validator actually runs and succeeds, at which point
it becomes SERVICE_VALIDATED. A reachable port with no validator wired
this milestone (e.g. 3306/mysql) stays HINTED forever — proven never to
reach VALIDATED (`test_hint_only_port_never_reaches_validated_state`, both
as a unit test and against a real bare TCP listener in the PostgreSQL
proof).

## 7. Second fresh-policy-dispatch boundary

M11 established a double policy gate for the INITIAL plan (create-time +
immediately-before-dispatch). M12 adds a SECOND, canonical, single
fresh-policy-dispatch boundary specifically for ADAPTIVELY-scheduled
steps — checked once per adaptive step inside the existing dispatch loop
(`_adaptive_dispatch_allowed()`), closing the "authorization revoked after
discovery, before adaptive dispatch" gap.

Proven with the exact required adversarial scenario
(`test_policy_revocation_before_adaptive_dispatch_blocks_network_io`,
both as an API-level test with a sequenced fake policy port and against
real dispatch in the PostgreSQL proof): discovery fact observed →
authorization revoked → adaptive rule matches → the adaptive step's
network adapter receives ZERO calls, its status/error_category recorded
as `policy_denied` with empty evidence.

## 8. M8/M9 reuse

Condition ingestion reuses M6's exact `SENSITIVE_SERVICE_OBSERVED`/
`source_category="network_discovery"` shape byte-for-byte — the only
change required anywhere was making `_SENSITIVE_PORTS` public. This means
M9's pre-existing `PublicSensitiveServiceContextRule` fires with ZERO M9
code changes. Port reachability alone is never a Finding — only the
sensitive-service condition (a deterministic rule over closed facts)
produces a `SecurityCondition`, `evidence_state="observed"` (never
`"validated"`, since no exploit or credentialed check ever ran).

`_evaluate_correlations_best_effort()` calls M9's real, unmodified
`TenantSecurityCorrelationService.evaluate(organization_id)` after
condition ingestion — bounded, best-effort: a failure is logged via a real
`CORRELATION_EVALUATED` event carrying the error type, and never corrupts
or blocks the execution's own truth. The correlation summary
(`rules_evaluated`/`created`/`updated`/`resolved`) is exposed in the
result via `correlations_created`/`updated`/`resolved`.

## 9. Execution plan evolution & audit trail

Index-based (not list-snapshot) step-execution loop, since
`ValidationExecution.steps` returns a fresh tuple on each access —
required so `append_adaptive_step()` calls made mid-loop are actually
picked up by the still-running dispatch loop. `_effective_target_for_step()`
uses `dataclasses.replace()` to construct a per-step "effective target"
(port/scheme override) for adaptively-dispatched TLS/HTTP steps, parsed
from the step's own `source_fact_ref` (e.g. `"tcp_port:8443:reachable"`),
without ever touching the target's own original endpoint.

7 new canonical event types: `DISCOVERY_STARTED`, `PORT_REACHABILITY_OBSERVED`,
`ADAPTIVE_RULE_MATCHED`, `STEP_ADDED_TO_PLAN`, `ASSET_RESOLVED`,
`SERVICE_CONTEXT_UPDATED`, `CORRELATION_EVALUATED`.

## 10. Migration & schema

Migration 0020 — 4 new columns on `validation_execution_steps` only:
`source VARCHAR(20) NOT NULL DEFAULT 'initial'`, `adaptive_rule_id
VARCHAR(60) NULL`, `adaptive_rule_version INTEGER NULL`,
`source_fact_ref VARCHAR(120) NULL`. No schema anywhere for credentials,
Authorization headers, cookies, private keys, arbitrary request/response
bodies, shell commands, or raw scanner output.

## 11. API surface

Extended (not duplicated) — all 7 M11 endpoints unchanged in shape/path:
`POST/GET /validation-executions`, `GET /summary`, `GET /{id}`,
`GET /{id}/steps`, `GET /{id}/events`, `GET /{id}/result`,
`POST /{id}/cancel`. New fields only: `ExecutionResponse.plan_summary`
(`PlanSummaryResponse` — initial/adaptive step counts, discovered-address/
reachable-port/validated-service/condition counts), `StepResponse` gains
the 4 provenance fields, `ResultResponse` gains `discovered_addresses`,
`reachable_ports`, `validated_services` (`{port, hint, state}`),
`correlations_created`/`updated`/`resolved`. Per-port discovery facts ride
inside the existing `port_discovery` step's evidence array and the result's
summary fields — no separate discovery-result route was added, since the
existing shape already carries this information without duplication.

## 12. Bugs found and fixed

**P1** — `ValidationProfile(profile)` raised a bare `ValueError` for an
unrecognized client-supplied profile string. The global error-handler
middleware only maps `RedForgeError` subclasses to clean HTTP status
codes; a bare `ValueError` fell through into an unhandled 500 with a full
stack trace leaked to the client. Found during live API acceptance (step
22 — "arbitrary client-supplied profile rejected"). Fixed by wrapping the
enum construction in the existing `ValidationError` (422), exactly as
every other input-validation path in the codebase already does. Full
backend regression suite re-run after the fix: 3,807 passed / 5 skipped,
zero regressions.

No other defects found.

## 13. Adversarial test coverage

52 dedicated M12 tests: 20 unit tests (`test_network_discovery_adaptive.py`
— port policy ownership, adaptive rule registry determinism/dedup/
duplicate-rejection, bounded discovery adapter against real local HTTP
server + closed port) + 23 API-isolation tests
(`test_validation_executions_m12_isolation.py` — policy-gate zero-dispatch,
client-cannot-submit-profile/step/port/rule, tenant isolation, cancellation,
restart persistence, correlation dedup, no-arbitrary-endpoint, provenance
correctness) + 9 dedicated real-PostgreSQL/owned-local-network-lab proof
tests (`test_network_discovery_postgres_proof.py`).

The 9 PostgreSQL proof tests cover: bounded discovery truthfully
representing reachable/closed ports (including the real local Postgres
server genuinely reachable on 5432 in this dev environment — reported
truthfully, not fabricated as closed); both adaptive rules firing with
real TLS handshake (against a genuine freshly-generated self-signed
certificate) and real HTTP fetch dispatch; the hint-only port (3306,
a bare TCP listener with no protocol behind it) never reaching VALIDATED;
canonical identity/condition dedup on repeat; real M9 correlation
invocation; strictly-increasing event ordering; the second
fresh-policy-dispatch boundary blocking adaptive network I/O after
revocation; cancellation mid-discovery; and restart persistence of
execution/asset/condition/correlation history.

## 14. Owned local network lab proof

Module-scoped fixtures, all on `127.0.0.1`, never an external target: an
HTTP server on port 8080 (in the discovery port policy), an HTTPS server
on port 8443 with a genuine freshly-generated self-signed certificate
(RSA 2048 / SHA-256 / SAN IPAddress), and a bare TCP listener on 3306
(mysql-shaped, reachable, hinted, no protocol behind it — proves the
"reachable + hinted, never validated" ladder for a port with no real
validator this milestone). Every other discovery-policy port (22, 443,
3389) intentionally left closed; 5432 is genuinely reachable (a real local
PostgreSQL server already running in this dev environment) and is
correctly, truthfully reported as such rather than fabricated closed.

## 15. PostgreSQL proof & clean migration proof

**Functional proof**: dedicated, self-created database
(`redforge_network_discovery_proof_test`), `Base.metadata.create_all`
table-subset creation (matching M11's own pattern), all 9 dedicated tests
passing.

**Clean migration proof**: separate dedicated database
(`redforge_m12_clean_migration_proof`) — fresh empty database →
`alembic upgrade head` (0001→0020) in full → all 4 new columns +
composite tenant FK + indexes confirmed present on
`validation_execution_steps` → `alembic history` confirms 0020 is the
latest revision (no M13 schema) → `alembic downgrade -1` cleanly removes
the 4 new columns → `alembic upgrade head` cleanly restores them, head
back at 0020 → database destroyed.

**New safety guard**: `_assert_isolated_proof_database()` — prints and
asserts the exact target database name before every destructive command
(create/downgrade/drop), refusing to proceed if it does not match the
isolated proof database. Added specifically because a prior M11 session's
downgrade proof briefly touched the shared dev database. Applied to every
destructive command in both the functional proof fixture and the clean
migration proof shell commands. The shared dev database (`redforge`) was
never downgraded or dropped this milestone — only a safe, additive,
forward-only `alembic upgrade head` (0019→0020) was applied to it, to
support the live browser-acceptance attempt.

## 16. Live API acceptance

Real server (isolated port 8010), real dedicated PostgreSQL
(`redforge_m12_live_acceptance`, migrated to head 0020), a genuine
`AITarget` pointing at an owned loopback endpoint. Full flow: register
requester → create org (auto-OWNER) → select org → register a distinct
approver (bypassing the invite/accept email flow via a direct membership
DB seed, matching this codebase's established test convention) → approver
selects org → register AI target → M10 authorization create → submit →
requester's own self-approval correctly rejected (422) → distinct approver
approves → ACTIVE → `SAFE_ACTIVE_BASELINE_V1` execution: real ALLOW → plan
built → real DNS resolution correctly denies the owned target's own
loopback address per the (unpatched, production) network boundary → crisp
truthful FAILED result (`tcp_reachable: false`, zero fabricated findings,
`failed_steps: ["dns_resolution"]`) → `plan_summary` present → event trail
strictly increasing → repeated execution stable →
`NETWORK_DISCOVERY_BASELINE_V1` execution: same truthful FAILED result via
the same boundary, provenance fields correctly all `"initial"` (zero
adaptive steps, since DNS resolution failed before any discovery fact
could be observed), discovery result fields all empty (no fabricated
discovery facts) → an arbitrary client-supplied profile string cleanly
rejected with 422 (the P1 bug above was caught and fixed here, previously
an unhandled 500) → cancelling an already-terminal execution truthfully
rejected with 422 (never silently accepted) → revoke authorization →
immediate DENY with zero steps for a new execution → foreign tenant gets
404 on another org's execution and an empty list, never leaked → no bearer
token or secret found in any response body → unauthenticated request
correctly 401 → process killed and restarted → execution/step/
plan_summary/event history confirmed persisted against the same database.
All 32 steps PASS.

## 17. Browser acceptance

**BLOCKED** — for the identical, pre-existing environment reason M10 and
M11's own checkpoints documented: the preview browser's React tree never
mounts past an initial "Loading…" placeholder on any page, reproduced on
the extended `/validation-operations` page. All JS bundle requests
(`layout.js`, `validation-operations/page.js`) returned 200 OK and zero
console errors were logged — the failure is environment-level (hydration
never completes in this preview harness), not an application defect.
Corroborated by clean `tsc`, a clean production `next build`, and 70
passing Vitest tests (5 new, exercising the identical component tree
including the new profile `<select>`, provenance badges, plan-summary
chips, and hinted/validated service panel).

## 18. Quality gates

**Backend**: `ruff check .` — all checks passed. `mypy src` (strict) —
577 source files, 0 issues (the true gate; `mypy src tests` carries
pre-existing, tolerated fixture-parameter/`run_sync`-argument-type debt
identical in kind and count-per-file to M11's own proof file, confirmed
not a regression). `pytest` — **3,807 passed, 5 skipped** (baseline 3,755;
+52, 0 regressions).

**Frontend**: `tsc --noEmit` — 0 errors. `next build` — succeeds,
`/validation-operations` route present. `vitest` — **70 passed** (baseline
65; +5). `npm audit` — 2 pre-existing moderate advisories, unchanged, no
new dependencies.

## 19. Documentation

`docs/PROJECT_CONTEXT.md` §10 (Completed Milestones) updated with the M12
row. This report and
[M12_COMPLETION_CHECKPOINT.md](M12_COMPLETION_CHECKPOINT.md) added.
