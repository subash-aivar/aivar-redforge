# M12 Completion Checkpoint

**Milestone:** M12 — Authorized Network Discovery & Adaptive Validation Orchestration
**Status: M12 COMPLETE**
**Full detail:** [M12_AUTHORIZED_NETWORK_DISCOVERY_ADAPTIVE_VALIDATION_REPORT.md](M12_AUTHORIZED_NETWORK_DISCOVERY_ADAPTIVE_VALIDATION_REPORT.md)

## Architecture decision
Reconnaissance-first extension of M11's own `domain/validation_execution/`
bounded context — no second AIAsset/inventory/scanner/execution-aggregate/
condition-model/correlation-engine/graph. AUTHORIZED TARGET → POLICY GATE →
BOUNDED DISCOVERY → ASSET/SERVICE ENRICHMENT → ADAPTIVE PLAN → REAL
VALIDATION → EVENTS → CONDITIONS → M9 CORRELATION → CRISP RESULT.

## Implementation completed
New `NETWORK_DISCOVERY_BASELINE_V1` profile (minimal initial plan: DNS +
bounded `PORT_DISCOVERY`) alongside preserved `SAFE_ACTIVE_BASELINE_V1`;
`DISCOVERY_PORT_POLICY_V1` (8 named ports, versioned, never 1-65535, never
client-supplied) built on M11's own TCP adapter; closed
`DiscoveryPortOutcome` ladder (REACHABLE/UNREACHABLE/TIMEOUT/NETWORK_ERROR/
POLICY_BLOCKED); canonical IP/HOST/SERVICE asset enrichment via M6's
existing `TenantAssetService` (one new `TARGET_RESOLVES_TO_IP` relationship
mapped to the existing `EdgeKind.CUSTOM` escape hatch, no ontology bump);
deterministic, versioned, duplicate-resistant `AdaptiveRuleRegistry`
mirroring M9's own collision discipline (`PORT_443_TLS_HTTPS`,
`PORT_80_HTTP`, unknown port → no probe); new `StepSource`
(INITIAL/ADAPTIVE) and adaptive provenance fields on `ValidationStep`,
justifying migration 0020; `ServiceEvidenceState` ladder (PORT_REACHABLE →
SERVICE_HINTED → SERVICE_VALIDATED); a SECOND, canonical fresh-policy-
dispatch boundary specifically for adaptively-scheduled steps; M6's
`SENSITIVE_SERVICE_OBSERVED` condition shape reused byte-for-byte so M9's
existing `PublicSensitiveServiceContextRule` fires with zero M9 changes;
M9's `TenantSecurityCorrelationService.evaluate()` given its first
automatic caller as a bounded, best-effort post-processing step; extended
(not duplicated) REST API (`plan_summary`, step provenance,
discovery/correlation result fields); extended Validation Operations
frontend (profile selector, provenance badges, plan-summary chips,
hinted-vs-validated service panel); 52 adversarial backend tests (20 unit
+ 23 API-isolation + 9 dedicated real-PostgreSQL/owned-local-network-lab
proof tests).

## Bugs found and fixed
**P1** — `ValidationProfile(profile)` raised a bare `ValueError` for an
unrecognized client-supplied profile string, which the global
`RedForgeError`-only error handler let fall through into an unhandled 500
with a leaked stack trace. Found during live API acceptance. Fixed by
wrapping the enum construction in the existing `ValidationError` (422),
matching every other input-validation path in the codebase. Full backend
regression re-run after the fix: 3,807 passed / 5 skipped, zero
regressions.

No other defects found.

## Discovery profile
`NETWORK_DISCOVERY_BASELINE_V1` — initial plan is DNS resolution + bounded
port discovery only; every other step is appended adaptively.

## Port-policy ownership
`DISCOVERY_PORT_POLICY_V1` (22, 80, 443, 3306, 3389, 5432, 8080, 8443),
versioned (`DISCOVERY_PORT_POLICY_VERSION = 1`), sourced from a new
`discovery_port_policy.py` module that imports M6's `SENSITIVE_PORTS`
(made public from a private name) rather than duplicating port truth.

## Adaptive rule architecture
`AdaptiveRuleRegistry` — closed, versioned, register-by-`(rule_id,
rule_version)`, duplicate registration rejected. Minimum rule set:
`PORT_443_TLS_HTTPS` (v1), `PORT_80_HTTP` (v1). Genuinely
duplicate-resistant — when both rules would propose the same shared step
type, only the first-registered rule's steps are appended; the
second rule still matches but contributes zero net-new steps (proven unit
+ real-dispatch).

## Service hint/validation semantics
`ServiceEvidenceState`: PORT_REACHABLE → SERVICE_HINTED → SERVICE_VALIDATED.
A port with no wired validator this milestone (e.g. 3306/mysql) stays
HINTED forever — proven never to reach VALIDATED, both as a unit test and
against a real bare TCP listener in the PostgreSQL proof.

## Asset/service enrichment
Canonical IP/HOST/SERVICE assets resolved via M6's existing
`TenantAssetService.resolve_asset()` — deterministic dedup and
cross-tenant separation inherited, not reimplemented. One new
`AssetRelationshipType.TARGET_RESOLVES_TO_IP`, mapped to the pre-existing
`EdgeKind.CUSTOM` escape hatch.

## M10 policy enforcement
Unchanged — `action_class="active_validation"` reused for both profiles,
the same `ExecutionPolicyService` gate M11 established.

## Adaptive time-of-use enforcement
A SECOND, canonical, single fresh-policy-dispatch boundary specifically
for ADAPTIVE steps, checked once per adaptive step inside the existing
dispatch loop. Proven: discovery fact observed → authorization revoked →
adaptive rule matches → the adaptive step's network adapter receives ZERO
calls, `status=failed`, `error_category=policy_denied`, `evidence=[]`.

## M8 condition integration
M6's exact `SENSITIVE_SERVICE_OBSERVED`/`source_category="network_discovery"`
shape reused byte-for-byte. Port reachability alone is never a Finding;
`evidence_state` is always `"observed"`, never `"validated"`.

## M9 correlation integration
`TenantSecurityCorrelationService.evaluate(organization_id)` given its
first automatic caller, invoked once per execution as a bounded,
best-effort step after condition ingestion. A failure is logged via a real
`CORRELATION_EVALUATED` event carrying the error type and never corrupts
or blocks the execution's own truth. Correlation summary exposed in the
result (`correlations_created`/`updated`/`resolved`).

## Graph/ontology decision
No ontology bump — stays at v5. One new relationship type mapped to the
existing `EdgeKind.CUSTOM` escape hatch.

## Migration head
**0020.**

## Adversarial test count
**52** (20 unit + 23 API-isolation + 9 real-PostgreSQL proof).

## Owned local network lab proof
HTTP (8080), HTTPS with a genuine freshly-generated self-signed certificate
(8443), a bare TCP listener with no protocol (3306, hint-only forever),
every other policy port intentionally closed except 5432 (a real local
PostgreSQL server genuinely running in this dev environment, truthfully
reported reachable rather than fabricated closed) — never an external
target.

## PostgreSQL proof
Isolated self-created database, real TLS handshake against the genuine
self-signed cert, real adaptive dispatch for both web-port rules, hint-only
port never validated, canonical identity/condition dedup, real M9
correlation invocation, strictly increasing event order, the second
fresh-policy-dispatch boundary blocking adaptive I/O after revocation,
cancellation mid-discovery, restart persistence. 9/9 passing. Database
destroyed after.

## Clean migration proof
Fresh empty database → 0001→0020 in full → 4 new columns + composite FK +
indexes confirmed present → no M13 schema → downgrade→re-upgrade
reversibility proven → database destroyed. New
`_assert_isolated_proof_database()` safety guard (prints + asserts the
target database name before every destructive command) applied
throughout — added specifically because a prior M11 session's downgrade
proof briefly touched the shared dev database; that mistake was not
repeated. The shared dev database only ever received a safe, additive,
forward-only upgrade (0019→0020) to support the browser-acceptance
attempt — never a downgrade or drop.

## Live API acceptance
Real server (isolated port 8010), real dedicated PostgreSQL, a genuine
`AITarget` pointing at an owned loopback endpoint. 32/32 steps PASS:
register→create org→select→distinct approver seeded and selected→register
target→M10 authorization create→submit→self-approval-denied→distinct-
approver-approves→ACTIVE→both profiles correctly, truthfully FAILED via
the same unpatched production network boundary→plan_summary/provenance/
event-trail all correct→repeat stable→arbitrary client profile cleanly
rejected (422 — the P1 bug was caught and fixed here)→already-terminal
cancel truthfully rejected (422)→revoke→immediate DENY zero steps→
cross-tenant 404+empty-list→no secrets→401 unauthenticated→restart→
persistence confirmed.

## Browser acceptance
**BLOCKED** — identical pre-existing environment limitation M10/M11
already documented: the preview browser's React tree never mounts past an
initial "Loading…" placeholder, reproduced on the extended
`/validation-operations` page despite every JS bundle loading 200 OK with
zero console errors. Not an application defect — corroborated by clean
tsc/build and 70 passing Vitest tests (5 new).

## Backend gates
ruff: all checks passed. mypy (strict) on `src/`: 577 files, 0 issues.
pytest: **3,807 passed, 5 skipped** (baseline 3,755; +52, 0 regressions).

## Frontend gates
tsc: 0 errors. build: succeeds, `/validation-operations` route present
with both profiles. vitest: **70 passed** (baseline 65; +5).

## npm advisory state
2 pre-existing moderate advisories — unchanged, no new dependencies.

## PROVEN
Discovery port policy ownership, bounded discovery truth ladder (including
the real local Postgres server truthfully reported reachable rather than
fabricated closed), canonical asset/service enrichment and dedup,
deterministic adaptive rule engine (including genuine non-duplication),
service hint-vs-validated semantics, the second fresh-policy-dispatch
boundary for adaptive steps (real revocation-blocks-adaptive-I/O proof),
M8 condition reuse, M9 correlation reuse (real invocation, real firing),
execution plan evolution and full audit trail, PostgreSQL proof, clean
migration, live API acceptance (all 32 steps), quality gates (backend +
frontend).

## CLAIMED-UNPROVEN
None.

## FAILED
None remaining — the P1 (unhandled 500 on an invalid profile string) found
during live API acceptance was fixed and re-verified before this
checkpoint.

## BLOCKED
Interactive browser click-through (preview environment hydration
limitation, not an application defect — identical to M10's and M11's own
documented limitation).

## Remaining M12 P0
None.

## Remaining M12 P1
None known.

## Is M12 honestly COMPLETE?
**Yes.**

## Exact recommended next milestone
**M13** — a natural continuation is either (a) widening the adaptive rule
registry with additional closed, deterministic rules against genuinely new
facts (e.g. a real HTTP-response-based service fingerprint feeding a new
adaptive step), still fully within the bounded, non-destructive observation
boundary M11/M12 established, or (b) building live SSE-based event
streaming now that the polling-based event log has a proven, ordered,
tenant-scoped, adaptively-growing foundation to stream from.
