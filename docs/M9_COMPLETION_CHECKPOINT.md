# M9 Completion Checkpoint

**Milestone:** M9 — Exposure Correlation & Attack Surface Intelligence
**Status: M9 COMPLETE**
**Full detail:** [M9_EXPOSURE_CORRELATION_ATTACK_SURFACE_REPORT.md](M9_EXPOSURE_CORRELATION_ATTACK_SURFACE_REPORT.md)

## Reconnaissance decision
Cloud and network asset graphs are disjoint (no CLOUD_RESOURCE↔HOST/IP/SERVICE
relationship exists); no security-group/ingress data exists anywhere; no
identity-to-resource access relationship is modeled. These findings
determined 2 rules were implementable now, 3 must be honestly deferred.

## Implementation completed
New `domain/security_correlation/` bounded context (`SecurityCorrelation`,
`ExternalExposureClassification`, deterministic identity key); migration 0017
(`security_correlations` + 2 normalized association tables, composite tenant
FKs); `CorrelationRuleRegistry` with 2 real rules
(`PUBLIC_SENSITIVE_SERVICE_CONTEXT`, `MULTIPLE_SECURITY_CONDITIONS_ON_ASSET`);
evaluation service with post-success-only resolution safety;
`TenantAttackSurfaceService` backend read model (no magic score); 5 new API
endpoints; Attack Surface frontend (overview/list/detail, "Exposure
Relationship Path" labeling); 37 new backend tests + 5 new frontend tests.

## Bugs found and fixed
**P0** — the evaluation summary's `resolved` count was overwritten per-rule
instead of summed across the rule registry, silently under-reporting
resolutions whenever an earlier-registered rule (not the last one) performed
the resolve. Caught live via the running server + real PostgreSQL, fixed by
accumulating the count, and covered by a dedicated regression test.

## SecurityCorrelation architecture
Persisted canonical aggregate (not a read-model), distinct from
SecurityCondition (single-asset condition), Finding (validated truth), and
RiskIncident (unrelated risk workflow).

## Correlation identity
`organization + stable_rule_id + rule_version + sorted canonical entity IDs`
— DB-enforced unique, entity order and title/summary/operator_action text
excluded.

## External exposure classification
5-level closed enum, explicit precedence (never alphabetical).
`BROAD_INGRESS_CONFIGURED`/`EXTERNALLY_REACHABLE_VALIDATED` are modeled but
never emitted — no producing source exists.

## Evidence-state derivation
Both implemented rules produce OBSERVED only — neither claims validated
reachability/exploitability from OBSERVED source facts.

## Implemented correlation rules
1. `PUBLIC_SENSITIVE_SERVICE_CONTEXT` v1 — public IP → host → sensitive
   service, via real M6 relationships + M8's `SENSITIVE_SERVICE_OBSERVED`.
2. `MULTIPLE_SECURITY_CONDITIONS_ON_ASSET` v1 — 2+ ACTIVE conditions on one
   asset, real `GROUP BY ... HAVING` query.

## Deferred rules and exact reason
- `BROAD_REMOTE_ADMIN_EXPOSURE_CONTEXT` — no security-group/ingress data exists.
- `MULTI_SOURCE_CORROBORATED_CONDITION` — no structured cross-source concern key exists.
- `PRIVILEGED_IDENTITY_EXPOSURE_CONTEXT` — no identity-to-resource access relationship exists.

## Lifecycle/resolution safety
ACTIVE on match/re-match; RESOLVED only after a fully successful evaluation
cycle finds the identity absent from the current active set. Reappearance
reactivates the same row. Proven under real PostgreSQL concurrency.

## Security Graph reuse decision
Reused the existing M4 `find_paths()` traversal as-is — no new graph engine,
no new query implementation.

## Ontology version
**v5 (unchanged).** No correlation node/edge — M9 stays outside the graph by
deliberate decision.

## Migration head
**0017.**

## PostgreSQL concurrency proof
`tests/integration/test_security_correlation_race.py`, isolated self-created
database, 4/4 PASS: concurrent evaluation→1 correlation; cross-tenant
separation; field-update-no-duplicate; resolve→reobserve→reactivation.

## Clean migration proof
Isolated empty database → `alembic upgrade head` ran 0001→0017 in full →
`alembic current` = `0017 (head)` → schema/FK inspection confirmed → no M10
schema present → database destroyed.

## Live API acceptance
Real server, real PostgreSQL, isolated port. Full flow PASS, including
catching and fixing the P0 above live, then re-verifying: evaluate →
list/detail → resolve source condition → re-evaluate → RESOLVED confirmed →
re-observe → re-evaluate → same correlation reactivated to ACTIVE → restart
→ persistence confirmed → cross-tenant guessed-ID/list/asset-exposure denial
(non-disclosing 404s) → runtime health. Test data cleaned up.

## Browser acceptance
**BLOCKED** — same environment tooling limitation as M8. Frontend
correctness independently proven via clean tsc/build/vitest.

## Backend quality gates
ruff: all checks passed. mypy: 533 files, 0 issues. pytest: **3,658 passed,
5 skipped** (baseline 3,621; +37, 0 regressions).

## Frontend quality gates
tsc: 0 errors. build: succeeds. vitest: **41 passed** (baseline 36; +5).

## npm advisory state
2 pre-existing moderate advisories — unchanged, no forced upgrade.

## PROVEN
Domain identity/precedence, both implemented rules against real facts,
evaluation-cycle safety, reactivation, PostgreSQL concurrency (4 tests),
clean migration, live API acceptance (incl. the P0 fix), quality gates.

## CLAIMED-UNPROVEN
None.

## FAILED
None remaining.

## BLOCKED
Interactive browser click-through (environment tooling limitation).

## Remaining M9 P0
None.

## Remaining M9 P1
None known.

## Is M9 honestly COMPLETE?
**Yes.**

## Exact recommended next milestone
**M10 — Authorized PT Scope & Execution Policy Foundation.**
