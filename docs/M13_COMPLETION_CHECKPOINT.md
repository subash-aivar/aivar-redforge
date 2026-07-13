# M13 Completion Checkpoint

**Milestone:** M13 — Protocol-Aware Service Validation & Enterprise Attack Surface Deepening
**Status: M13 COMPLETE**
**Full detail:** [M13_PROTOCOL_AWARE_SERVICE_VALIDATION_REPORT.md](M13_PROTOCOL_AWARE_SERVICE_VALIDATION_REPORT.md)

## Architecture decision
PORT REACHABILITY MUST NOT BE TREATED AS SERVICE IDENTITY. Reconnaissance-
first extension of M12's own `domain/validation_execution/` bounded
context and canonical `AIAsset` SERVICE model — no second scanner
framework, no second service inventory, no second vulnerability table.

## Validator registry
`ProtocolValidatorRegistry` (`application/validation_execution/
protocol_validators.py`) — closed, server-owned, mirrors
`AdaptiveRuleRegistry`'s collision discipline exactly: register by
`(validator_id, validator_version)`, duplicates rejected. No client-
facing validator name/path, no dynamic import, no subprocess, no shell
command anywhere.

## Implemented protocol validators
- **SSH** (`SSH_BANNER_V1`) — passive banner read only, RFC 4253 shape.
- **MySQL** (`MYSQL_HANDSHAKE_V1`) — passive read of the server's own
  initial greeting, parses protocol_version/server_version/CLIENT_SSL
  flag.
- **PostgreSQL** (`POSTGRESQL_PROTOCOL_V1`) — sends only the documented
  standard 8-byte SSLRequest message, reads the single 'S'/'N' reply.
- **Redis** (`REDIS_PING_V1`) — sends only `PING`, accepts `+PONG` or a
  RESP-shaped error reply as valid protocol identity.

## Deferred validators
- **RDP (3389)** — safely validating RDP without touching NLA/
  credential negotiation could not be honestly proven with a bounded,
  non-authenticating probe this milestone. Stays SERVICE_HINTED
  forever, proven in the owned local lab.
- **SSH full-pipeline dispatch** — the validator itself is fully
  implemented and proven directly; its end-to-end dispatch through the
  real discovery pipeline could not be proven in this environment
  (binding port 22 requires root privileges this proof suite neither
  has nor should be granted). An honestly disclosed environment
  limitation, not a masked gap.

## Candidate vs validated semantics
A reachable port only ever creates a PROTOCOL CANDIDATE (via the
existing `expected_service_hint(port)`, reused unchanged from M12) —
never validated service identity. New `ProtocolValidationState`
(NOT_ATTEMPTED/UNREACHABLE/INCONCLUSIVE/HINTED/VALIDATED/ERROR),
deliberately distinct from M12's own `ServiceEvidenceState` (the asset/
event-level ladder, reused unchanged) — the same relationship
`DiscoveryPortOutcome` already has to `ServiceEvidenceState`.

## Canonical service decision
New `TenantAssetService.update_metadata_for_org()` write path enriches
an EXISTING SERVICE asset (M12 could only set metadata at creation).
Idempotent; proven convergent under a genuine concurrent race, not just
sequential re-runs. Version strings/banners/certificate subjects never
part of canonical identity (already enforced by
`domain/inventory/identity.py`).

## SecurityCondition rules
`TLS_CERTIFICATE_EXPIRED`, `TLS_SELF_SIGNED_CERTIFICATE_OBSERVED`,
`DEPRECATED_TLS_PROTOCOL_OBSERVED` (all derived from M11's own existing
TLS_HANDSHAKE evidence, no new adapter) and
`PLAINTEXT_SENSITIVE_SERVICE_OBSERVED` (fired only on real capability-
flag/SSLRequest evidence proving no TLS support — never inferred from a
version string). Zero CVE inference, zero vulnerability claim from bare
reachability anywhere.

## Correlation decision
No new correlation rule needed — `MultipleSecurityConditionsOnAssetRule`
(M9) already naturally covers 2+ M13 conditions on one asset, proven
rather than assumed.

## Security Graph / ontology decision
No bump — stays at v5. SERVICE nodes enriched via metadata only, no new
node/edge semantics, no fake attack-path/compromise/exploit edge
anywhere.

## Adaptive rules
4 new rules (`Port22SshRule`, `Port3306MySqlRule`,
`Port5432PostgreSqlRule`, `Port6379RedisRule`), each owning exactly one
fixed port with a distinct `rule_id` (sidesteps the `(step_type,
adaptive_rule_id)` dedup-key constraint found during reconnaissance).
`max_adaptive_steps` raised 6→8 (sized to the 7 adaptive steps a fully
multi-protocol-reachable target can genuinely produce, plus one unit of
headroom).

## M10 policy enforcement
Unchanged — the second, fresh-policy-dispatch boundary is step-type-
agnostic and already covered every `ADAPTIVE` step, protocol or not,
with zero code changes; re-proven for a real protocol step (revocation
→ zero validator calls) in both the API-isolation suite and the
PostgreSQL proof.

## Migration head
**0021.**

## PostgreSQL concurrency proof
Two genuinely simultaneous `create_and_run()` calls (`asyncio.gather()`)
against the identical org/target converge on one canonical SERVICE
asset per port — proven, not assumed. Dedicated isolated database,
destroyed after.

## Owned multi-protocol lab proof
HTTP (8080), HTTPS with a genuine self-signed cert (8443), real MySQL-
greeting responder (3306), real Redis PING/PONG responder (6379), bare
RDP listener (3389, proving the deferral), real local PostgreSQL
(5432). 14/14 proof tests passing.

## Live API acceptance
Real server, real dedicated PostgreSQL. 28/28 steps PASS, including
client-supplied validator fields structurally ignored, arbitrary
profile still cleanly rejected (422), and every M13 step field
surviving a real process restart.

## Browser acceptance
**BLOCKED** — identical pre-existing environment limitation M10/M11/M12
already documented. Not an application defect — corroborated by clean
tsc/build and 75 passing Vitest tests (5 new).

## Bugs found/fixed
None new this milestone. Adversarial review across all 22 required
categories found the implementation safe by construction (bounded
reads, closed error categories, no client-controlled protocol
selection, tenant-scoped identity, no CVE/vulnerability inference) —
confirmed via targeted tests, not assumed.

## Backend quality gates
ruff: all checks passed. mypy (strict) on `src/`: 580 files, 0 issues.
pytest: **3,850 passed, 5 skipped** (baseline 3,807; +43, 0 regressions).

## Frontend quality gates
tsc: 0 errors. build: succeeds. vitest: **75 passed** (baseline 70; +5).

## npm advisory state
2 pre-existing moderate advisories — unchanged, no new dependencies.

## PROVEN
Protocol validator registry (determinism, duplicate rejection), all 4
implemented validators against real owned local fixtures, hinted-vs-
validated truth ladder, the second fresh-policy-dispatch boundary for
protocol steps, canonical SERVICE asset enrichment (including under a
genuine concurrent race), condition dedup/reactivation, M9 correlation
reuse, PostgreSQL concurrency proof, clean migration, live API
acceptance (all 28 steps), quality gates (backend + frontend).

## CLAIMED-UNPROVEN
None.

## FAILED
None.

## BLOCKED
Interactive browser click-through (preview environment hydration
limitation, not an application defect) and SSH's full discovery-
pipeline dispatch (requires root to bind port 22 — the validator itself
is fully proven directly).

## Remaining M13 P0
None.

## Remaining M13 P1
None known.

## Is M13 honestly COMPLETE?
**Yes.**

## Exact recommended next milestone
**M14** — natural continuations include (a) a safe, bounded RDP
validator once a non-authenticating negotiation-level probe can be
honestly justified, (b) extending the deterministic condition rule set
with additional evidence-backed checks (e.g. weak cipher suite
observation from the existing TLS evidence), or (c) building live
SSE-based event streaming now that the polling-based event log has a
proven, ordered, tenant-scoped, protocol-aware foundation to stream
from.
