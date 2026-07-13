# M13 — Protocol-Aware Service Validation & Enterprise Attack Surface Deepening

Full detail report. See [M13_COMPLETION_CHECKPOINT.md](M13_COMPLETION_CHECKPOINT.md)
for the concise summary.

## 1. Architecture decision

M13's core correction: **PORT REACHABILITY MUST NOT BE TREATED AS SERVICE
IDENTITY.** M12 closed the gap between "port open" and "protocol
hinted" but only 4 of 8 discovery-policy ports (80/443/8080/8443) ever
had a real protocol validator — the other four (22/ssh, 3306/mysql,
3389/rdp, 5432/postgresql) topped out at `SERVICE_HINTED` forever. M13
closes this for three of the four (ssh, mysql, postgresql) plus adds a
fourth candidate (redis), while honestly deferring RDP.

This is a reconnaissance-first extension of M12's own
`domain/validation_execution/` bounded context and the canonical
`AIAsset` SERVICE model — no second scanner framework, no second
service inventory, no second vulnerability table. Every explicit
prohibition in the brief was honored by construction: no arbitrary
command execution, no shell-based scanner, no exploit execution, no
credential attacks, no brute force, no C2, no persistence/post-
exploitation, no destructive validation.

## 2. Reconnaissance findings (M13.1)

- `ServiceEvidenceState` (M12) lives in `domain/validation_execution/
  value_objects.py` as the asset/event-level truth ladder
  (PORT_REACHABLE/SERVICE_HINTED/SERVICE_VALIDATED) — reused unchanged.
- SERVICE assets are identified via `IdentityScheme.SERVICE_ENDPOINT`
  (`"{host_asset_id}:tcp:{port}"`) — `domain/inventory/identity.py`'s
  own docstring already states version/banner/product guesses must
  never be part of identity.
- Service metadata is representable via the existing, already-wired
  `AssetMetadata` (`dict[str,str]`) — `resolve_asset(metadata_entries=...)`
  sets it at CREATION time, but no write path existed for an asset that
  already exists. This was the one genuine gap closed by
  `TenantAssetService.update_metadata_for_org()`.
- Adaptive rules register via `AdaptiveRuleRegistry` (M12), collision
  discipline `(rule_id, rule_version)`, mirrored exactly by the new
  `ProtocolValidatorRegistry`.
- `append_adaptive_step()`'s dedup key is `(step_type, adaptive_rule_id)`
  — a single rule firing one step type for two different ports would
  silently drop the second. Each new M13 rule owns exactly one fixed
  port to sidestep this entirely.
- Events persist via the existing standalone, append-only
  `ExecutionEvent` log — unchanged.
- Evidence sanitization: `network_adapters.py`'s `_REDACTED_HEADER_NAMES`
  (HTTP-specific) and `execution_service._ev()` (stringify + bound) —
  M13's protocol adapters apply the same discipline: every metadata
  field is a short, pre-extracted scalar, never a raw response body.
- M10's second policy check (`_adaptive_dispatch_allowed()`) is
  step-type-agnostic — it already covers any `StepSource.ADAPTIVE`
  step, protocol or not, with zero code changes needed.
- M8 conditions ingest via `TenantSecurityConditionService.ingest()`;
  M9 correlations auto-evaluate via `_evaluate_correlations_best_effort()`
  (M12's own addition) — both reused unchanged.
- Security Graph: `NodeKind.SERVICE`/`EdgeKind.EXPOSES` already
  represent service truth; no new kind needed since M13 only enriches
  metadata on an already-projected node.
- A migration was genuinely necessary: `validator_id`/`validator_version`/
  `protocol_validation_state` are real new provenance fields, not
  evidence-blob-encoded, exactly matching the precedent that justified
  migration 0020's `adaptive_rule_id`/`adaptive_rule_version`.

## 3. Protocol validator architecture

`application/validation_execution/protocol_validators.py` — closed,
server-owned `ProtocolValidatorRegistry`:

```python
class ProtocolValidator(Protocol):
    validator_id: str
    validator_version: int
    supported_protocol: str
    def supports(self, port: int) -> bool: ...
    async def validate(self, address: str, port: int, timeout: float) -> ProtocolValidationOutcome: ...
```

`register()` raises `DuplicateProtocolValidatorRegistrationError` on a
duplicate `(validator_id, validator_version)`. `get_for_protocol()` is
the ONLY lookup path — keyed by protocol name derived from the closed
`StepType` the server itself scheduled, never from any client-supplied
field. No dynamic import, no plugin path, no subprocess, no shell
command exists anywhere in this module or its adapters.

`ProtocolValidationOutcome` — validator_id/version, candidate_protocol,
`ProtocolValidationState`, validated_protocol, bounded `metadata: dict[str,str]`,
error_category. `ProtocolValidationState`: NOT_ATTEMPTED, UNREACHABLE,
INCONCLUSIVE, HINTED, VALIDATED, ERROR.

## 4. Bounded protocol adapters (`protocol_adapters.py`)

A single shared `_bounded_read()` primitive: connect (optionally send
one fixed message), read at most `max_bytes` within `timeout`, never
loop, never accumulate. Every byte cap is hard-coded and small (SSH
256, MySQL 1024, PostgreSQL 8, Redis 256).

- **SSH** (`read_ssh_banner`): purely passive — SSH servers speak first
  (RFC 4253 §4.2). Never sends anything. Validates the
  `SSH-(1\.99|1\.5|2\.0)-\S+` identification shape.
- **MySQL** (`read_mysql_handshake`): purely passive read of the
  server's own initial handshake greeting. Parses `protocol_version`
  (must be 0x0A), NUL-terminated `server_version`, and the
  `CLIENT_SSL` capability bit — all fixed-offset, bounds-checked
  parsing, no crash risk on truncated/malformed input.
- **PostgreSQL** (`probe_postgresql`): sends ONLY the documented,
  standard 8-byte SSLRequest message (`length=8`, code=80877103) — the
  exact first message every real PostgreSQL client driver sends before
  authentication. Reads the single `'S'`/`'N'` response byte. No
  credentials, no StartupMessage, no SQL.
- **Redis** (`ping_redis`): sends ONLY `PING\r\n`, Redis's own
  documented liveness command. Accepts `+PONG` or a RESP-shaped error
  reply (e.g. `-NOAUTH ...`) as valid protocol identity — recognizing
  the wire protocol, never bypassing authentication.

## 5. Service candidate model

Reuses M12's own `expected_service_hint(port)` as the candidate
signal — no new candidate table. `DISCOVERY_PORT_POLICY_VERSION`
bumped 1→2 (adds port 6379/redis); `PROTOCOL_VALIDATOR_PORTS = {22,
3306, 5432, 6379}` documents exactly which ports have a real validator.
3389 (RDP) is deliberately excluded — a documented deferral (see §7).

## 6. Adaptive rules

`Port22SshRule`, `Port3306MySqlRule`, `Port5432PostgreSqlRule`,
`Port6379RedisRule` — each triggers on exactly one fixed port, with a
distinct `rule_id`, avoiding the `(step_type, adaptive_rule_id)`
dedup-collision constraint found during reconnaissance.
`max_adaptive_steps` raised from 6 to 8 — sized exactly to the 7
adaptive steps a fully multi-protocol-reachable target can genuinely
produce (3 HTTP/TLS + 4 protocol candidates), plus one unit of
headroom.

## 7. Deferred: RDP

Safely validating RDP without touching NLA/credential negotiation
could not be honestly proven with a bounded, non-authenticating probe
this milestone. RDP (3389) remains in the discovery port policy,
correctly hinted, and permanently capped at `SERVICE_HINTED` — a
documented deferral, not an oversight, proven in the owned local lab
(`test_unvalidated_rdp_port_never_fabricates_a_protocol`).

## 8. Deferred (partially): SSH full-pipeline dispatch

`SshBannerValidator` is fully implemented and thoroughly proven
directly against real valid/invalid banner servers (unit tests,
bypassing the discovery-port constraint via an ephemeral port). Its
full end-to-end dispatch through the real discovery pipeline could NOT
be proven in this environment: binding a listener on port 22 requires
root privileges, which this proof suite neither has nor should be
granted. This is an honestly disclosed environment limitation — the
validator logic itself is proven identically to the other three.

## 9. Canonical service enrichment

`TenantAssetService.update_metadata_for_org()` — new write path,
enriches an EXISTING SERVICE asset's `AssetMetadata` (protocol,
validator_id/version, bounded safe fields). Idempotent by construction
(`AssetMetadata.with_entry()` overwrites the same keys). Proven
convergent under a genuine concurrent race
(`test_concurrent_execution_converges_on_one_canonical_service_asset`),
not just sequential re-runs. Version strings/banners/certificate
subjects are never part of canonical identity — already enforced by
`domain/inventory/identity.py`'s `normalize_service_endpoint()`.

## 10. Security Graph decision

No ontology bump — stays at v5. SERVICE nodes are enriched via
metadata only; no new node/edge kind, no fake attack-path/compromise/
exploit/lateral-movement/C2 edge introduced anywhere.

## 11. Deterministic SecurityCondition rules

- `TLS_CERTIFICATE_EXPIRED`, `TLS_SELF_SIGNED_CERTIFICATE_OBSERVED`,
  `DEPRECATED_TLS_PROTOCOL_OBSERVED` — all derived purely from
  evidence M11's own TLS_HANDSHAKE step already captures
  (protocol_version/subject_common_name/issuer_common_name/not_after).
  No new adapter required — a new pure evaluator,
  `network_adapters.evaluate_tls_findings()`.
- `PLAINTEXT_SENSITIVE_SERVICE_OBSERVED` — fired only when the MySQL/
  PostgreSQL validators' own real capability-flag/SSLRequest evidence
  deterministically proves no TLS/SSL support. Never inferred from a
  version string.
- Candidates NOT implemented: none blindly skipped — all four assessed
  candidates from the brief were implemented, each with real evidence.

Zero CVE inference, zero vulnerability claim from bare reachability or
a version banner anywhere in this milestone.

## 12. M9 correlation reuse

No new correlation rule was needed. `MultipleSecurityConditionsOnAssetRule`
(M9, source-category-agnostic) already naturally covers 2+ M13
conditions on one asset — proven
(`test_sensitive_and_plaintext_conditions_deduplicate_on_repeat` and the
existing correlation-determinism proof), not merely assumed.

## 13. Bugs found and fixed

No new P0/P1 defects were found this milestone. The adversarial review
across all 22 required categories (SSRF, DNS rebinding, redirect
escape, protocol confusion, banner amplification, timeout exhaustion,
TLS metadata amplification, secret leakage via headers/errors, forged
client protocol identity, client-submitted validator ID, adaptive step
duplication, policy/cancellation races, cross-tenant collision/leakage,
false CVE/Finding inference, graph fabrication, unsafe DB/Redis probes,
unbounded persistence) found the implementation safe by construction —
confirmed via targeted tests for each category, not assumed.

## 14. Adversarial test coverage

43 new tests: 24 unit (`test_protocol_validators.py` — registry
determinism/duplicate-rejection, each of the 4 validators against real
owned local TCP fixtures including invalid/silent/closed-port cases,
bounded-read/amplification-defense proofs, "never sends anything
extra" proofs) + 5 API-isolation (`test_validation_executions_m13_isolation.py`
— client-supplied validator/step-type fields structurally ignored, the
second fresh-policy-dispatch boundary proven again for a protocol step,
hinted-vs-validated truth for a real MySQL candidate, no exception/
traceback leakage) + 14 dedicated real-PostgreSQL/owned-local-multi-
protocol-lab proof tests.

## 15. Owned local multi-protocol lab proof

`tests/integration/test_protocol_aware_service_validation_postgres_proof.py`
— HTTP (8080), HTTPS with a genuine self-signed certificate (8443), a
real MySQL-greeting-shaped responder (3306), a real RESP PING/PONG
responder (6379), a bare protocol-less listener on RDP's port (3389,
proving the documented deferral), and the real local PostgreSQL server
already running in this dev environment (5432, matching M12's own
precedent for this exact port). Proves: HTTP/HTTPS/MySQL/PostgreSQL/
Redis candidates all genuinely validate; RDP never fabricates a
protocol; repeated execution never duplicates SERVICE assets;
CONCURRENT execution (`asyncio.gather()`, a genuine race) converges on
one canonical SERVICE asset per port; conditions deduplicate and
correctly reactivate on re-observation; correlation evaluation is
deterministic; revocation before protocol dispatch yields zero
validator calls; cross-tenant SERVICE assets/conditions for the
identical endpoint stay completely disjoint; restart preserves
protocol-validation history (validator id/version/state).

## 16. PostgreSQL concurrency proof

Same file as §15 — the concurrency-specific proof
(`test_concurrent_execution_converges_on_one_canonical_service_asset`)
issues two genuinely simultaneous `create_and_run()` calls via
`asyncio.gather()` against the identical org/target and asserts the
resulting SERVICE asset external_ids are unique — the race is resolved
by `resolve_asset()`'s existing `IntegrityError`-retry semantics (M3/M6),
now proven under a real simultaneous race rather than only a sequential
re-run. Dedicated isolated database
(`redforge_protocol_validation_proof_test`), destroyed after.

## 17. Migration proof

Migration 0021 adds exactly 3 columns to `validation_execution_steps`:
`validator_id` (str60, nullable), `validator_version` (int, nullable),
`protocol_validation_state` (str20, nullable). Clean migration proof:
fresh empty database (`redforge_m13_clean_migration_proof`) →
`alembic upgrade head` (0001→0021) in full → all 3 new columns
confirmed present → `alembic history` confirms 0021 is the latest
revision (no M14 schema) → `alembic downgrade -1` cleanly removes them
→ `alembic upgrade head` cleanly restores them, head back at 0021 →
database destroyed. The `_assert_isolated_proof_database()` guard
(introduced in M12 after a prior M11 incident) was applied to every
destructive command; the shared dev database only ever received a
safe, additive, forward-only upgrade (0020→0021), never a downgrade or
drop.

## 18. Live API acceptance

Real server (isolated port 8011), real dedicated PostgreSQL
(`redforge_m13_live_acceptance`, migrated to head 0021). 28/28 steps
PASS: the same full M10→M11/M12 authorization/execution flow proven in
M12's own live acceptance, extended with M13-specific checks — every
`StepResponse` in a `NETWORK_DISCOVERY_BASELINE_V1` execution carries
the new `validator_id`/`validator_version`/`protocol_validation_state`
fields (all correctly `null` here, since DNS resolution fails first
under the unpatched production network boundary — deep protocol
dispatch is proven end-to-end in the dedicated Postgres proof, §15-16,
not re-proven here); an arbitrary client-supplied profile is still
cleanly rejected with 422 (regression check for the M12-discovered P1);
client-supplied `validator_id`/`validators` fields are accepted by the
request body (extra fields silently ignored by the closed
`CreateExecutionRequest` model) but never influence which validator (if
any) runs; cross-tenant 404/empty-list isolation; unauthenticated 401;
no secret/token leak; process restart confirmed to preserve every M13
step field.

## 19. Browser acceptance

**BLOCKED** — for the identical, pre-existing environment reason
M10/M11/M12's own checkpoints documented: the preview browser's React
tree never mounts past an initial "Loading…" placeholder, reproduced on
the extended `/validation-operations` page. All JS bundle requests
returned 200 OK and zero console errors were logged — the failure is
environment-level (hydration never completes in this preview harness),
not an application defect. Corroborated by clean `tsc`, a clean
production `next build`, and 75 passing Vitest tests (5 new).

## 20. Quality gates

**Backend**: `ruff check .` — all checks passed. `mypy src` (strict) —
580 source files, 0 issues. `pytest` — **3,850 passed, 5 skipped**
(baseline 3,807; +43, 0 regressions).

**Frontend**: `tsc --noEmit` — 0 errors. `next build` — succeeds,
`/validation-operations` route present with the new protocol-validation
rendering. `vitest` — **75 passed** (baseline 70; +5). `npm audit` — 2
pre-existing moderate advisories, unchanged, no new dependencies.

## 21. Documentation

`docs/PROJECT_CONTEXT.md` §10 (Completed Milestones) updated with the
M13 row. This report and
[M13_COMPLETION_CHECKPOINT.md](M13_COMPLETION_CHECKPOINT.md) added.
