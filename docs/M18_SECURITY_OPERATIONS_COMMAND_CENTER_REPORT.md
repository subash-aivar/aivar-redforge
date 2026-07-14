# M18 — Security Operations Command Center

**Platform:** AIVAR RedForge · **Migration head:** `0028` · **Builds on:** M1–M17 + infra closure (`796c5d1`)

## 1. Architecture decision

M18 is an **evolution of M15's existing Security Operations Command Center**, not a greenfield build. Reconnaissance (9-agent read-only sweep) established that the platform already had a production-grade real-time backbone and a canonical merged-activity read model; M18 **reuses these and adds no second source of authoritative truth**. Concretely:

- **Real-time delivery reused unchanged:** SSE over `GET /api/v1/security-operations/events/stream` (bearer-auth, `Last-Event-ID` resume, durable composite cursor `occurred_at|source_tag|row_id`, multi-instance safe, 2s commit-visibility margin) + the `useSecurityOperationsStream.ts` client. **No WebSockets, no Kafka/Redis, no `platform_events` resurrection** — the smallest production-grade option, already proven.
- **Merged activity feed extended, not duplicated:** M15's `fetch_merged_candidates()` merges durable per-context append-only logs at query time. M18 added the **7th source** — the previously write-only M16 `network_drift_events` (source tag `"K"`, `SourceDomain.NETWORK_SECURITY`) — via one projector in `projection_registry.py`. This is the exact pattern M16 used to go 4→6 sources.
- **One new bounded context** (`domain/command_center/` + `application/command_center/`) holding only genuinely-new logic: the deterministic posture formula and the closed enums. Everything else is read from its owning context's existing tables.
- **Isolation/RBAC inherited:** every route derives `organization_id` from the verified `TenantContext` (never a client param), gated by `require_permission`, with the live suspended-membership re-check from the infra-closure work.

Two new persisted tables were justified (both boundaries/projections, never authoritative domain state): `integration_providers` (the external-telemetry boundary) and `network_zone_assignments` (explicit admin zone classification). Plus one supporting index on `network_observations` for the top-ports aggregation. Migration `0028`.

## 2. Canonical data source & calculation for every panel

| Command Center panel / metric | Class | Canonical source & calculation |
|---|---|---|
| **Posture score** | DERIVED (new, deterministic) | `domain/command_center/posture.compute_posture_score` — pure function over `security_conditions.count_active_by_severity` (GROUP BY severity WHERE lifecycle='active') + `security_correlations.count_active`. `score = clamp(0,100, 100 − Σ(count×weight) − correlations×10)`, weights critical15/high8/medium3/low1/info0/unknown3. Bands ≥90 strong / ≥70 moderate / ≥40 at_risk / else critical. Formula **versioned** (`1.0.0`) and full breakdown returned. **No trend line** (no time-bucketed history exists → none fabricated). |
| **Active critical/high conditions** | LIVE | `security_conditions` active-by-severity counts (real GROUP BY). |
| **Active correlations** | LIVE | `security_correlations` `COUNT(*) WHERE lifecycle='active'`. |
| **High-risk assets** | LIVE | `security_condition_repository.list_asset_ids_with_multiple_active_conditions` (real GROUP BY … HAVING COUNT ≥ 2), enriched with asset name/type + active-condition count. |
| **Asset inventory** | LIVE | `ai_assets` `count_by_type` (real GROUP BY asset_type). |
| **Runtime health** | LIVE | M15 `RuntimeHealthEngine` via `/security-operations/summary.runtime_unhealthy_components` (the 5 real app components). |
| **Validation activity / drift counts / security events** | LIVE | M15 `/security-operations/summary` (unchanged). |
| **Live security activity feed** | LIVE | M15 SSE merged feed (7 sources incl. network drift). Reused. |
| **Top open ports** | LIVE aggregate (new query) | `network_observations` GROUP BY `data->>'port'` WHERE `observation_type='tcp_reachability' AND outcome='reachable'` → port, transport(tcp), distinct-asset count, observation count, max(observed_at). Supporting index `ix_no_org_obstype_outcome`. Drill-down to affected assets. |
| **Service exposure** | LIVE aggregate (new query) | `network_observations` GROUP BY validated protocol WHERE `observation_type='protocol_validation'` — service identity is the validator-confirmed `validated_protocol`, never guessed from a port/banner. |
| **Network drift feed** | LIVE (newly surfaced) | M16 `network_drift_events` via `GET /network-security/drift` + the live feed. |
| **UEBA** | DERIVED (deterministic) | `organization_admin_audit_log` (M17): per-actor admin-action volume (≥10 warning / ≥25 high) and org-wide privilege-change activity (≥5). Each signal links to the exact audit rows. |
| **HBA** | DERIVED (deterministic) | `network_drift_events` host/service categories (ip observed/gone, port reachable/gone). Each signal links to the drift rows. |
| **NBA** | DERIVED (deterministic) | `network_drift_events` protocol/TLS categories (protocol validated/lost/changed, TLS cert changed). Each signal links to the drift rows. |
| **Network map** | LIVE data / new renderer | M4 `security_graph_nodes`/`edges` via `/security-graph`, rendered as a bundled inline-SVG layered node-link graph. Explicitly labelled an **Exposure Relationship graph — not a live-probed topology, not an attack path**. |
| **DMZ / network zones** | LIVE (new, admin-assigned) | `network_zone_assignments` — explicit admin classification only. DMZ overview shows only assets an admin placed in DMZ + their real active-condition counts. Never an IP heuristic. |
| **Connected devices / inventory drill-down** | LIVE | `ai_assets` (asset types incl. AI_AGENT, RAG_SYSTEM, MCP_SERVER, AI_ENDPOINT, HOST, DEVICE, NETWORK, SERVICE, CLOUD_ACCOUNT…). |
| **Open incidents / security work** | LIVE (integration seam preserved) | `/risk-incidents`, `/findings`, `security_correlations` — linked from the command center; no duplicate incident domain created. |
| **System health (CPU/mem/disk)** | NOT CONFIGURED | No host-metric source exists (no psutil). Only the 5 app components are truthfully reported. |
| **Firewall / IDS / IPS** | NOT CONFIGURED | `integration_providers` boundary; no provider wired → reports NOT_CONFIGURED. |
| **Bandwidth / network telemetry** | NOT CONFIGURED | Boundary only; no flow/bandwidth source exists. |
| **ISP / connectivity** | NOT CONFIGURED | Boundary only. |
| **Backup / DR** | NOT CONFIGURED | Boundary only. |
| **Threat intelligence** | NOT CONFIGURED | Boundary only. |
| **Geolocation / attack map** | NOT CONFIGURED | Boundary only; no geo-enrichment source. The map shows real relationship data, never randomly-drawn attacker arcs. |

## 3. Real-time architecture

Reuse of M15 SSE + query-time merge (see §1). Adding the network-drift source was one projector + one merge block + a fixed frontend `SourceDomain` union (the client union previously omitted `network_security`, though the backend already emitted it — corrected). KPI tiles poll `/summary`; the activity stream uses the SSE hook. No new transport, broker, or event table.

## 4. Behavior analytics honesty

UEBA/HBA/NBA are **deterministic rule evaluations** with fixed, documented thresholds and a fixed severity table — never ML, never opaque scoring. Every emitted signal carries `evidence` linking to the exact source rows (`organization_admin_audit_log` entries or `network_drift_events` rows). A signal with no backing rows is never emitted. Auth/login-attempt signals are **not** covered because those events are only written to the structured log, not a queryable table — disclosed as a known limitation, not faked.

## 5. Integration boundaries (NOT CONFIGURED)

The six external-telemetry integrations are provider-neutral boundaries backed by `integration_providers`. With zero rows (the default) every one reports `not_configured`. An org admin (`org:manage`) may register a provider descriptor (`PUT /command-center/integrations/{type}`); config is **allowlisted to non-secret reference fields** (`endpoint`, `region`, `account_ref`, `collector_id`, `description`, `link_name`) and anything resembling a secret is dropped before persistence. A registered-but-no-telemetry provider reports `awaiting_telemetry` — **never a fabricated `active`**, and no metric values are ever synthesized. Every register/disable is audited.

## 6. Security review

- **Tenant isolation:** every command-center query filters by the token-derived `organization_id`; the zone-assignment FK is a composite `(asset_id, organization_id)` making cross-tenant assignment a DB-level impossibility. Covered by adversarial tests.
- **RBAC:** reads gated by `SECURITY_OPERATIONS_READ` (all roles) / `NETWORK_SECURITY_READ`; zone writes by `NETWORK_SECURITY_MANAGE`; integration writes by `ORG_MANAGE`.
- **Suspended membership:** inherited live `is_membership_active` check denies a suspended member's still-valid token.
- **Malformed / unknown IDs:** unknown zone type / integration type → 422; unknown asset → 404; never a 500.
- **No secret leakage:** integration config allowlist + no telemetry payloads stored; the command-center event shape is the bounded M15 `OperationalEvent` with no raw fields.
- **No fabrication:** every not-configured capability's value-emitting code path does not exist; posture has no trend; behavior signals require backing rows.

## 7. Proofs & gates

- **Migration proof:** clean `0001 → 0028 → 0027 → 0028` up/down/up on an isolated disposable database; the two new tables drop and recreate correctly and the supporting index is present.
- **PostgreSQL concurrency proof:** concurrent zone assignment for the same asset converges on exactly one row (the `(organization_id, asset_id)` unique constraint) — see the adversarial test suite.
- **Backend gates:** ruff clean; mypy strict clean (674 source files); adversarial + correctness suite against a dedicated isolated Postgres proof DB; full suite run for no M1–M17 regressions.
- **Frontend gates:** `tsc --noEmit` clean; `npm run build` clean (all 6 new command-center routes compiled); vitest 131/131; `npm audit` unchanged (2 pre-existing moderate `postcss`-via-`next` advisories, breaking-upgrade-only).
- **Browser acceptance:** see the completion checkpoint.

## 8. Known honest limitations

- Six external-telemetry integrations (firewall, bandwidth, ISP, backup/DR, threat-intel, geolocation) are NOT-CONFIGURED boundaries — no provider exists in-environment.
- Host metrics (CPU/mem/disk) are not available (no host-metric source).
- UEBA covers administrative audit events (real, queryable); login/auth-attempt behavioral signals require the generic audit log to be persisted to a queryable table (future work).
- The network map is a relationship graph, deliberately not an attack/exploitability path.
- No posture trend line (no time-bucketed history table).
