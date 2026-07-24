# M37 — RedForge Native SIEM: Frozen Enterprise Architecture Specification

Status: **Architecture only. No code, migrations, APIs, or UI in this milestone.**

## 0. Vision

RedForge's SIEM is not a wrapper around Splunk/Sentinel/Chronicle/QRadar/Elastic — it is a first-class bounded context that ingests, normalizes, stores, correlates, and investigates security events natively, on the same architectural foundation (DDD, Clean Architecture, CQRS-lite, multi-tenancy, repository pattern, DI) already proven across 32+ bounded contexts in this platform. Every other frozen platform capability (Integration Hub, Credential Vault, Knowledge Graph, Risk Engine, Evidence, Identity/RBAC) becomes an *input or consumer* of the SIEM, not a component it reimplements.

The SIEM's job is to answer, at enterprise scale and in real time: **what happened, where, to whom, and does it matter** — durably, tenant-isolated, and fast enough to be a genuine detection-and-response product rather than a log viewer.

## 1. Bounded Context Structure

Following the platform's established one-bounded-context-per-capability convention (`backend/src/<context>/{domain,application,infrastructure,api}`), the SIEM is decomposed into **cooperating bounded contexts** rather than one monolithic `siem` package, because its sub-capabilities have genuinely different scaling, storage, and consistency needs — exactly the reasoning that already split `campaign`/`campaignexecution`/`taskgraph`/`scenario` apart in this codebase rather than merging them.

| Bounded Context | Responsibility | Why separate |
|---|---|---|
| `siem_ingestion` | Accept events from every source (connectors, agents, cloud, network, endpoint, identity, AI, custom); source-adapter registry; backpressure/admission control | High write-throughput, source-adapter churn independent of everything downstream |
| `siem_normalization` | Canonical Event Model (CEM) mapping, schema versioning/evolution | Pure transformation logic, needs independent versioning from storage/detection |
| `siem_storage` | Hot/warm/cold tiering, retention policy enforcement, tenant-isolated storage boundary | Storage lifecycle and cost/retention policy are an operational concern distinct from detection logic |
| `siem_detection` | Rule engine (Sigma-compatible), correlation rules, behavioral/AI-assisted detections | Detection authoring/versioning lifecycle is independent of raw ingestion |
| `siem_correlation` | Multi-event, entity, threat, and campaign correlation | Stateful, windowed processing — different consistency/latency profile than stateless detection rules |
| `siem_investigation` | Timeline construction, evidence graph assembly, incident context aggregation | Read-heavy, cross-context query composition — a CQRS read-side concern |
| `siem_alerting` | Severity, deduplication, suppression, escalation, workflow handoff | Alert lifecycle state machine, analogous to how `incident` already models lifecycle separately from `detection` |
| `siem_search` | Full-text/structured search, aggregations, time-series query surface | A distinct query-engine concern, not a domain concept — thin, mostly infrastructure |
| `siem_analytics` | Dashboards, metrics, detection statistics, trend analysis | Read-model/reporting concern, same shape as the existing `analytics`/`reporting` contexts |

This mirrors the platform's existing pattern of splitting `exposure` from `exposure_reporting`, and `remediation_impact` from `reporting` — computation/domain logic stays separate from its reporting/read-model surface.

**Shared kernel**: the Canonical Event Model (CEM) and its identifiers are the one thing every SIEM sub-context depends on. It lives in a `siem_shared` package (mirroring `redforge/shared/identifiers.py`'s existing role as the one cross-context dependency every bounded context is allowed to take), containing only the CEM value objects, event envelope shape, and versioning contract — no behavior, no infrastructure.

## 2. Domain Model

### 2.1 Canonical Event Model (CEM) — the shared kernel

Every source-specific event (a CloudTrail record, a Sysmon event, an Okta login, an OpenAI API call log) is transformed by `siem_normalization` into one `NormalizedSecurityEvent` shape before anything downstream ever sees it. This is the architectural non-negotiable of the whole SIEM: **no bounded context downstream of normalization understands a vendor/source-specific schema**, exactly matching the Integration Hub's own "no module should understand vendor APIs" principle (ADR-driven precedent already established in this codebase).

`NormalizedSecurityEvent` (value object, immutable, append-only — same immutability principle as `docs/adr/0003-evidence-immutability.md` already established for Evidence):
- `event_id: EntityId` (ULID, canonical platform identifier per ADR-0005)
- `tenant_id: EntityId`
- `occurred_at: datetime` (source-reported time) / `ingested_at: datetime` (platform receipt time) — kept distinct, since detection/correlation windows must be able to reason about ingestion lag
- `source: EventSource` (value object: `source_type` [connector|agent|cloud|network|endpoint|identity|ai|custom], `source_connector_id: EntityId | None` referencing Integration Hub's `ConnectorRegistration`, `vendor: str`)
- `category: EventCategory` (enum: authentication, network, process, file, cloud_api, identity_change, ai_inference, ai_governance, configuration_change, custom, …)
- `actor: EntityRef | None` (subject performing the action — identity, service principal, AI agent)
- `target: EntityRef | None` (object acted upon — asset, resource, another identity)
- `outcome: EventOutcome` (success | failure | unknown)
- `raw_payload_ref: EvidenceRef` (a pointer into the existing Evidence bounded context, **not** the raw payload inline — see §11 Integration; keeps the CEM small and append-only-clean while preserving full fidelity via Evidence's own immutability guarantee)
- `attributes: dict[str, Any]` (schema-versioned, category-specific extension bag — see §2.3 Schema Evolution)
- `schema_version: SchemaVersion` (value object, semantic-versioned)
- `fingerprint: EventFingerprint` (stable hash for idempotent re-ingestion, same design principle as Integration Hub's `AssetIdentity.fingerprint`)

`EntityRef` (value object): a **typed, source-agnostic reference** (`entity_type: EntityRefType` [asset|identity|ai_system|connector|unknown], `entity_id: EntityId | None`, `raw_identifier: str`). `entity_id` is populated only after entity resolution (§11); `raw_identifier` preserves what the source actually said (an IP, a username, an ARN) so correlation can still work before/without resolution.

### 2.2 Aggregates

- **`IngestedEventBatch`** (`siem_ingestion` aggregate) — a bounded, replay-safe unit of admission (not a single event — batching is the throughput-relevant unit). Holds admission decision (accepted/throttled/rejected), source, tenant, batch fingerprint. Raises `EventBatchIngested`/`EventBatchThrottled`.
- **`DetectionRule`** (`siem_detection` aggregate) — versioned rule definition (Sigma-compatible rule body, correlation rule, or behavioral rule reference), lifecycle (draft → active → deprecated), owning tenant (or platform-global for built-in content). Raises `DetectionRuleActivated`/`DetectionRuleDeprecated`/`DetectionRuleVersionPublished`.
- **`CorrelationSession`** (`siem_correlation` aggregate) — a bounded, time-windowed accumulation of related events under evaluation (entity-correlation window, campaign-correlation window). Explicitly bounded lifetime (opens, accumulates, closes/expires) — this is the aggregate most at risk of becoming a "God aggregate" if not kept strictly to correlation bookkeeping; it must never hold detection logic itself (that stays in `siem_detection`'s domain services, invoked by correlation, not embedded in it).
- **`Alert`** (`siem_alerting` aggregate) — severity, dedup key, suppression state, escalation state, workflow status. Raises `AlertRaised`/`AlertDeduplicated`/`AlertSuppressed`/`AlertEscalated`/`AlertAcknowledged`/`AlertClosed`. Deliberately **not** the same aggregate as `incident` (existing bounded context) — an `Alert` is a detection-pipeline output; an `Incident` is a human/workflow construct that may aggregate multiple alerts. `siem_alerting` publishes; `incident` (existing context) subscribes and decides whether to open/attach.
- **`InvestigationTimeline`** (`siem_investigation` aggregate, but predominantly a *read-model* — see CQRS note below) — ordered, cross-source event sequence for a given entity/incident scope.

### 2.3 Schema Evolution & Versioning

`SchemaVersion` is semantic (`major.minor`). Normalizers declare which CEM `major` version they emit. `major` bumps are breaking (require a new normalizer version and a defined migration/backfill strategy at the storage layer — architecture only, no migration code here); `minor` bumps are additive-only within `attributes`. This mirrors how `INormalizer`/`AssetIdentity` versioning already works conceptually in Integration Hub, generalized to events. Every stored event retains its `schema_version` permanently (append-only, per Evidence-immutability precedent) — reprocessing/backfill is a projection concern (same "findings are regenerable from evidence" principle as ADR-0003), never a mutation of stored events.

### 2.4 Domain Events (cross-context integration surface)

- `EventBatchIngested`, `EventBatchThrottled` (ingestion)
- `EventsNormalized`, `NormalizationFailed` (normalization — failures are first-class events, not silent drops, so `siem_analytics` can report normalization health)
- `DetectionMatched` (detection — carries `rule_id`, matched `event_id`(s), confidence)
- `CorrelationSessionOpened`, `CorrelationMatched`, `CorrelationSessionExpired` (correlation)
- `AlertRaised`, `AlertDeduplicated`, `AlertSuppressed`, `AlertEscalated` (alerting)
- `RetentionTierTransitioned`, `RetentionExpired` (storage lifecycle)

All published through the platform event pipeline (§9 — the same real `EventDispatcher` pattern established in Integration Hub Phase 2C, not reinvented).

### 2.5 Commands / Queries (CQRS boundary)

Write side (commands, one per aggregate above): `IngestEventBatch`, `ActivateDetectionRule`, `PublishDetectionRuleVersion`, `RaiseAlert`, `AcknowledgeAlert`, `EscalateAlert`, `OpenCorrelationSession` (internal, not typically externally invoked).

Read side (queries, explicitly separate handlers/read-models, not the same objects as the write-side aggregates — matching the CQRS pattern already used by e.g. `ai_posture`'s query/query-handler split): `SearchEvents`, `GetEventTimeline`, `GetEntityTimeline`, `GetAlertQueue`, `GetDetectionStatistics`, `GetCorrelationGraph`. These are served by `siem_search`/`siem_investigation`/`siem_analytics` against **denormalized read stores**, never against the hot/warm/cold write-optimized event store directly (§4, §8).

## 3. Event Ingestion Layer

Sources map onto Integration Hub's existing connector/plugin abstraction wherever a source *is* a connector (cloud, AI, identity events arriving via an already-registered `ConnectorRegistration`). Sources that are **not** connector-shaped (agent telemetry, raw network taps, custom application events) get a distinct `EventSourceAdapter` port in `siem_ingestion` — deliberately not forced through the connector abstraction, since connectors model *pull-based, credentialed, discoverable* integrations, while raw event ingestion is *push-based, high-volume, streaming*. Conflating the two would be exactly the kind of unnecessary-abstraction the Integration Hub audits (this session) have repeatedly flagged as a smell — two genuinely different shapes should not share one port.

**Admission control**: every batch passes through tenant-scoped rate/quota admission (reusing the *pattern* established by `RateLimitTrackingService` in Integration Hub — same idea, not the same instance, since ingestion volume is orders of magnitude higher and needs a durable, horizontally-scalable budget store, not the in-process dict flagged as a scale risk in the Integration Hub audit — this is an explicit lesson carried forward, not repeated).

**Backpressure**: `IngestedEventBatch.status = THROTTLED` is a first-class outcome, not an error — high-volume sources must degrade gracefully (drop-newest or drop-oldest, tenant-configurable) rather than the ingestion path ever blocking or crashing.

## 4. Event Storage

Three tiers, explicit lifecycle, tenant-isolated at every tier:

- **Hot** — recent (default: 7–30 days, tenant-configurable), optimized for the detection/correlation engines' low-latency read pattern and `siem_search`'s interactive query pattern. Write-optimized, indexed on `tenant_id + occurred_at + category + entity refs`.
- **Warm** — mid-retention (default: 30–365 days), optimized for investigation/timeline reconstruction and analytics aggregation, not sub-second interactive search. Lower cost per event, higher query latency tolerance.
- **Cold archive** — long-retention/compliance (1+ years, tenant/regulatory-driven), write-once, retrieval-on-demand only (not queried in place) — this is where the Evidence bounded context's existing immutability/append-only guarantee is the direct precedent to extend, not reinvent.

**Retention strategy** is a tenant-scoped policy object (`RetentionPolicy`: per-category, per-tier durations), enforced by a scheduled domain process that emits `RetentionTierTransitioned`/`RetentionExpired` events rather than silently deleting — auditable by construction, matching the platform's existing Audit Logging non-negotiable.

**Multi-tenant isolation**: every tier's storage boundary is tenant-partitioned at the physical/logical level appropriate to that tier's technology (this is an architecture decision, not a technology selection — see §21 Trade-offs for why technology choice is deliberately deferred). The one hard requirement carried into implementation: **no query across any tier may execute without a tenant filter compiled in at the query-construction layer**, not left to caller discipline — this is the single most important lesson from this session's own Integration Hub audits (which found tenant scoping was, in practice, consistently applied by convention across ~18 repository methods, but never structurally enforced). For the SIEM, given event volume and blast radius of a mistake, this must be structural: a shared `TenantScopedQueryBuilder` (or equivalent enforced-at-construction-time mechanism) that makes an unscoped query a compile-time/type-level impossibility, not a code-review convention.

## 5. Detection Engine

`DetectionRule` supports three rule shapes behind one domain interface (`IDetectionEvaluator`, evaluated per-event or per-window depending on shape):
1. **Sigma-compatible rules** — parsed into the platform's own rule AST at publish time (not evaluated via an embedded third-party Sigma engine at runtime — parse-once, evaluate-native, so detection evaluation stays in the platform's own performance/observability envelope).
2. **Correlation rules** — declarative multi-event patterns, delegated to `siem_correlation` for actual window/state management; `siem_detection` owns the rule definition, `siem_correlation` owns execution.
3. **Behavioral / AI-assisted detections** — delegate to the existing **AI Security Foundation** and **Risk Engine Foundation** (frozen platform capabilities) via ports, not reimplemented inside the SIEM. `siem_detection` calls out to a `IBehavioralScoringPort`/`IAnomalyDetectionPort` exactly the way Integration Hub calls out to `ICredentialVaultPort` — the SIEM does not own behavioral modeling, it consumes it.

Rule lifecycle (draft/active/deprecated) and versioning matches `DetectionRule`'s aggregate design above — this reuses the exact "plugin/registry, additive, open-closed" shape that the Integration Hub audit called out as the *one* unambiguously well-designed piece of that context (`NormalizerRegistry`) — deliberately repeated here as a proven pattern, not coincidence.

## 6. Correlation Engine

- **Time windows**: `CorrelationSession` is explicitly bounded and expiring — no unbounded state accumulation. Window size is a rule-level parameter, not a global constant.
- **Entity correlation**: joins events sharing a resolved `EntityRef.entity_id` (post entity-resolution, §11) within a session window.
- **Threat correlation**: joins against the existing **Attack Library** (frozen platform capability) and threat intelligence context — the SIEM does not maintain its own threat-actor/TTP taxonomy, it references the existing one.
- **Campaign correlation**: joins against the existing `campaign`/`campaignexecution` bounded contexts' data *for red-team/validation context*, and separately supports detecting a genuine *adversary* campaign pattern (multi-stage, multi-entity) — these are two different meanings of "campaign" in this platform (red-team-authored vs. adversary-observed) and must never be conflated in the domain model; the SIEM's `CorrelationSession` only ever means the latter.

**This is explicitly the highest-execution-risk component** (see §22 Risks) — correlation is the one place where naive design becomes an unbounded-memory/unbounded-fan-out problem at real event volume. The architecture commits to bounded, expiring sessions and rule-scoped windows specifically to avoid the "God aggregate accumulating forever" failure mode.

## 7. Investigation Engine

Read-model composition, not new domain logic: `InvestigationTimeline` and `EvidenceGraph` (the SIEM's contribution, distinct from but linked to the existing Evidence bounded context's own graph/immutability model) are built by **querying**, not owning:
- Timeline: ordered `NormalizedSecurityEvent` read-model, scoped to an entity or alert/incident.
- Evidence graph: extends the existing **Knowledge Graph** (frozen platform capability) with SIEM-sourced nodes/edges (events, alerts, correlation sessions) rather than building a second, parallel graph store — this is a direct, explicit application of the "no duplicate abstractions" instruction governing this whole milestone.
- Related assets/identities/AI systems: resolved via the existing Asset Inventory, Identity, and AI Security Foundation contexts' own query ports — the SIEM never duplicates asset/identity data, it references it by `EntityId`.

## 8. Alert Pipeline

`Alert` lifecycle: `RAISED → (DEDUPLICATED | SUPPRESSED) → ESCALATED → ACKNOWLEDGED → CLOSED`, with suppression rules and dedup keys as tenant-configurable policy objects (same "policy as data, not code" pattern already used by `RetentionPolicy` above and by existing contexts like `remediation_impact`'s scope adapters). Escalation is a domain event (`AlertEscalated`) consumed by the existing `incident` bounded context to decide incident creation/attachment — the SIEM does not own incident workflow, only alert-to-incident handoff.

## 9. Event Flow (textual sequence)

```
Source (connector | agent | cloud | network | endpoint | identity | ai | custom)
  → siem_ingestion.IngestEventBatch (admission control, backpressure)
  → EventBatchIngested (domain event)
  → siem_normalization (source adapter → CEM mapping, schema-versioned)
  → EventsNormalized (domain event) | NormalizationFailed (domain event)
  → siem_storage (hot tier write, tenant-partitioned)
  → [parallel fan-out via platform event dispatcher, not sequential blocking:]
       → siem_detection (per-event rule evaluation) → DetectionMatched?
       → siem_correlation (session accumulation) → CorrelationMatched?
       → siem_analytics (streaming metrics update)
  → (DetectionMatched | CorrelationMatched) → siem_alerting.RaiseAlert
  → AlertRaised (domain event)
  → incident (existing context, subscriber) — decides incident creation
  → siem_investigation — timeline/evidence-graph queries, on demand, read-only
  → siem_storage lifecycle worker — hot → warm → cold → expire, independent background process
```

The fan-out after storage is explicitly **parallel/asynchronous, not a sequential pipeline call chain** — detection, correlation, and analytics each subscribe to `EventsNormalized` independently. This avoids the single biggest anti-pattern this session's Integration Hub audits found repeatedly: a synchronous call chain masquerading as an event-driven design, with no real pub/sub underneath. The SIEM must not repeat that mistake at the component that will see the platform's highest event volume.

## 10. Search Architecture

`siem_search` is a thin, mostly-infrastructure bounded context (a query-translation/aggregation layer, minimal domain logic of its own) fronting whichever tier(s) a query needs, chosen automatically by the query's own time-range (a query spanning only the last 24h never touches warm/cold). Full-text, structured, aggregation, and time-series query shapes are each a distinct query-handler (CQRS read side, §2.5) rather than one generic "search everything" endpoint — this keeps each query shape independently optimizable and matches the platform's existing preference for explicit, narrow query handlers over generic query builders exposed to callers.

## 11. Integration with Existing Platform Contexts

| Existing context | Integration shape |
|---|---|
| **Integration Hub** | Source of connector-originated events (cloud/AI/identity categories) and the source of asset/connector identity referenced by `EntityRef`. `siem_ingestion` subscribes to Integration Hub's discovery/sync domain events where relevant (e.g. `AssetDiscovered` can itself be a SIEM-relevant event), but the SIEM never duplicates Integration Hub's own asset model — it references `EntityId`s. |
| **Credential Vault** | The SIEM never touches raw source credentials directly for connector-shaped sources — those flow through Integration Hub's existing `ICredentialVaultPort`-mediated connectors. Non-connector sources (agents) authenticate via their own enrollment/identity mechanism (architecture placeholder — agent identity/enrollment is out of this milestone's scope, flagged as a Future Extension Point, §19). |
| **Knowledge Graph** | Extended, not duplicated (§7) — SIEM nodes/edges are a new node/edge *type* in the existing graph, not a parallel graph. |
| **Risk Engine Foundation** | `siem_detection`'s behavioral/AI-assisted rule shape consumes Risk Engine scoring via a port; conversely, `DetectionMatched`/`AlertRaised` events are a genuine input signal *back* into Risk Engine's own scoring (a bidirectional but decoupled relationship — each side depends only on the other's published events/ports, never on internals). |
| **Evidence** | `NormalizedSecurityEvent.raw_payload_ref` points into Evidence — Evidence's existing append-only/immutable guarantee (ADR-0003) is reused wholesale for raw event payload storage rather than the SIEM building a second evidence store. |
| **Findings** | `DetectionMatched`/`AlertRaised` are candidate inputs to Findings generation (existing context) — architecture placeholder for exact mapping, deferred as a Future Extension Point since Findings' current triggering model needs its own review before this binding is finalized. |
| **Asset Inventory** | Referenced, not duplicated — `EntityRef` resolution against Asset Inventory's existing query ports. |
| **Identity/RBAC** | SIEM API/query access is gated by the existing platform RBAC (no new permission model invented) — new permission scopes are added (`siem:read`, `siem:detection:manage`, `siem:alert:manage`, etc.) following the existing RBAC scope-naming convention, not a parallel authorization system. |
| **AI Security Foundation** | Both a *source* (AI event category in the CEM) and a *consumer* (behavioral/AI-assisted detection delegates to it) — bidirectional, decoupled via ports both ways, same shape as Risk Engine above. |
| **Attack Library** | Referenced by correlation for TTP/threat-actor context (§6) — not duplicated. |
| **Provider Framework** | If/when the SIEM needs to *export* to or *ingest from* external SIEMs (Sentinel, Splunk, etc. — explicitly a *future*, not current, capability), that integration is a Provider Framework plugin, not a SIEM-internal connector reimplementation — reuses the platform's existing extension mechanism rather than inventing a second one. |
| **Future Cloud Security / Vulnerability Engine / SOAR** | All three are natural downstream consumers of `AlertRaised`/`DetectionMatched`/correlation output via the same domain-event subscription pattern used above — no bespoke integration needed per future context, which is the direct payoff of committing to real pub/sub now (§9). |

## 12. Scalability Strategy

- Ingestion and normalization scale horizontally and independently of storage/detection (stateless, partition by tenant+source).
- Detection (per-event, stateless rule evaluation) scales horizontally trivially.
- Correlation (stateful, windowed) scales by **session partitioning** (tenant + entity/rule-scoped session ownership, not global shared state) — this is the load-bearing scalability decision for the whole SIEM, since correlation is the one genuinely stateful hot-path component.
- Storage tiers scale independently per tier, each with its own cost/performance profile.
- No component in this architecture is designed as a single global bottleneck; every fan-out point in §9's event flow is partition-able by tenant at minimum, and by tenant+entity for correlation specifically.

## 13. Multi-Region & High Availability

Tenant data residency (region pinning) is a first-class attribute of tenant configuration (reusing the existing multi-tenancy foundation's tenant-config model, not inventing a new one) — a tenant's hot/warm/cold storage and ingestion path are pinned to their configured region(s). Cross-region SIEM capability (e.g. a global tenant with regional subsidiaries) is an explicit Future Extension Point (§19), not solved in this milestone. HA within a region follows the same active-active/stateless-where-possible principle as §12 — the only genuinely stateful component (correlation sessions) is the one component requiring explicit HA design attention (session state must be recoverable/rebuildable from the hot event store on node failure, not held only in a single process's memory — direct lesson carried from the Integration Hub audit's finding that in-memory `CircuitBreakerService`/`RateLimitTrackingService` state doesn't survive restarts or replicas).

## 14. Disaster Recovery

Cold archive is the DR baseline (durable, write-once, geographically redundant per whatever the platform's existing storage DR posture is — not re-specified here, reused). Hot/warm tiers are recoverable-from-cold with a defined (not yet quantified in this architecture-only milestone) RPO/RTO, since they are performance tiers of the same durable event stream, not independent sources of truth — the cold archive is the single source of truth; hot/warm are accelerated views over it, which is itself a scalability/DR design decision worth stating explicitly as an ADR-level choice (see §20).

## 15. Performance Strategy

Deferred to implementation phases per this milestone's explicit non-goals — the one architecture-level commitment made here is the tiering + partition strategy above; specific throughput targets, indexing strategy, and technology selection are implementation-phase decisions, not architecture-freeze decisions, and are explicitly out of scope per the milestone's own instructions.

## 16. Security Model

- Tenant isolation: structural, not conventional (§4).
- RBAC: extends existing platform RBAC, no parallel model (§11).
- Secrets: never handled directly by the SIEM for connector-sourced events (delegated to Integration Hub/Credential Vault, §11); non-connector source authentication (agents) is a Future Extension Point requiring its own security review before implementation.
- Raw payload handling: routed through Evidence's existing immutability/access-control model (§11), not a new storage-and-access-control surface.
- Audit: every SIEM domain event (§2.4) is itself audit-loggable via the platform's existing Audit Logging capability — the SIEM does not need a bespoke audit trail, its own domain events already constitute one, consistent with how Evidence's immutability was designed to make audit "inherent," per ADR-0003.

## 17. Extension Framework

- New event sources: implement `EventSourceAdapter` (connector-shaped) or register a `ConnectorPlugin` extension (Integration-Hub-shaped) — no core changes required, matching the Integration Hub's own "future connectors require zero redesign" principle, now extended to event sources generally.
- New detection rule shapes: implement `IDetectionEvaluator` — the rule-shape abstraction is intentionally the one open extension point in `siem_detection`.
- New normalizers: register against `siem_normalization`'s registry, same open/closed shape as Integration Hub's `NormalizerRegistry` (explicitly reused, not reinvented, per §5).
- New correlation patterns: declarative rule definitions against the existing `CorrelationSession` execution model — no new session-management code needed per pattern.

## 18. Deployment Topology (architecture-level only)

Each SIEM bounded context deploys as an independently scalable unit (consistent with how the rest of the platform's bounded contexts already compose into one FastAPI app today, but explicitly designed so `siem_ingestion`/`siem_normalization`/`siem_correlation` — the throughput-sensitive components — *can* be split into independently-deployed services later without a domain-model change, since bounded-context boundaries already match deployment-unit boundaries by construction). No specific infrastructure/technology is selected in this milestone (explicit non-goal).

## 19. Future Extension Points (explicitly deferred, not designed here)

- Agent identity/enrollment model (§11, §16).
- Cross-region tenant SIEM topology (§13).
- External SIEM export/ingest via Provider Framework (§11).
- Findings-generation binding from `DetectionMatched`/`AlertRaised` (§11).
- SOAR integration (playbook-triggered response from alerts) — natural consumer of `AlertRaised`, not designed further here.
- Sigma rule marketplace/community-content ingestion — the rule *shape* (§5) supports it; the content-distribution mechanism is undesigned.

## 20. Key Architectural Decisions (ADR-style summary)

1. **Multiple cooperating bounded contexts, not one `siem` monolith** — because ingestion/normalization/storage/detection/correlation/investigation/alerting/search/analytics have genuinely different scaling and consistency profiles (§1). Rejected alternative: single `siem` context — would recreate the exact "God module" risk this session's Integration Hub audits repeatedly flagged at smaller scale.
2. **Canonical Event Model as a shared kernel, not per-context duplication** — one immutable, versioned event shape, matching the "no module understands vendor APIs" principle already proven in Integration Hub (§2.1).
3. **Correlation sessions are explicitly bounded/expiring, partitioned by tenant+entity** — the single highest-risk scalability decision in this architecture; rejected alternative (unbounded global correlation state) was ruled out specifically because of lessons from the Integration Hub audit's in-memory-state findings (§6, §12, §13).
4. **Real async pub/sub fan-out after storage, not a sequential call chain** — direct correction of the exact anti-pattern (constructed-but-undispatched events, or synchronous chains dressed as event-driven) found repeatedly in this session's audits of the existing platform (§9).
5. **Storage tiering with cold archive as source of truth, hot/warm as accelerated views** — enables independent scaling and a clean DR story without inventing a second consistency model (§4, §14).
6. **Alert (SIEM) and Incident (existing context) are deliberately distinct aggregates** — avoids collapsing a detection-pipeline concept into a human-workflow concept, preserving both contexts' independent evolution (§2.2, §8).
7. **No duplicate graph/asset/identity/threat-intel stores** — Knowledge Graph, Asset Inventory, Identity, and Attack Library are extended/referenced, never re-implemented inside the SIEM (§7, §11).
8. **Non-connector-shaped sources get their own adapter port, not forced through the Integration Hub connector abstraction** — two genuinely different shapes (pull/credentialed/discoverable vs. push/streaming/high-volume) should not share one abstraction (§3).

## 21. Trade-offs

- Splitting into 9 cooperating bounded contexts (§1) adds coordination overhead (more explicit integration points, more domain events to design/version) versus a single context — accepted deliberately, because the alternative's failure mode (a God-context) is worse at this scale and was directly observed as a real problem pattern in this session's audits of a *much smaller* context.
- Deferring technology/storage-engine selection (§4, §15, §18) means this architecture cannot yet be validated against real throughput numbers — accepted because this milestone is explicitly architecture-only; technology selection belongs to an implementation-phase spike, not this freeze.
- Treating cold archive as source-of-truth (§4, §14) trades faster hot-tier recovery flexibility for a simpler, single-consistency-model DR story — accepted as the right trade for a security product where "we lost the audit trail" is a worse failure than "hot-tier recovery took longer than ideal."

## 22. Risks

- **Correlation engine is the component most likely to be under-designed at architecture-freeze time relative to its real complexity** (§6) — flagged explicitly rather than glossed over; recommend a dedicated architecture spike specifically for `siem_correlation`'s session-partitioning and windowing semantics before implementation begins, even though this document commits to the bounded/partitioned approach at a high level.
- **Agent identity/enrollment is undesigned** (§19) — any source category relying on agents cannot be implemented until this gap is closed; not a blocker for connector-shaped sources.
- **Cross-context event volume** — nine cooperating contexts publishing/subscribing to a shared event pipeline at SIEM-scale volume is a genuinely new load profile for the platform's existing event-dispatch mechanism (proven only at Integration Hub's much smaller scale in Phase 2C) — recommend a load-bearing validation of the platform event pipeline itself before committing SIEM implementation to it unmodified.
- **Findings integration is deferred** (§19) — means the SIEM's detection output and the platform's existing Findings concept could drift out of sync if implementation proceeds on both fronts before this binding is designed.

## 23. Architecture Review

**Is the architecture stable?** Yes, at the level this milestone requires — bounded-context decomposition, CEM shared kernel, and integration points are internally consistent and each traceable to a precedent already proven elsewhere in this platform (normalizer registries, immutable evidence, ports over concrete cross-context imports, real event dispatch). No component invents a new architectural pattern the rest of the platform doesn't already use.

**Is it scalable?** Directionally yes — every component is partition-able, and the one genuinely stateful component (correlation) has an explicit partitioning strategy rather than being left unaddressed. Not yet *proven* scalable, since technology/throughput decisions are explicitly deferred (§15, §18) — this is appropriate for an architecture-only milestone, not a gap in the architecture itself.

**Is it maintainable?** Yes — the decomposition follows the same reasoning that already justified splitting other multi-part capabilities in this platform (`campaign`/`campaignexecution`/`taskgraph`, `exposure`/`exposure_reporting`), and every integration point reuses an existing platform mechanism rather than inventing a parallel one, directly minimizing future architectural drift.

**Is it production ready?** No — and it should not be, since this is explicitly an architecture-only milestone with no code. "Production ready" is not the right question to ask of this deliverable; the right question is whether it is *implementation-ready*, and the answer is: mostly, with three named exceptions (§22) that should be resolved — at least at a design-spike level — before implementation begins on `siem_correlation` specifically, on agent-sourced ingestion, and on the Findings integration binding.

**Would this be approved for a trillion-dollar-scale enterprise cybersecurity platform?** As an architecture, yes, conditioned on the three risks in §22 receiving dedicated attention before their respective implementation phases start — not as blanket blockers to freezing the overall architecture, but as named, tracked pre-implementation work items for those three specific sub-areas.

## 24. Freeze Recommendation

# ARCHITECTURE FREEZE APPROVED

**with three named pre-implementation spikes required before their respective areas begin implementation**, not before the freeze itself:
1. `siem_correlation` session-partitioning/windowing detailed design (§6, §22).
2. Agent identity/enrollment model (§11, §16, §19, §22).
3. Findings integration binding (§11, §19, §22).

The remaining 17 scope areas (§3–§5, §7–§10, §12–§18, §20–§21) are frozen as specified and ready for implementation planning without further architecture-level rework.
