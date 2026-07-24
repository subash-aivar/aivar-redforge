# M42 — Native SIEM Implementation Master Plan

Status: **Planning only. No code, migrations, APIs, or UI in this milestone.**

Source of truth: `m37-native-siem-architecture.md` (all section refs below are M37 §N unless stated otherwise), amended by the additive governance layer in `m41-cross-domain-architecture-consolidation.md` (cited as M41 ADR-Gn). This plan does not redesign anything M37 or M41 already decided — it sequences it.

## 0. Governance amendments this plan bakes in from day one

Per M41, four ADRs apply to M37 as soon as any implementation work starts (M41 was explicit these are applied at implementation time, not by editing M37's document):

- **ADR-G1**: `siem_alerting`'s Risk Engine integration is implemented against `IRiskContributionPort` from the start — not the ad hoc relationship M37 §11 originally described before that port existed.
- **ADR-G3**: the event M37 names `AlertRaised` is implemented under the canonical name `SIEMFindingOpened` (M37's own document is unchanged; this plan's Phase 8 deliverable uses the canonical name, with `Alert` as the aggregate's continuing domain name per ADR-G2's equivalence).
- **ADR-G4**: every cross-aggregate reference (`EntityRef` usage in `NormalizedSecurityEvent.actor`/`.target`, per M37 §2.1) is implemented as the platform-wide `EntityRef` type, not a SIEM-local lookalike.
- **ADR-G6**: any relationship edge `siem_investigation`'s evidence graph produces (M37 §7) uses Integration Hub's existing `RelationshipType` enum, extended additively only if a genuinely new relationship semantic is needed — confirmed, not assumed, in Phase 9.

## 1. Phase Dependency Graph

```
Phase 1 (Domain Foundation)
  └─> Phase 2 (Canonical Event Model)
        └─> Phase 3 (Ingestion Pipeline) ──────────────┐
              └─> Phase 4 (Normalization Engine)        │
                    └─> Phase 5 (Storage Layer)          │
                          ├─> Phase 6 (Detection Engine) │
                          ├─> Phase 7 (Correlation Engine)│  (6 & 7 parallel-safe,
                          │         └─> Phase 8 (Alert Pipeline)   both consume Phase 5's
                          └─> Phase 9 (Investigation Engine)       output independently)
                                └─> Phase 10 (Search)
                                      └─> Phase 11 (Analytics)
                                            └─> Phase 12 (Reporting)
Phase 13 (Performance) ── cross-cutting, starts after Phase 8, continues through Phase 12
Phase 14 (Security Hardening) ── cross-cutting, starts after Phase 3, continues through Phase 12
Phase 15 (Enterprise Validation) ── final, depends on all above
```

Phases 6 and 7 may run concurrently (different teams/sessions) once Phase 5 is done, since detection is per-event/stateless while correlation is stateful/windowed — they share no write path. Phase 9 (Investigation) can also start once Phase 5 lands, in parallel with 6/7/8, since it is a pure read-model consumer of stored events and does not depend on detection/correlation output existing yet (though it becomes materially more useful once Phase 8 exists). Phases 13 and 14 are explicitly not "a phase you do once at the end" — they are continuous validation gates re-run after every phase from 3 onward, formalized as recurring checkpoints rather than a single terminal phase, with Phase 13/14's own numbered sections below describing what "done" means for the *cumulative* cross-cutting work by the time Phase 15 starts.

## 2. Implementation Order Rationale (safest path)

The order above is chosen specifically to avoid repository-wide refactoring and keep every phase independently verifiable, matching the platform's own working conventions observed throughout this session (Integration Hub Phase 2A → 2B → 2C landed incrementally, each phase's own quality gates run and verified before the next began):

1. **Domain-first, infrastructure-second**: Phases 1–2 produce pure domain code (aggregates, value objects, the CEM) with no database, no API, no UI — cheaply testable in isolation, and any modeling mistake caught here costs nothing to fix (contrast: a modeling mistake caught after Phase 5's storage schema exists costs a migration).
2. **One new bounded context's write path fully proven before the next context's write path starts**: Phase 3 (ingestion) must be solid — tested, admission-controlled, backpressure-verified — before Phase 4 (normalization) consumes its output, exactly mirroring Integration Hub's own proven discipline of finishing discovery before building the normalization layer on top of it.
3. **Storage (Phase 5) is deliberately mid-sequence, not first**: writing `siem_storage`'s hot/warm/cold tiering against a still-changing CEM (Phases 1–2) would risk exactly the kind of premature-schema-commitment this platform's own M38/M39 architecture reviews repeatedly warned against (e.g. M38's own retrospective finding that Integration Hub's early schema decisions needed a corrective migration once real query patterns emerged, per the Integration Hub Phase 2C `0155` migration precedent) — Phase 5 happens only once the CEM (Phase 2) and its actual write pattern (Phase 3/4) are proven, not before.
4. **Detection/Correlation/Alerting (6→7→8) sequenced, not parallelized with each other's *dependent* phase**: Phase 8 depends on both 6 and 7's output shape being stable (an alert can originate from either a detection match or a correlation match, per M37 §9's event flow), so Alert Pipeline is correctly sequenced last of the three even though Detection and Correlation can build concurrently.
5. **Read-side (9→10→11→12) sequenced after write-side is proven**: Investigation/Search/Analytics/Reporting are all CQRS read-models (M37 §2.5) — building them against an unstable write-side would mean repeatedly rebuilding read-models as the write-side changes; sequencing them after Phase 8 (once the full write path, including alerting, is proven) minimizes rework, except Phase 9 which can start slightly earlier per §1's parallelism note since it only needs stored events, not alerts.
6. **Performance and Security Hardening are continuous, not terminal**: matching this session's own repeated lesson from the Integration Hub freeze work — verifying quality gates only at the very end (rather than after each phase) is exactly how regressions went undetected until a late-stage full-suite run caught them. This plan requires gate re-verification after every phase, not a single Phase 13/14 pass at the end.

## 3. Phase-by-Phase Plan

### Phase 1 — SIEM Domain Foundation

- **Objective**: stand up the `siem_shared` shared kernel and the skeleton of all nine bounded contexts (M37 §1) with domain-layer-only code — no infrastructure, no persistence.
- **Scope**: `siem_shared` (identifiers, `EntityRef` reuse per ADR-G4), and for each of `siem_ingestion`/`siem_normalization`/`siem_storage`/`siem_detection`/`siem_correlation`/`siem_investigation`/`siem_alerting`/`siem_search`/`siem_analytics`: package scaffolding matching the platform's established `{domain,application,infrastructure,api}` layout, with `domain/` populated for the aggregates each context owns per M37 §2.2 (`IngestedEventBatch`, `DetectionRule`, `CorrelationSession`, `Alert`, `InvestigationTimeline`) — application/infrastructure/api left empty until their respective phases.
- **Dependencies**: none (first phase).
- **Deliverables**: 9 bounded-context skeletons; `siem_shared` package; domain-layer aggregates/value-objects/events for all 9 contexts per M37 §2.2/§2.3/§2.4, written but not yet wired to anything.
- **Acceptance Criteria**: every aggregate constructible and unit-testable in isolation; domain layer has zero infrastructure imports (verified the same way Integration Hub's `test_architecture.py` already enforces this platform-wide convention — extend that test's module enumeration to include the 9 new contexts); `EntityRef`/`RelationshipType` reuse confirmed at the type level (ADR-G4/G6), not redefined locally.
- **Risks**: none of consequence — this is the lowest-risk phase in the plan by design (§2.1).
- **Estimated complexity**: Low.
- **Testing strategy**: pure unit tests, no fixtures beyond in-memory value construction. Architecture-conformance test extended to cover the 9 new contexts (§5).

### Phase 2 — Canonical Event Model

- **Objective**: finalize `NormalizedSecurityEvent` (M37 §2.1) as production-shaped domain code, including schema-versioning machinery (M37 §2.3).
- **Scope**: `siem_shared`'s CEM value objects (`EventSource`, `EventCategory`, `EntityRef` per ADR-G4, `EventOutcome`, `SchemaVersion`, `EventFingerprint`); the `INormalizer`-equivalent port contract each source-adapter will implement in Phase 4 (defined here, implemented later — matching how M37 §2.1 itself frames normalization as "no module downstream... understands a vendor schema," which requires the *contract* to exist before any concrete normalizer).
- **Dependencies**: Phase 1 (`siem_shared`, `EntityRef`).
- **Deliverables**: CEM value objects; `INormalizedEventPort`/equivalent; a documented `major.minor` versioning policy (what constitutes a breaking vs. additive change, per M37 §2.3) as an actual written convention, not just a value object.
- **Acceptance Criteria**: CEM round-trips through serialization with schema-version fidelity in unit tests; the versioning policy document exists and is referenced by every subsequent phase that touches CEM shape.
- **Risks**: getting the CEM's `attributes` extension-bag shape wrong here is expensive to fix later (every downstream context consumes it) — this phase should include a deliberate "sanity check against at least 3 divergent real source shapes" exercise (e.g. sketch how a CloudTrail event, a Sysmon event, and an OpenAI API log would each map into this CEM, without actually building the normalizers yet) before declaring the CEM final, precisely because M37 §2.3 stakes so much on this one shape being right.
- **Estimated complexity**: Medium (the design-validation exercise, not the code itself, is what makes this non-trivial).
- **Testing strategy**: unit tests for CEM construction/validation/versioning; a written (not automated) design-review checklist artifact confirming the 3-source sanity check was actually performed.

### Phase 3 — Event Ingestion Pipeline

- **Objective**: implement `siem_ingestion`'s admission control, backpressure, and `IngestedEventBatch` write path (M37 §3), for both connector-shaped and non-connector-shaped sources.
- **Scope**: `EventSourceAdapter` port (M37 §3, deliberately distinct from Integration Hub's `ConnectorPlugin` per M37's own reasoning) for push-based sources; connector-shaped sources register directly against Integration Hub's existing `ConnectorPlugin`/`DiscoveryPage` contract (reused, not reimplemented); tenant-scoped admission/quota store — explicitly **not** an in-process dict (M37 §3 names this as a direct, deliberate correction of the Integration Hub audit's flagged in-memory-state risk) — durable, horizontally-shareable from day one.
- **Dependencies**: Phase 2 (CEM shape informs what a batch actually carries pre-normalization — raw payloads at this stage, not yet CEM-shaped, but the batch envelope references the eventual schema version it targets).
- **Deliverables**: `IngestedEventBatch` write path; admission-control durable store; at least one connector-shaped source proven end-to-end (reusing an existing Integration Hub connector is acceptable for proof purposes) and one push-based source stub proven against `EventSourceAdapter`.
- **Acceptance Criteria**: a batch that exceeds tenant quota is throttled (`THROTTLED` status, M37 §3), not dropped/errored; admission-control state survives a process restart (durable store requirement verified by an actual restart-and-check test, not just code review); zero synchronous blocking under simulated high-volume load in a load test (§4).
- **Risks**: this is the first phase touching real infrastructure (a durable admission store) — the specific risk named in M37 §22/M41 finding #7 (SIEM ingestion volume as a genuinely new, unvalidated load profile for the platform's event pipeline) starts becoming concretely testable here for the first time, and this phase's exit criteria should include an initial (not final) load-shape sanity check, not deferred entirely to Phase 13.
- **Estimated complexity**: Medium-High (the durable, horizontally-shareable admission store is genuinely new infrastructure for this platform, not a reuse of an existing pattern).
- **Testing strategy**: unit (admission logic), integration (durable store round-trip, restart survival), initial load test (order-of-magnitude volume, not final performance validation — that's Phase 13).

### Phase 4 — Normalization Engine

- **Objective**: implement `siem_normalization`'s source-adapter-to-CEM mapping (M37 §2.1, §2.3).
- **Scope**: concrete normalizers for the sources proven in Phase 3; `NormalizationFailed` event handling (M37 §2.4 — failures are first-class, not silent drops); the schema-version-declaration mechanism per normalizer.
- **Dependencies**: Phase 3 (ingestion must produce batches to normalize).
- **Deliverables**: 2+ concrete normalizers (matching Phase 3's proven sources); `EventsNormalized`/`NormalizationFailed` events real and dispatched (not constructed-and-discarded — the M37-established non-negotiable, verified explicitly in this phase's acceptance criteria, not assumed).
- **Acceptance Criteria**: a malformed/unexpected source payload produces `NormalizationFailed` with enough diagnostic detail to be actionable (not a bare exception), never a silent drop or a crash; `siem_analytics`'s eventual normalization-health reporting (Phase 11) is provably wireable against these events now (i.e., the event shape is confirmed sufficient before Phase 11 needs it, avoiding a Phase-11-triggered rework of Phase 4).
- **Risks**: normalizer-per-source content is exactly the kind of "registry-driven, additive, open/closed" pattern this platform has now proven four times (M38 §5) — the risk here is not the pattern, it's under-testing the *failure* path, which is easy to under-invest in relative to the happy path.
- **Estimated complexity**: Medium.
- **Testing strategy**: unit (mapping correctness per normalizer, using recorded/fixture source payloads, not live vendor calls); explicit failure-path tests (malformed payload → `NormalizationFailed`, never a crash).

### Phase 5 — Storage Layer

- **Objective**: implement `siem_storage`'s hot/warm/cold tiering, retention policy enforcement, and the structural tenant-isolation mechanism M37 §4 names as its single most important requirement.
- **Scope**: hot-tier write path (from Phase 4's `EventsNormalized` output); `RetentionPolicy` value object and its enforcement worker (emitting `RetentionTierTransitioned`/`RetentionExpired`, never silent deletion); the `TenantScopedQueryBuilder`-equivalent mechanism M37 §4 requires ("no query across any tier may execute without a tenant filter compiled in... not left to caller discipline") — this is the one piece of Phase 5 that is not optional/deferrable, given M37's own explicit framing of it as "the single most important lesson" carried into this milestone.
- **Dependencies**: Phase 4 (needs `EventsNormalized` events to store).
- **Deliverables**: hot-tier storage with the structural tenant-scoping mechanism; retention policy enforcement worker; warm/cold tier *design* proven with at least a stub/interface-level implementation (full warm/cold buildout may reasonably extend past this phase's minimum bar into Phase 13's performance-hardening pass, but the tenant-isolation mechanism must be complete for all three tiers' *interfaces* even if warm/cold's actual storage backend is provisional).
- **Acceptance Criteria**: an attempt to construct an unscoped query is a compile-time/type-level impossibility (or the closest practical equivalent in the implementation language), not merely a convention — verified by a test that specifically tries to bypass tenant scoping and confirms it cannot compile/construct, not just that it "usually" filters correctly; retention enforcement is auditable (emits events, doesn't silently delete) verified by an actual test asserting an event fires before/at expiry.
- **Risks**: this is the highest-consequence phase in this plan for the "structural tenant isolation" requirement — a mistake here has the worst blast radius of anything in this plan (cross-tenant data exposure in a security product), and M37's own text names this explicitly as the platform's most important carried-forward lesson from the Integration Hub audits' finding that tenant scoping was previously "consistently applied by convention... never structurally enforced." This phase must not repeat that pattern.
- **Estimated complexity**: High.
- **Testing strategy**: unit + integration (tenant-isolation-bypass-attempt tests are the load-bearing test class here, not incidental coverage); a dedicated security-review checkpoint (Phase 14 gate, pulled forward specifically for this phase given its risk profile) before Phase 6 begins.

### Phase 6 — Detection Engine

- **Objective**: implement `siem_detection`'s three rule shapes (M37 §5) against the now-stored, tenant-scoped event stream.
- **Scope**: `IDetectionEvaluator` port; Sigma-compatible rule parsing (parse-once-at-publish, evaluate-native, per M37 §5's explicit rejection of an embedded runtime Sigma engine); `DetectionRule` lifecycle (draft/active/deprecated) reusing the now-quadruple-proven registry pattern; behavioral/AI-assisted detection delegation via port to Risk Engine/AI Security Foundation (referenced, not reimplemented, per M37 §5).
- **Dependencies**: Phase 5 (needs queryable, tenant-scoped stored events).
- **Deliverables**: `IDetectionEvaluator` + at least one concrete Sigma-compatible rule evaluated end-to-end against real stored events; `DetectionMatched` events real and dispatched.
- **Acceptance Criteria**: a published rule's parse step rejects malformed Sigma content at publish time (not at evaluation time, per the parse-once design) with an actionable error; `DetectionMatched` carries enough context (rule_id, matched event_id(s), confidence) to be independently useful to both Phase 8 (alerting) and future SOAR consumers without needing a follow-up query.
- **Risks**: low relative to Phase 5 — this phase inherits Phase 5's tenant-isolation guarantee rather than introducing new isolation risk, and the registry/plugin pattern is well-proven platform-wide.
- **Estimated complexity**: Medium.
- **Testing strategy**: unit (rule parsing, evaluation logic against fixture events); integration (a rule genuinely fires against genuinely stored events, not a mocked storage layer, at least once).

### Phase 7 — Correlation Engine

- **Objective**: implement `siem_correlation`'s bounded, tenant+entity-partitioned `CorrelationSession` (M37 §6).
- **Scope**: session open/accumulate/expire lifecycle; entity correlation (post-entity-resolution `EntityRef.entity_id` joins); threat correlation (Attack Library reference, not duplication); explicit exclusion of unbounded/global session state, per M37 §6's own framing of this as the architecture's highest-execution-risk component.
- **Dependencies**: Phase 5 (stored events), Phase 6 can run concurrently (§1) — correlation rules reference `siem_detection`'s rule-definition ownership per M37 §5 point 2 ("`siem_detection` owns the rule definition, `siem_correlation` owns execution") but does not require Phase 6 to be *complete* to begin its own session-management work, only to be far enough along that the rule-definition contract is stable.
- **Deliverables**: `CorrelationSession` lifecycle; at least one working correlation rule (multi-event, time-windowed) proven against real stored events; `CorrelationSessionOpened`/`CorrelationMatched`/`CorrelationSessionExpired` events real and dispatched.
- **Acceptance Criteria**: a session genuinely expires (bounded lifetime enforced, not merely documented) under test; no unbounded memory growth under a sustained-load test with continuously arriving, non-matching events (a session that never closes because nothing ever "finishes" it is exactly the failure mode M37 §6/§22 names as the top architecture risk, and this phase's acceptance criteria must specifically test for it, not just test the happy-path match case); session state is recoverable/rebuildable from the hot event store on simulated node failure (M37 §13's HA requirement, tested here rather than deferred).
- **Risks**: the single highest-risk phase in this entire plan, matching M37's own explicit flag (§6, §22) — an under-designed correlation engine is the architecture's most likely source of a genuine production incident (unbounded memory, missed detections from premature session expiry, or state loss on restart). This phase should not be considered done on "it compiles and one test passes" — the negative-case tests (non-expiring sessions, memory growth, restart-state-loss) are the actual bar.
- **Estimated complexity**: High (the highest of any phase in this plan, consistent with M37's own risk assessment).
- **Testing strategy**: unit; integration; a dedicated sustained-load/soak test specifically targeting session-lifetime and memory-growth behavior (not merely a smoke test) — this is the one phase where "testing strategy" and "risk mitigation" are effectively the same activity.

### Phase 8 — Alert Pipeline

- **Objective**: implement `Alert` (M37 §2.2, §8) — severity, dedup, suppression, escalation, workflow handoff to `incident` — using the canonical `SIEMFindingOpened` event name per ADR-G3, and `IRiskContributionPort` for risk contribution per ADR-G1.
- **Scope**: `Alert` aggregate lifecycle; dedup-key/suppression-rule policy objects (tenant-configurable, registry-content pattern); `siem_alerting`'s subscription to both `DetectionMatched` (Phase 6) and `CorrelationMatched` (Phase 7) as alert-raising triggers; `incident` context subscription wiring (existing platform context, subscriber only — `siem_alerting` does not own incident-creation logic, per M37 §8/§11).
- **Dependencies**: Phase 6 and Phase 7 (both are legitimate alert sources).
- **Deliverables**: full `Alert` lifecycle (`RAISED → DEDUPLICATED|SUPPRESSED → ESCALATED → ACKNOWLEDGED → CLOSED`, M37 §8); `SIEMFindingOpened` (canonical name) dispatched and independently consumable by `incident`; `IRiskContributionPort` implementation live.
- **Acceptance Criteria**: two detections that should dedupe (same dedup key) genuinely produce one alert, not two, under test; `incident`'s existing subscription mechanism receives a real `SIEMFindingOpened` event and can decide incident creation without any SIEM-side code change (proving the decoupling, per M37 §8's explicit "SIEM does not own incident workflow" boundary); Risk Engine receives a real contribution via the port, not a stub.
- **Risks**: the dedup/suppression policy logic is easy to get subtly wrong in ways that either flood the queue (under-dedup) or hide real alerts (over-suppress) — both failure modes should have explicit test coverage, not just "the happy path dedupes correctly."
- **Estimated complexity**: Medium-High.
- **Testing strategy**: unit (lifecycle transitions, dedup/suppression logic including both failure-mode directions above); integration (real end-to-end: detection/correlation match → alert → incident subscription fires → Risk Engine contribution recorded).

### Phase 9 — Investigation Engine

- **Objective**: implement `siem_investigation`'s timeline/evidence-graph read-model composition (M37 §7), confirming `RelationshipType` reuse per ADR-G6.
- **Scope**: `InvestigationTimeline` read-model (ordered CEM events scoped to entity/alert/incident); Knowledge Graph extension (new node/edge types for SIEM data, not a parallel graph — M37 §7's explicit constraint) using Integration Hub's existing `RelationshipType` vocabulary, extended additively only if genuinely needed (confirmed here per ADR-G6, not assumed).
- **Dependencies**: Phase 5 (stored events); can start in parallel with Phases 6–8 per §1, though its usefulness compounds once Phase 8 exists (alerts/incidents to build timelines around).
- **Deliverables**: timeline query handler; evidence-graph Knowledge-Graph extension; a confirmed (not assumed) statement of which `RelationshipType` members SIEM-produced edges use, and whether any genuinely new member was needed (if so, added additively to the one enum, per ADR-G6, never as a parallel vocabulary).
- **Acceptance Criteria**: a timeline query for a real entity/alert returns correctly ordered, cross-source events without an N+1 query pattern (explicit anti-pattern check, given this exact defect class was found repeatedly in this platform's own prior Integration Hub audits); Knowledge Graph extension is additive (existing non-SIEM graph queries unaffected, verified by re-running Knowledge Graph's own existing test suite unmodified).
- **Risks**: Medium — the main risk is accidentally building a second, parallel graph store instead of correctly extending Knowledge Graph (the exact mistake M37 §7 explicitly warns against), which should be caught by the acceptance criterion above rather than discovered later.
- **Estimated complexity**: Medium.
- **Testing strategy**: unit (query composition logic); integration (real cross-source timeline assembly); N+1-detection test (query-count assertion, not just correctness).

### Phase 10 — Search

- **Objective**: implement `siem_search`'s tier-aware query translation/aggregation surface (M37 §10).
- **Scope**: distinct query-handler-per-shape (full-text, structured, aggregation, time-series, per M37 §10's explicit rejection of one generic "search everything" endpoint); automatic tier selection by query time-range.
- **Dependencies**: Phase 5 (all three tiers must exist, even if warm/cold are still Phase-5-provisional).
- **Deliverables**: 4 distinct query handlers; tier-selection logic proven against queries spanning hot-only, hot+warm, and warm+cold ranges.
- **Acceptance Criteria**: a query scoped entirely within the hot-tier range never touches warm/cold (verified by an actual query-plan/call-count assertion, not just correct results); each query shape is independently paginated/bounded (no unbounded-result-set risk, the exact defect class M38's own Integration Hub audit found and had to retrofit — this phase should not need a later corrective pass for the same mistake).
- **Risks**: Low-Medium — mostly a risk of repeating the specific "unbounded query, no pagination" defect this platform has already paid down once (Integration Hub Phase 2C); this phase's acceptance criteria exist specifically to prevent a repeat.
- **Estimated complexity**: Medium.
- **Testing strategy**: unit; integration; explicit pagination/bounding tests per query shape.

### Phase 11 — Analytics

- **Objective**: implement `siem_analytics`'s dashboards/metrics/detection-statistics/trend-analysis read-side (M37 §11 implicit "thin, mostly infrastructure" treatment, consistent with M38 §15/M39's equivalent).
- **Scope**: metrics aggregation over Phases 3–9's events (ingestion volume, normalization health from Phase 4's `NormalizationFailed`, detection/correlation match rates, alert queue depth/aging); no new domain logic.
- **Dependencies**: Phases 3–9 (needs real events from every upstream phase to have anything to aggregate).
- **Deliverables**: metrics read-models for each of the above categories.
- **Acceptance Criteria**: normalization-health metrics genuinely reflect Phase 4's `NormalizationFailed` events (proving the "confirmed wireable" acceptance criterion from Phase 4 was correct); no double-counting/drift between raw event counts and aggregated metrics under test.
- **Risks**: Low.
- **Estimated complexity**: Low-Medium.
- **Testing strategy**: unit; integration (metrics accuracy against known fixture event volumes).

### Phase 12 — Reporting

- **Objective**: implement scheduled/on-demand reporting over Phase 11's analytics read-models.
- **Scope**: report generation/export, reusing whatever reporting-export mechanism the platform's existing `reporting` bounded context already provides (checked and reused, not reimplemented — consistent with this plan's own "reuse, don't rebuild" discipline applied to itself).
- **Dependencies**: Phase 11.
- **Deliverables**: at least one real scheduled report definition proven end-to-end.
- **Acceptance Criteria**: report output matches Phase 11's underlying metrics exactly (no independent recomputation drift).
- **Risks**: Low.
- **Estimated complexity**: Low.
- **Testing strategy**: integration (report content vs. source metrics equivalence).

### Phase 13 — Performance (cross-cutting, continuous from Phase 3 onward, formalized here)

- **Objective**: consolidate and formally validate the load-shape/throughput characteristics flagged as unvalidated risk in M37 §22 and M41 finding #7, closing that repeatedly-raised-but-never-closed governance item.
- **Scope**: ingestion throughput under realistic multi-tenant load; correlation-session memory/CPU behavior under sustained load (extending Phase 7's soak test to production-representative volume); storage-tier query latency across hot/warm/cold; end-to-end pipeline latency (ingest → normalize → store → detect/correlate → alert).
- **Dependencies**: all of Phases 3–8 functionally complete (this phase validates, it does not build new functionality).
- **Deliverables**: a load-test report with concrete throughput/latency numbers per stage; explicit answer to M37 §22's named risk ("is this a genuinely new load profile the platform's existing event pipeline hasn't been proven at") — closed with evidence, not re-flagged a fourth time (per M41's explicit escalation of this exact risk).
- **Acceptance Criteria**: no stage exhibits unbounded resource growth under sustained load; documented throughput numbers exist for capacity planning (even if final production tuning is out of this plan's scope, per M37's own explicit deferral of specific throughput targets to implementation, §15 of M37).
- **Risks**: if this phase surfaces a genuine architectural bottleneck (not just a tuning issue), that finding must go back to an architecture-review process, not be silently worked around in implementation — named explicitly so a real problem here isn't quietly absorbed as "just needs more optimization."
- **Estimated complexity**: Medium-High (test infrastructure/harness work, not application code).
- **Testing strategy**: dedicated load/soak testing, distinct from and in addition to each phase's own unit/integration suites.

### Phase 14 — Security Hardening (cross-cutting, continuous from Phase 3 onward, formalized here)

- **Objective**: consolidate tenant-isolation, credential-handling, and audit-completeness verification across all 9 contexts, with Phase 5's tenant-isolation mechanism as the anchor already-tested item (pulled forward per Phase 5's own note) rather than a first-time check here.
- **Scope**: re-verify structural tenant isolation across every repository method added in Phases 3–12 (not just Phase 5's storage layer — detection/correlation/alerting/investigation/search/analytics/reporting all add their own query surfaces that must inherit, not merely assume, Phase 5's guarantee); credential handling for any connector-shaped source (must be `ICredentialVaultPort`-mediated, zero exceptions, matching every prior milestone's identical commitment); RBAC scope wiring (`siem:*` scopes per M37 §16); audit-log completeness (every domain event in M37 §2.4 genuinely reaches the platform's Audit Logging capability, not just theoretically capable of it).
- **Dependencies**: all of Phases 3–12.
- **Deliverables**: a security-review checklist with pass/fail per item above, per bounded context.
- **Acceptance Criteria**: zero unscoped-query findings across all 9 contexts (an actual audit pass, not a spot-check); zero direct-credential-handling findings; every domain event confirmed to reach audit logging.
- **Risks**: the primary risk this phase exists to catch is exactly the class of defect this session's own Integration Hub audits found repeatedly (tenant scoping "consistently applied by convention... never structurally enforced," a credential-vault port defined-but-bypassed) — this phase is this plan's explicit defense against repeating those specific, previously-documented mistakes in a new bounded-context family.
- **Estimated complexity**: Medium (mostly verification/audit work against already-built code, not new implementation).
- **Testing strategy**: security-focused integration tests (cross-tenant-leak-attempt tests per repository method, credential-never-logged assertions); manual/agent-assisted audit pass against the checklist, not purely automated.

### Phase 15 — Enterprise Validation

- **Objective**: final, holistic validation that the full M37 SIEM, as actually implemented across Phases 1–14, matches the frozen architecture and is genuinely ready for production use.
- **Scope**: full quality-gate re-run (backend tests/mypy/ruff, frontend typecheck/tests/build, migration validation) across the complete SIEM implementation; browser verification of every workflow named in M37's scope (dashboard-equivalent views, discovery/ingestion status, detection rule management, alert queue, investigation timeline, search); architecture-conformance re-validation against M37's frozen document (does the actual implementation still match §1's bounded-context list, §2's aggregate/event/command/query inventory, §11's integration points) — an explicit "does implementation drift from the frozen architecture" check, not assumed clean by construction.
- **Dependencies**: all prior phases.
- **Deliverables**: a final validation report structured identically to the Integration Hub freeze-verification reports already produced in this session (ground-truth-verified quality-gate numbers, not agent-claimed ones; honest browser-verification results, including explicit documentation of anything that couldn't be verified rather than fabricated).
- **Acceptance Criteria**: matches this session's own established bar for "ready" — real, independently-verified test/lint/typecheck numbers; real (or honestly-documented-as-blocked) browser verification; zero unresolved P0-severity findings from Phase 14's security review; Phase 13's performance findings either closed or explicitly carried forward as named, tracked operational debt (not silently dropped).
- **Risks**: the main risk at this final phase is scope-creep temptation (discovering a "nice to have" mid-validation and quietly implementing it, drifting from M37's frozen scope) — this phase's discipline is explicitly to validate against what was frozen, not to extend it.
- **Estimated complexity**: Medium (validation effort, not new implementation).
- **Testing strategy**: the full quality-gate suite defined in §4 below, run in totality for the first and only time as a single combined pass (each phase already ran its own subset; this is the first point all of it runs together).

## 4. Quality Strategy

- **Unit testing**: per-phase, per-aggregate/value-object/domain-service — the majority of test volume, matching this platform's existing convention of thousands of fast unit tests per bounded context.
- **Integration testing**: per-phase, against real (not mocked) infrastructure for that phase's own scope (real durable admission store in Phase 3, real stored events in Phases 6/7/9/10) — this plan explicitly requires integration tests to exist per phase, not deferred to Phase 15.
- **Contract testing**: for every cross-context port introduced or reused (`IRiskContributionPort`, `EntityRef`, `RelationshipType`, `ICredentialVaultPort`, Integration Hub's `ConnectorPlugin`/`DiscoveryPage`) — a contract test confirming SIEM's usage matches the port's actual current shape, catching drift the way M41's own review found drift between M37's original design and M38's later port introduction (ADR-G1) — this plan's contract-testing requirement exists specifically so that kind of drift is caught automatically going forward, not rediscovered by a future M-numbered governance review.
- **Performance testing**: Phase 13, formalized as described above.
- **Security testing**: Phase 14, formalized as described above, plus the pulled-forward tenant-isolation-bypass-attempt tests in Phase 5.
- **Browser validation**: Phase 15 (the SIEM has no meaningful UI to browser-test before then, since Phases 1–12 are backend/domain-focused per this plan's phase ordering — UI/frontend requirements were deliberately not broken out as their own numbered phase in this plan, since M37's own scope treats dashboards/investigation/search views as read-side consumers of the backend work; frontend implementation should track Phases 9–12's backend read-models incrementally in practice, but this plan's phase *gates* are backend-first by design, consistent with §2's domain-first rationale).
- **Architecture conformance validation**: extend the platform's existing `test_architecture.py`-style enforcement (already proven in Integration Hub) to cover all 9 SIEM contexts from Phase 1 onward, not introduced late — domain-layer purity, no repository-pattern bypass, no direct cross-context concrete imports (the exact credential-vault-port-bypass defect class found and fixed in Integration Hub) checked continuously, every phase, not just at Phase 14/15.

## 5. Risk Register

| Risk | Phase(s) | Severity | Mitigation in this plan |
|---|---|---|---|
| Correlation engine unbounded state / memory growth | 7 | Critical | Dedicated soak testing, explicit negative-case acceptance criteria (§Phase 7) |
| Cross-tenant data exposure via unscoped query | 5, 14 | Critical | Structural (not conventional) tenant-scoping mechanism required as Phase 5's non-optional deliverable; re-audited every phase in Phase 14 |
| SIEM ingestion volume as unvalidated load profile (M37 §22, M41 finding #7) | 3, 13 | High | Initial load sanity-check pulled into Phase 3's own acceptance criteria; formally closed with evidence in Phase 13, not deferred a fourth time |
| CEM shape wrong, expensive to fix once contexts are built on it | 2 | High | Deliberate multi-source sanity-check exercise required before Phase 2 exit, before any downstream phase begins |
| Credential-vault-port-style bypass recurrence (proven defect class from Integration Hub) | 3, 14 | Medium | Contract testing (§4) + Phase 14's explicit audit checklist item |
| N+1 query pattern recurrence (proven defect class from Integration Hub) | 9, 10 | Medium | Explicit query-count assertion tests named in both phases' acceptance criteria |
| Unbounded/unpaginated result sets recurrence (proven defect class from Integration Hub Phase 2C) | 10 | Medium | Explicit pagination/bounding test requirement in Phase 10's acceptance criteria |
| Alert dedup/suppression logic under- or over-firing | 8 | Medium | Explicit bidirectional test requirement (both failure modes, not just happy path) |
| Knowledge Graph accidentally forked into a parallel store | 9 | Medium | Explicit acceptance criterion re-running Knowledge Graph's own existing test suite unmodified |
| Scope creep at final validation phase | 15 | Low-Medium | Explicit discipline named in Phase 15's risk entry — validate against frozen scope, don't extend it |
| Event-naming/contract drift from M41's governance ADRs | All | Low | ADRs G1/G3/G4/G6 baked into Phase 1/2/8/9 deliverables explicitly, not left to individual implementer discretion |

## 6. Exit Criteria Summary (per phase, condensed)

1. Domain Foundation: all 9 contexts scaffolded, domain layer pure, architecture-conformance test passes.
2. CEM: multi-source sanity check performed and documented; CEM round-trips in tests.
3. Ingestion: durable admission control survives restart; throttling (not dropping/erroring) proven; initial load sanity-check done.
4. Normalization: failure path never silently drops; events real and dispatched.
5. Storage: structural tenant-scoping proven unbypassable; retention enforcement auditable.
6. Detection: end-to-end rule match against real stored events proven.
7. Correlation: sessions provably bounded/expiring; no unbounded memory growth under soak test; restart-recoverable.
8. Alerting: dedup/suppression correct in both directions; `incident` decoupling proven; Risk Engine contribution live.
9. Investigation: cross-source timeline correct, no N+1; Knowledge Graph extension additive, not forked.
10. Search: tier-selection correct and query-count-verified; all 4 query shapes bounded/paginated.
11. Analytics: metrics accuracy verified against fixture volumes.
12. Reporting: report content matches source metrics exactly.
13. Performance: load-shape risk formally closed with evidence.
14. Security: zero unscoped-query findings, zero direct-credential-handling findings, full audit-log coverage confirmed.
15. Enterprise Validation: full quality-gate suite green (or honestly documented gaps), architecture-conformance re-confirmed against the frozen M37 document, browser verification real or honestly blocked-and-documented.

## 7. Overall Definition of Done

The M37 Native SIEM implementation is Done when: all 15 phases' exit criteria (§6) are met; the Phase 15 validation report shows real (independently-verified, not agent-claimed) quality-gate numbers with zero unresolved Critical/High risks from §5; M41's governance ADRs (G1/G3/G4/G6) are confirmed implemented, not merely planned; the implementation matches the frozen M37 architecture document with any necessary drift explicitly documented and justified rather than silent; and Phase 13/14's cross-cutting performance/security work has run continuously through the whole implementation, not been bolted on at the end.

## 8. Readiness Statement

This plan is a sequencing of already-frozen architecture (M37) and already-adopted governance decisions (M41) — it introduces no new design decisions of its own, consistent with this milestone's explicit constraint. Given that, and given every phase has concrete, testable acceptance criteria and an identified risk-mitigation strategy proportionate to its actual risk (correlation and storage correctly receiving the most scrutiny, matching M37's own architecture review's risk ranking):

**This implementation plan is ready to begin coding, starting at Phase 1.**

The one caveat worth stating plainly rather than glossing over: Phase 2's CEM sanity-check and Phase 5's tenant-isolation mechanism are both named in this plan as harder and more consequential than their phase numbering alone might suggest — an implementer should not read "Phase 2" and "Phase 5" as "early, therefore simple." Budget accordingly.
