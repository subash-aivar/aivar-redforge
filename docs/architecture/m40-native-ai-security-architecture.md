# M40 — RedForge Native AI Security Platform: Frozen Enterprise Architecture Specification

Status: **Architecture only. No code, migrations, APIs, or UI in this milestone.**

## 0. Vision

RedForge's AI Security platform is not a wrapper around Protect AI/Lakera/HiddenLayer/Robust Intelligence/Microsoft or Google AI Security — it is the fifth cooperating pillar in this platform's native security-domain family (alongside M37 SIEM, M38 Cloud Security, M39 Vulnerability Engine), and unlike those three, it does **not** start from zero: three bounded contexts already exist and are confirmed, by direct inspection of this codebase, to already own real domain concepts — `ai_posture` (`AISystemAsset`, `AIThreatProfile`, `AIRiskScoreSnapshot`, `AIComplianceMapping`, `ShadowAIAlert`), `ai_agent_governance` (`AgentOperationalEnvelope`, `AgentDeviationEvent`), and `ai_supply_chain` (`ModelProvenance`, `ModelBillOfMaterials`, `AIDiscoveryScanRun`) — plus an existing AI Red Team Foundation (`red_team_operator`, `campaign`, `autonomous_intelligence`'s adaptive intelligence layer). **This milestone's primary architectural discipline is therefore not "design new domain concepts" — it is "correctly extend, connect, and fill genuine gaps in what already exists, without duplicating any of it."** That constraint is stated up front because it is the single most important thing distinguishing M40 from M37/M38/M39, all three of which were greenfield.

## 1. What Already Exists (verified, not assumed) — the baseline this milestone extends

| Existing context | Confirmed aggregates | What it already owns |
|---|---|---|
| `ai_posture` | `AISystemAsset`, `AIThreatProfile`, `AIRiskScoreSnapshot`, `AIComplianceMapping`, `ShadowAIAlert` | AI asset registration, per-asset threat profiling, risk scoring snapshots, compliance mapping, shadow-AI (undiscovered/unsanctioned AI usage) alerting. **This is the existing AI Asset Inventory + AISPM + AI Risk Scoring + AI Compliance foundation** — M40's Scope items 1, 3, 15, 16 must extend this context, not recreate it. |
| `ai_agent_governance` | `AgentOperationalEnvelope`, `AgentDeviationEvent` | Agent behavioral-boundary definition and deviation detection — **this is the existing foundation for Scope item 8 (Agent Security)**, specifically the "envelope" concept is the natural home for tool-permission/delegation boundaries, not a new concept. |
| `ai_supply_chain` | `ModelProvenance`, `ModelBillOfMaterials`, `AIDiscoveryScanRun` | Model provenance tracking, SBOM-equivalent-for-models, discovery scan runs — **this is the existing foundation for Scope item 11 (Model Security)**, specifically provenance/version-governance. |
| `red_team_operator`, `campaign`, `autonomous_intelligence` | `RedTeamOperator`, campaign orchestration, `IntelligenceSuggestion`/adaptive intelligence layer (per this session's own memory of Sprint 36/37 — "Adaptive AI Red Team Intelligence Layer," deferred-completion-contract, recommended-vs-applied injection distinction) | **This is the existing AI Red Team Foundation** referenced in the milestone background — active offensive validation of AI systems already exists; M40 Scope item 7 (AI Red Team Engine Integration) is explicitly an *integration*, not a new red-team engine. |

Everything in §2 onward is scoped against this baseline: new bounded contexts are introduced **only** where a genuine gap exists (runtime/inline detection of prompt injection, jailbreaks, guardrail violations; MCP-specific security; RAG-specific security), and existing contexts are extended by reference/event, never re-implemented.

## 2. Ubiquitous Language

- **AI Asset** — already `AISystemAsset` (`ai_posture`); this document does not redefine it. New AI asset *sub-types* introduced here (MCP Server, RAG Pipeline, AI Agent as a distinct addressable entity, AI Gateway) are modeled as `AISystemAsset` specializations, per the same "specialize, don't compete" discipline M38 used for `CloudResource` extending `DiscoveredAsset` (§2.1 of M38).
- **Guardrail** — a tenant-configurable, versioned policy that constrains AI input/output/tool-use at runtime; distinct from a **Detection Rule** (M37 concept, reused not reinvented here, §6) in that a guardrail is *preventive/blocking*, evaluated inline in the request path, while a detection rule is *observational*, evaluated on ingested events after the fact. This distinction is load-bearing: guardrails have a hard latency budget (they sit in the live inference path); detections do not.
- **Prompt Injection** (direct) vs. **Indirect Prompt Injection** — direct: malicious instruction in the user's own prompt. Indirect: malicious instruction smuggled in via retrieved content (a RAG document, a tool's output, a web page an agent fetched) that the model treats as trusted context. These require **structurally different detection mechanisms** (direct injection is inspectable at the prompt-ingestion boundary; indirect injection requires inspecting *retrieved/tool-sourced content* specifically, which is why RAG Security and Prompt Security are kept as related-but-distinct capabilities, §10).
- **Jailbreak** — an attempt to subvert a model's own safety alignment/system-prompt constraints (distinct from prompt injection, which subverts the *application's* intent — a jailbreak can succeed with no injection at all, e.g. a purely social-engineering prompt against the base model).
- **Agent Delegation** — one AI agent invoking/tasking another agent or tool on its own initiative, without a fresh human-originated request; the trust-boundary-defining event for multi-agent security (§8).
- **Trust Boundary** (AI-specific) — per this milestone's explicit review requirement, every place where content crosses from an untrusted origin (user input, retrieved document, tool output, another agent's output) into a context the model/agent will treat as instructions-or-fact is a trust boundary, and this document requires every such boundary to be explicitly named, not implicit (§8, §9, §10, §22).
- **MCP** (Model Context Protocol) — a tool-exposure/capability-invocation protocol between an AI system and external tools/data; modeled here as a first-class trust boundary, not a generic "connector," because an MCP server can dynamically declare capabilities at runtime in a way ordinary API connectors cannot, which materially changes the security model (§9).

## 3. Bounded Context Structure

| Bounded Context | Responsibility | Relationship to existing contexts |
|---|---|---|
| `ai_discovery` | AI-specific discovery (models, agents, RAG pipelines, MCP servers, prompts-as-assets, tools, plugins, AI APIs, AI workflows) across sanctioned and shadow usage | **New context, but built entirely on Integration Hub** (§4) — feeds discovered assets into `ai_posture`'s existing `AISystemAsset`/`ShadowAIAlert`, does not maintain a parallel registry. |
| `ai_prompt_security` | Prompt injection (direct + indirect) detection, prompt leakage detection, prompt tampering detection | **New context** — this is a genuine gap; nothing in `ai_posture`/`ai_agent_governance`/`ai_supply_chain` does inline prompt-content security analysis. |
| `ai_jailbreak_detection` | Jailbreak attempt detection | **New context**, kept separate from `ai_prompt_security` per the Ubiquitous Language distinction above — different signal shape (alignment-subversion patterns vs. instruction-injection patterns), plausibly different detection models. |
| `ai_guardrail` | Guardrail policy definition, versioning, and **inline** validation (the one component in this entire architecture with a hard synchronous-latency requirement) | **New context** — genuine gap; `ai_agent_governance`'s `AgentOperationalEnvelope` is a *behavioral boundary* concept (what an agent is allowed to do over time), while a guardrail is a *per-request* inline check (is this specific input/output allowed right now) — related but operationally distinct, kept separate rather than overloading `AgentOperationalEnvelope` with a latency-critical inline-evaluation responsibility it wasn't designed for. |
| `mcp_security` | MCP-specific: tool exposure inventory, capability validation, permission boundaries, trust model, protocol validation | **New context** — MCP's dynamic capability-declaration model is genuinely distinct from Integration Hub's static connector-plugin model (§9); not forced into the connector abstraction. |
| `rag_security` | Retrieval validation, document-poisoning detection, vector-DB protection posture, context isolation enforcement, data-leakage detection | **New context** — genuine gap, though it consumes `ai_posture` asset data for the RAG pipeline itself and `mcp_security`/`ai_prompt_security` for indirect-injection-via-retrieval overlap (§10). |
| `ai_runtime_monitoring` | Inline/near-real-time observation of AI request/response traffic — the substrate `ai_prompt_security`, `ai_jailbreak_detection`, and `ai_guardrail` all evaluate against | **New context**, deliberately thin: this is the AI-domain equivalent of M37's `siem_ingestion`, and in fact **is** partially M37 reused — high-volume AI request/response telemetry is exactly the shape M37's ingestion layer was built for (§12). `ai_runtime_monitoring`'s own responsibility is narrowly the AI-specific *framing* (associating traffic with an `AISystemAsset`, a session, an agent-delegation chain) before handing off to M37 for actual ingestion/storage. |
| `ai_threat_detection` | Correlates `ai_runtime_monitoring` + `ai_prompt_security` + `ai_jailbreak_detection` + `mcp_security` + `rag_security` signals into AI-specific threat patterns (e.g. a multi-turn jailbreak escalation, a coordinated indirect-injection-then-delegation chain) | **New context**, the AI-domain analogue of M37's `siem_correlation`/`siem_detection` — and explicitly should reuse M37's detection-rule/correlation-session machinery rather than reinventing it (§6, §12), the same "reuse, don't rebuild" discipline M38/M39 already applied to Integration Hub's discovery machinery. |
| `ai_findings` | AI-specific finding lifecycle | **New context**, the fifth instance of the now-proven Alert/CloudFinding/VulnerabilityFinding/`AIFinding` pattern (§14) — no longer worth re-justifying at length, this is a settled platform convention. |

**Explicitly not new bounded contexts** (the discipline this milestone is graded on):
- AI asset inventory, AI risk scoring, AI compliance mapping, shadow-AI detection → **`ai_posture`, extended, not recreated.**
- Agent behavioral boundaries, tool-permission-over-time, agent identity → **`ai_agent_governance`, extended.**
- Model provenance, version governance, BOM → **`ai_supply_chain`, extended.**
- AI red-teaming/offensive validation → **`red_team_operator`/`campaign`/`autonomous_intelligence`, integrated with, not reimplemented** (§7).
- Event ingestion/storage/correlation-session machinery → **M37, reused** (§12).
- Risk scoring → **Risk Engine Foundation, contributed to via `IRiskContributionPort`** (the same port M38 and M39 both already extend, §15) — the fourth consecutive milestone to make this exact choice, now unambiguously a fixed platform contract rather than a per-milestone decision.

**Shared kernel**: `ai_security_shared` — `AISystemAssetRef` (referencing `ai_posture`'s existing aggregate), `TrustBoundaryType` enum, `AISessionRef` — no behavior, the same minimal-shared-kernel discipline as every prior milestone.

## 4. AI Discovery Engine

Built entirely on Integration Hub, identical commitment to M38 §3: AI-specific sources (an LLM gateway's API, an agent orchestration platform, an MCP registry, a vector database's admin API) are `ConnectorPlugin`s using the existing paginated `DiscoveryPage` contract. `ai_discovery`'s normalizers map raw discovery payloads not to a new asset type but to `ai_posture`'s existing `AISystemAsset` (with sub-type discriminators for model/agent/RAG-pipeline/MCP-server/prompt/tool/plugin/AI-API/AI-workflow) — this directly closes Scope item 1 without inventing a competing inventory. Shadow AI discovery (unsanctioned usage — e.g. traffic to an unregistered LLM API detected via `ai_runtime_monitoring`/network egress patterns) feeds `ai_posture`'s **existing** `ShadowAIAlert` aggregate, confirmed already present — this is a gap-fill of an existing concept's data source, not a new concept.

## 5. AI Security Posture Management (AISPM)

**Not a new bounded context.** AISPM as a capability is the composition of `ai_posture`'s existing `AISystemAsset` + `AIThreatProfile` + `AIComplianceMapping` with this milestone's new signal sources (`ai_prompt_security`, `mcp_security`, `rag_security`, `ai_supply_chain`'s model provenance) feeding into it via domain events, exactly as M38's `cloud_exposure` was "a pure aggregation/read-model context... computes nothing... aggregates and presents" (§9 of M38) over `cloud_graph`/`ciem`/`cwpp`. AISPM here is the identical shape: a read/aggregation surface over `ai_posture` plus this milestone's new detection contexts, not a tenth bounded context.

## 6. Prompt Security Engine, Jailbreak Detection Engine

Both consume `ai_runtime_monitoring`'s framed traffic (§12) and are implemented as **detection-rule content** against M37's existing rule-evaluator shape (`IDetectionEvaluator`, §5 of M37) — a `PromptInjectionRule`/`JailbreakPatternRule` is a new *rule shape* registered against the same extensible detection-rule abstraction M37 already defined as its one open extension point (§17 of M37: "New detection rule shapes: implement `IDetectionEvaluator`"), not a parallel rule engine. This is the clearest, most direct payoff of M37's own architecture decision showing up three milestones later exactly as intended.

Indirect prompt injection specifically requires `ai_prompt_security` to receive **content-provenance-tagged** input (is this text user-authored or retrieved/tool-sourced?) — this tagging is `rag_security`'s and `mcp_security`'s responsibility to attach at the trust boundary (§10, §9), not something `ai_prompt_security` can reconstruct after the fact. This dependency is named explicitly because it is easy to under-specify: indirect-injection detection is architecturally impossible without upstream provenance tagging, so that tagging is elevated here to a first-class cross-context contract, not an implementation detail.

## 7. AI Red Team Engine Integration

Explicitly an **integration**, not a new engine, per Scope item 7's own framing and this milestone's baseline (§1). The existing `red_team_operator`/`campaign`/`autonomous_intelligence` foundation already performs active offensive validation against AI systems; the integration point is: (a) `ai_discovery`/`ai_posture` assets are the target inventory red-team campaigns already select against (referenced, not duplicated — the existing campaign-to-target binding presumably already does this, verify at implementation time rather than assumed here), and (b) this milestone's new passive/defensive detection contexts (`ai_prompt_security`, `ai_jailbreak_detection`, `ai_guardrail`) are natural **validation targets** for red-team campaigns — i.e., the existing AI Red Team Foundation should be able to test whether M40's own defenses actually catch known attack patterns, closing the loop between offense and defense within the platform. This bidirectional relationship (red team validates defenses; defenses' findings inform future red-team scenario selection, echoing this session's own memory of the "recommended vs. applied injection distinction" from the adaptive intelligence layer) is named as the integration shape; the exact event contract is left to implementation.

## 8. Agent Security

Tool permissions and agent identity extend `ai_agent_governance`'s existing `AgentOperationalEnvelope` (the natural home for "what is this agent allowed to do," already established) rather than a new permission model. **Agent memory** and **agent delegation** are the two genuinely new concepts this milestone must add: `AgentMemoryRef` (a reference to an agent's persistent/session memory store, with an explicit security concern — memory poisoning, where an attacker plants content in an agent's memory for a later session to act on, is a distinct trust-boundary crossing from prompt injection, since it exploits *temporal* trust rather than *immediate-context* trust) and `AgentDelegationEvent` (extending `ai_agent_governance`'s existing `AgentDeviationEvent` concept — a delegation is itself deviation-detectable: does this agent's `AgentOperationalEnvelope` actually permit delegating to this target agent/tool?). **Multi-agent security** is the composition of per-agent envelope enforcement plus delegation-chain validation — explicitly named as one of this document's required trust boundaries (§22), not a separately new concept beyond the two above.

## 9. MCP Security

MCP's dynamic capability declaration is the architectural reason `mcp_security` is not modeled as an ordinary Integration Hub connector: an MCP server can expose a *different* tool/capability set at different times, and a connector's static `ConnectorPlugin` capability-negotiation model (Integration Hub's own recently-hardened P1 feature, per the Integration Hub session history) assumes capabilities are relatively stable, catalog-listed facts — MCP requires **runtime capability validation** (does the tool set an MCP server is claiming *right now* match what was previously trusted/reviewed?), which is a genuinely new concern. `mcp_security` owns: tool-exposure inventory (referencing `ai_posture`'s `AISystemAsset` for the MCP server itself, per §4), capability-validation-at-connect-time and capability-drift-detection-over-time, permission-boundary enforcement (an MCP tool invocation is itself a trust-boundary crossing, evaluated by `ai_guardrail`, §6), and MCP protocol-level validation (malformed/malicious protocol messages, distinct from application-level content security). This is named as a **named AI-specific trust boundary** per this milestone's explicit review requirement (§22).

## 10. RAG Security

Retrieval validation and document-poisoning detection are `rag_security`'s core responsibility: every document/chunk returned by a retrieval step is content-provenance-tagged (§6's dependency) as retrieved/untrusted before being assembled into a prompt. Vector-DB protection posture (access control, embedding-space integrity) extends M38's Cloud Security posture model where the vector DB is a `CloudResource` (a vector database is itself just a database resource from M38's perspective — `rag_security` adds the AI-specific *semantic* posture concern — e.g. can arbitrary tenant content be embedded and retrieved cross-tenant — on top of M38's generic database posture, not instead of it). Context isolation (ensuring one tenant's/session's retrieved context can never leak into another's prompt assembly) is named as a **named AI-specific trust boundary** (§22) with direct multi-tenancy implications beyond the platform's already-structural tenant-query-isolation commitment (§20) — this is isolation *within a single inference request's context window construction*, a narrower and AI-specific instance of the same discipline. Data leakage (the model's output revealing retrieved-but-not-meant-to-be-disclosed content) is evaluated by `ai_prompt_security`'s output-side analysis (prompt leakage detection, per the Ubiquitous Language definition, extended to cover retrieval-sourced leakage specifically).

## 11. Model Security

Model inventory, provenance, and version governance are **`ai_supply_chain`, extended, not recreated** (§1) — `ModelProvenance`/`ModelBillOfMaterials` already exist. This milestone's one genuine addition is **safety evaluation**: a versioned record of a model's safety-benchmark results (jailbreak resistance, alignment evaluation, bias/fairness metrics where applicable), modeled as a new value object (`ModelSafetyEvaluation`) attached to `ai_supply_chain`'s existing `ModelProvenance` aggregate — not a new aggregate, an extension of the existing one, since safety evaluation is intrinsically a provenance-adjacent fact about a specific model version.

## 12. AI Runtime Monitoring

The thinnest, most infrastructure-heavy context in this architecture by design, mirroring M37's `siem_ingestion`'s own "stateless, partition by tenant+source" scaling commitment (§12 of M37) — because it largely **is** M37's ingestion layer, AI-framed. `ai_runtime_monitoring` associates raw AI request/response traffic with `AISystemAssetRef`, `AISessionRef`, and (where applicable) an agent-delegation-chain reference, then hands off to M37's `siem_ingestion` using M37's Canonical Event Model with a new `ai` category discriminator carrying AI-specific `attributes` (prompt/response references — via Evidence, not inline, per §14 — token counts, latency, tool-invocation records). This is the direct architectural payoff of M37's CEM being designed extensible via versioned `attributes` in the first place (§2.1, §2.3 of M37) — AI Security is the first concrete proof that decision was right, not merely theoretically extensible.

## 13. AI Threat Detection Flow

```
AI request/response traffic (inference call, tool invocation, agent delegation, RAG retrieval)
  → ai_runtime_monitoring (frame with AISystemAssetRef/AISessionRef/delegation-chain)
  → siem_ingestion (M37, `ai` category CEM event) — durable record, hot-tier
  → [parallel fan-out, async pub/sub — same non-negotiable discipline as M37 §9/M38/M39:]
       → ai_guardrail (INLINE, synchronous, hard latency budget — the one path that is NOT
         purely async fan-out, since a guardrail must be able to block before the response
         is returned to the caller; this is named explicitly as an architectural exception
         to the "always async" rule established in M37, and the exception is justified
         precisely because guardrails are preventive, not observational, per the
         Ubiquitous Language distinction in §2)
       → ai_prompt_security (async — injection/leakage/tampering detection)
       → ai_jailbreak_detection (async)
       → mcp_security (capability-validation, sync at MCP-connect-time; drift-detection async thereafter)
       → rag_security (retrieval-time provenance tagging happens inline as part of context
         assembly — a second narrow synchronous exception, justified because provenance
         tags must exist before the prompt is assembled, not after)
  → ai_threat_detection (correlates the above signals, M37 correlation-session machinery reused)
  → DetectionMatched-equivalent (AI-domain event) → ai_findings.OpenFinding
  → AIFindingDiscovered → IRiskContributionPort → Risk Engine Foundation
  → (existing) red_team_operator/campaign — informed by validated real-world detection gaps (§7)
```

The two named synchronous exceptions (`ai_guardrail` inline blocking, `rag_security` inline provenance tagging) are the most important deviation from M37/M38/M39's otherwise-uniform "always async fan-out" principle in this entire four-milestone architecture family, and are called out explicitly rather than silently violating a previously-stated non-negotiable — both are justified by genuine latency/correctness requirements, not convenience.

## 14. AI Findings Lifecycle & Risk Scoring

`AIFinding` — the fifth instance of the Alert/CloudFinding/VulnerabilityFinding pattern, identical lifecycle shape (`DISCOVERED → VERIFIED → ASSIGNED → (EXCEPTED|SUPPRESSED) → RESOLVED → REOPENED`), same discipline of aggregating related occurrences (e.g. repeated jailbreak attempts against the same agent within a session collapse to one finding, not N). Contributes to Risk Engine via `IRiskContributionPort` (§15) — no parallel AI risk-scoring engine, extending `ai_posture`'s existing `AIRiskScoreSnapshot` as the AI-domain-specific *view* of Risk Engine's output, the same "domain context presents, Risk Engine owns the number" discipline as every prior milestone.

Per §11's flagged accumulating debt from M39 (§17 of M39: three milestones deferring the domain-Finding-to-generic-Findings binding) — **this is now the fourth occurrence**, and this document explicitly escalates it from "flag again" to "this should not be deferred a fifth time in any future milestone without a dedicated resolution," per this milestone's own instruction to critically review rather than mechanically repeat prior documents' hedges.

## 15. Risk Integration

Identical to M38 §10/M39 §7 — `IRiskContributionPort`, extended with AI-specific contribution fields (prompt-injection-susceptibility, jailbreak-resistance-score, guardrail-coverage-gap, MCP-trust-boundary-violations, agent-delegation-anomaly-rate) as additive inputs, not a new port. Fourth consecutive milestone confirming this as a fixed platform contract.

## 16. Compliance

NIST AI RMF, ISO 42001, OWASP LLM Top 10, MITRE ATLAS mappings are `BenchmarkControl`-equivalent registry content (M38's compliance-registry pattern, §14 of M38, reused a third time) evaluated against `ai_posture`'s `AIComplianceMapping` (already exists) plus this milestone's new signal sources. No new compliance-scoring engine.

## 17. Executive Dashboards, Search, Reporting

Thin CQRS read-side over the above, identical treatment to M37 §10/§15, M38 §15, M39 (implicit) — not re-justified at length, a settled pattern.

## 18. Multi-Tenant Isolation

Structural, non-negotiable, fourth consecutive identical commitment — with one AI-specific addition named in §10: context-window-construction isolation (a narrower, request-scoped instance of the same discipline, specific to RAG/retrieval assembly).

## 19. Scalability, HA, DR, Deployment Topology

Identical posture to M37/M38/M39 — stateless components (discovery, async detection, findings) partition and scale active-active; `ai_guardrail`'s inline synchronous path (§13) is the one component requiring dedicated latency-focused scaling design (co-located with or embedded in the inference path itself, likely as a lightweight local evaluator with async policy-sync rather than a remote call per-request — flagged as needing its own performance architecture at implementation time, not solved here). Runtime monitoring/threat-detection state recoverability inherits M37's "raw event data is truth, correlation/detection state is recomputable" DR principle directly (§14 of M37), fourth consecutive reuse.

## 20. Security Model

- Tenant isolation: structural (§18).
- AI-specific trust boundaries (consolidated from §8, §9, §10, §22): (1) user-input → prompt assembly, (2) retrieved-document → prompt assembly (indirect injection surface), (3) tool-output → agent context (MCP/tool-invocation surface), (4) agent-to-agent delegation, (5) agent-memory-write → later-session-read (temporal trust surface), (6) model-output → caller (leakage surface). Every one of these six must have an explicitly named, evaluated control point at implementation time — this document requires their existence, not their implementation.
- Credential handling: AI provider/gateway/vector-DB credentials exclusively `ICredentialVaultPort`-mediated, fourth consecutive identical commitment, no exceptions carved out for AI-specific sources.
- RBAC: new scopes (`ai:read`, `ai:guardrail:manage`, `ai:findings:manage`, `ai:redteam:integrate`) extending existing RBAC.
- Audit: every domain event across §3's contexts is audit-loggable via existing Audit Logging — fifth consecutive milestone relying on this ADR-0003-rooted principle.

## 21. Extension Framework

- New AI sources (gateways, orchestration platforms, MCP registries, vector DBs): `ConnectorPlugin`, zero core changes (§4).
- New prompt-injection/jailbreak detection patterns: `IDetectionEvaluator` rule-shape registration against M37's existing extension point (§6) — no new extension mechanism invented.
- New guardrail policies: registry content, tenant-authored, same lifecycle discipline as M37 detection rules/M38 CSPM policies.
- New compliance frameworks: registry content (§16).
- New trust-boundary types (as AI systems evolve — e.g. a future multimodal or embodied-AI trust surface): additive to the `TrustBoundaryType` enum in the shared kernel, explicitly designed as an open/extensible vocabulary rather than a closed enum, since this is the one taxonomy in this document most likely to need genuine growth as AI system architectures evolve.

## 22. Architecture Review — AI-Specific Trust Boundaries, High-Risk Assumptions, Risks

**Named AI-specific trust boundaries** (consolidated list, per explicit review requirement): the six enumerated in §20. This is the most important single artifact this review produces — every one of these must be a real, tested control point before this platform's AI Security claims can be taken seriously, and their mere enumeration here is necessary but nowhere near sufficient.

**High-risk assumptions this architecture makes, stated explicitly rather than left implicit:**
1. That `ai_guardrail`'s inline synchronous evaluation can meet a real production inference-path latency budget at all — this is asserted as a requirement (§13) but not validated; if guardrail evaluation cannot be made fast enough, the entire "preventive, not just detective" value proposition of this milestone degrades to detection-only, which is a materially weaker product claim.
2. That content-provenance tagging (§6, §10) can be reliably maintained end-to-end through arbitrary agent/tool/RAG composition chains — a sufficiently complex multi-agent, multi-tool pipeline may lose or corrupt provenance tags across hops, silently defeating indirect-injection detection; this is a real, unresolved risk, not a solved problem.
3. That MCP's dynamic capability model can be validated at the speed MCP servers actually change capabilities in practice — if capability drift happens faster than `mcp_security`'s validation cadence, there is a real window of unvalidated trust.
4. That existing `ai_posture`/`ai_agent_governance`/`ai_supply_chain` aggregates can absorb this milestone's extensions without their own breaking changes — this document assumes, but does not verify, that those three existing contexts' current shapes have room for the extensions described in §4, §8, §11; verifying this against the actual current code (not just the aggregate names confirmed in §1) is required before implementation, not assumed by this architecture review.

**Future research topics** (explicitly not solved by this document, offered as forward context rather than architecture): formal verification approaches for guardrail coverage completeness; standardized cross-agent provenance-tagging protocols (whether MCP itself, or a future standard, might solve assumption #2 at the protocol level rather than requiring RedForge to solve it alone); embedding-space/vector-similarity-based poisoning detection techniques for `rag_security`; multi-agent emergent-behavior detection (patterns that only manifest across many agents' interactions, not visible to any single agent's `AgentOperationalEnvelope` check).

## 23. Risks

- **`ai_guardrail` latency feasibility** (§22, assumption 1) — the highest-severity unresolved risk in this document, since it questions whether the single most differentiating capability (preventive, inline AI security) is achievable at all with the architecture as specified, not merely how to build it.
- **Provenance-tag propagation fragility across composed agent/tool/RAG chains** (§22, assumption 2) — directly threatens indirect-injection detection efficacy, this architecture's most novel defensive claim relative to traditional (non-AI) security tooling.
- **MCP capability-drift validation cadence** (§22, assumption 3) — a genuinely new class of risk with no direct precedent in M37/M38/M39, since none of them integrate a protocol with MCP's dynamic-capability-declaration property.
- **Extension compatibility with existing `ai_posture`/`ai_agent_governance`/`ai_supply_chain` aggregates** (§22, assumption 4) — a verification gap in this document itself, named honestly rather than asserted as already checked.
- **Fourth-milestone accumulation of the deferred domain-Finding-to-generic-Findings binding** (§14) — now explicitly escalated from "flag" to "should not recur a fifth time."
- **Cross-pillar event volume**: `ai_runtime_monitoring` feeding M37 adds a fourth high-volume source category (after M37's own native sources, M38's cloud events, M39's vulnerability events) to a shared ingestion pipeline whose combined-load behavior was already flagged as unvalidated in M38 §22 and repeated as a live concern in M39 §17 — this is now a three-times-compounded risk that should be treated as urgent before a fourth security domain's traffic is added on top.

## 24. Trade-offs

- Nine new bounded contexts atop three existing ones (twelve total AI-domain contexts) — a larger context count than M37/M38/M39 individually, justified specifically because AI security's sub-problems (prompt security, jailbreak detection, guardrails, MCP, RAG, runtime monitoring, threat detection, findings, plus the three pre-existing) are demonstrably as separable-by-data-shape as SIEM's or Cloud Security's were, and forcing them together would repeat exactly the God-context risk this document's own family of prior milestones has repeatedly warned against.
- Two named synchronous exceptions to the "always async" principle (§13) trade architectural uniformity for genuine latency/correctness requirements — accepted as the right trade specifically because the alternative (fully async guardrails) would not actually be a guardrail (a control that can't block isn't preventive), and this document treats intellectual honesty about that trade-off as more valuable than superficial consistency with prior milestones.
- Deferring `ai_guardrail`'s actual performance architecture (§19, §22) trades completeness for freezing on schedule — accepted only because assumption 1 is explicitly flagged as requiring validation before implementation proceeds, not silently assumed solved.

## 25. Architecture Review — Domain Classification

| Domain | Classification |
|---|---|
| AI Asset Inventory (extends `ai_posture`) | **Frozen** |
| AI Discovery Engine (Integration-Hub-shaped) | **Frozen** |
| AISPM (aggregation shape over existing + new contexts) | **Frozen** |
| Prompt Security Engine (rule-shape extension of M37) | **Frozen** |
| Jailbreak Detection Engine | **Frozen** |
| Guardrail Validation Engine's policy/versioning model | **Frozen** |
| Guardrail Validation Engine's inline-latency performance architecture | **Frozen with Required Architecture Spike** — assumption 1 (§22, §23) unresolved |
| AI Red Team Engine Integration | **Frozen** (integration shape only; exact event contract deferred to implementation, not a spike-blocking gap) |
| Agent Security — tool permissions/identity (extends `ai_agent_governance`) | **Frozen** |
| Agent Security — agent memory (new concept) | **Frozen with Required Architecture Spike** — memory-poisoning detection mechanism not designed, only the reference concept (`AgentMemoryRef`) is |
| Agent Security — agent delegation, multi-agent security | **Frozen** (shape); delegation-chain provenance propagation is the shared risk with §10, tracked once below rather than twice |
| MCP Security — inventory/permission-boundary shape | **Frozen** |
| MCP Security — capability-drift validation cadence/mechanism | **Frozen with Required Architecture Spike** — assumption 3 (§22, §23) |
| RAG Security — retrieval validation/context isolation shape | **Frozen** |
| RAG Security / cross-context — provenance-tag propagation mechanism | **Frozen with Required Architecture Spike** — assumption 2 (§22, §23), the single most consequential spike in this document since it undermines both `ai_prompt_security`'s indirect-injection detection and `rag_security`'s data-leakage detection simultaneously |
| Model Security (extends `ai_supply_chain` + new `ModelSafetyEvaluation`) | **Frozen** |
| AI Runtime Monitoring (M37-reuse shape) | **Frozen**, contingent on the cross-milestone ingestion-volume risk (§23) being addressed operationally |
| AI Threat Detection Flow | **Frozen** |
| AI Findings Lifecycle | **Frozen** |
| AI Risk Scoring (via `IRiskContributionPort`) | **Frozen** |
| Compliance (registry-content reuse) | **Frozen** |
| Executive Dashboards / Search / Reporting | **Frozen** |
| Multi-tenant Isolation | **Frozen** |
| Scalability / HA / DR / Deployment Topology | **Frozen**, with `ai_guardrail` performance carved out per above |
| Security Model (six named trust boundaries) | **Frozen** as an enumeration; each boundary's actual control mechanism is only as frozen as its owning capability above |
| Extension Framework | **Frozen** |
| Verification that existing `ai_posture`/`ai_agent_governance`/`ai_supply_chain` aggregates can absorb this milestone's extensions without breaking changes | **Deferred** — not a design gap, a verification-against-real-code task that must precede implementation and was explicitly named as unverified by this document (§22, assumption 4) |
| Future research topics (§22) | **Deferred**, by design |

## 26. Freeze Recommendation

# ARCHITECTURE FREEZE APPROVED WITH REQUIRED ARCHITECTURE SPIKES

**Required spikes, in priority order, before implementation begins in their respective areas** (§25):
1. **Content-provenance-tag propagation mechanism across composed agent/tool/RAG chains** — the single most consequential spike, since it simultaneously determines the real-world efficacy of indirect prompt-injection detection and RAG data-leakage detection.
2. **`ai_guardrail` inline-evaluation performance architecture** — determines whether this platform's core preventive-AI-security claim is achievable as specified.
3. **MCP capability-drift validation cadence/mechanism** — a genuinely new risk class with no precedent in M37/M38/M39.
4. **Agent-memory-poisoning detection mechanism** — the one entirely new agent-security concept beyond existing `ai_agent_governance` extension.

**Required pre-implementation verification (not a design spike, but a hard gate nonetheless):** confirm the existing `ai_posture`/`ai_agent_governance`/`ai_supply_chain` aggregate shapes actually accommodate this milestone's extensions before writing implementation code against assumed compatibility.

**Standing operational concern carried forward, not blocking freeze but requiring attention before M40 implementation adds a fourth high-volume source to shared SIEM ingestion:** the cross-milestone event-volume risk first raised in M38 §22 and repeated in M39 §17.

The remaining scope areas — AI Asset Inventory, AI Discovery, AISPM, Prompt/Jailbreak detection engines' rule-shape design, AI Red Team integration shape, Agent Security's governance-extension and delegation shape, MCP Security's inventory/boundary shape, RAG Security's validation/isolation shape, Model Security, AI Runtime Monitoring, AI Threat Detection Flow, AI Findings Lifecycle, AI Risk Scoring, Compliance, Dashboards/Search/Reporting, Multi-tenant Isolation, Scalability/HA/DR, and Extension Framework — are frozen as specified and ready for implementation planning without further architecture-level rework.
