# PROJECT_CONTEXT.md — AIVAR RedForge

**Classification**: Internal Engineering  
**Audience**: AI coding agents, onboarding engineers, architecture reviewers  
**Last verified**: 2026-07-11 against source code (Sprint 40 — Evaluation Control Loop)
**Test baseline**: 3,284 tests passing, ruff clean (2 pre-existing in knowledge_graph.py), mypy --strict clean

> This document is the canonical onboarding reference for any future AI coding session or new engineer.
> **Trust the source code, not this document alone.** Run `pytest`, `ruff check`, and `mypy --strict` after every change.

---

## Table of Contents

1. [Project Vision](#1-project-vision)
2. [Current Architecture](#2-current-architecture)
3. [Platform Capabilities](#3-platform-capabilities)
4. [Repository Structure](#4-repository-structure)
5. [End-to-End Event Flow](#5-end-to-end-event-flow)
6. [Knowledge Graph](#6-knowledge-graph)
7. [Design Principles](#7-design-principles)
8. [Technology Stack](#8-technology-stack)
9. [Coding Rules](#9-coding-rules)
10. [Completed Milestones](#10-completed-milestones)
11. [Technical Debt](#11-technical-debt)
12. [Future Roadmap](#12-future-roadmap)
13. [AI Session Bootstrap](#13-ai-session-bootstrap)
14. [Architecture Snapshot](#14-architecture-snapshot)
15. [Executive Summary](#15-executive-summary)

---

## 1. Project Vision

### What is AIVAR RedForge?

AIVAR RedForge is an **Enterprise Continuous AI Security Validation and AI Red Teaming Platform**. It validates the security posture of AI systems — LLM applications, AI agents, RAG systems, MCP servers, multi-agent workflows — through automated, continuous, and intelligence-driven security testing.

It is not a wrapper around LLM APIs. It is not a prompt testing utility. It is a purpose-built enterprise security platform, analogous in ambition to what CrowdStrike became for endpoint security or Wiz became for cloud security — but for the AI era.

### Why it exists

Every enterprise deploying AI systems faces a new attack surface that traditional security tools cannot address. Prompt injection, jailbreaks, data exfiltration through conversational interfaces, tool abuse in agentic systems, and RAG poisoning are structurally different from web application vulnerabilities. They require purpose-built validation infrastructure.

Traditional tools fail here:
- Manual pentests are point-in-time; AI risks are continuous
- Vulnerability scanners (Nessus, Qualys) are network/infra focused, not AI interaction focused
- Developer tools (Promptfoo, NVIDIA Garak) are single-target, not enterprise-multi-tenant
- Research frameworks (Azure PyRIT) require manual scripting, not automated continuous execution

### Long-term mission

```
Today  → Automated AI red teaming
Year 2 → Continuous AI security posture management
Year 3 → AI security intelligence platform
Year 5 → Autonomous AI security validation
Year 10 → AI system governance and safety infrastructure
```

### Product philosophy

- **Domain first**: business concepts are rich domain objects, not anemic data containers
- **Protocol first**: every extension point is a Python `Protocol`; implementations are injected
- **Correctness over velocity**: optimize for 10-year code lifespan
- **Evidence integrity**: evidence is immutable once finalized — all findings are derived, always regenerable
- **Multi-tenant isolation**: every data path is organization-scoped
- **No provider lock-in**: OpenAI, Anthropic, Google, local models are treated identically

### Enterprise goals

- Support 10,000+ attack definitions across 14 categories
- Execute millions of validation runs per day
- Serve thousands of organizations with strict data isolation
- Map all findings to OWASP GenAI Top 10, MITRE ATLAS, NIST AI RMF, SOC2, ISO 27001
- Support customer-supplied attack packs (plugin SDK, future)

---

## 2. Current Architecture

The codebase uses **Clean Architecture with Domain-Driven Design**. Dependencies point strictly inward: Infrastructure → Application → Domain. The Domain layer has zero infrastructure imports.

### Bounded Context Map

There are **22 bounded contexts** implemented as of Sprint 34/35:

| Context | Location | Purpose |
|---------|----------|---------|
| Identity | `domain/identity/` | Users, roles, permissions, invitations |
| Organizations | `domain/organizations/` | Multi-tenant isolation, billing plans |
| AI Targets | `domain/ai_targets/` | Systems under continuous security validation |
| Attack Library | `domain/attack_library/` | Versioned, lifecycle-managed attack definitions |
| Policies | `domain/policies/` | Compose attacks, define strategy and schedule |
| Payloads | `domain/payloads/` | Template rendering, variable substitution |
| Planning | `domain/planning/` | Attack plan generation and strategy |
| Execution | `domain/execution/` | Runtime plan lifecycle, stages, steps |
| Validations | `domain/validations/` | ValidationRun lifecycle management |
| Evidence | `domain/evidence/` | Immutable interaction records |
| Findings | `domain/findings/` | Security assessments derived from evidence |
| Providers | `domain/providers/` | Registered AI provider adapters |
| Knowledge | `domain/knowledge/` | Reusable AI security knowledge items |
| Risk | `application/risk_engine.py` | Risk incident correlation and scoring |
| Posture | `domain/posture/` | Baselines, snapshots, trend analysis |
| Intelligence | `domain/intelligence/` | Insights, recommendations, gap analysis |
| Inventory | `domain/inventory/` | Enterprise AI asset catalogue |
| Connectors | `domain/connectors/` | External platform discovery integrations |
| Conversations | `domain/conversations/` | Multi-turn adaptive attack sessions |
| Agents | `domain/agents/` | Agent/MCP security validation sessions |
| Red Team | `domain/red_team/` | Goal-oriented attack graph orchestration (Sprint 34/35) |
| Advanced Validation | `application/advanced_validation/` | Multi-turn, long-context, multi-model validation (Sprint 32/33) |
| Platform | `domain/platform/` | Immutable event backbone (Sprint 24) |

---

### Bounded Context Details

#### Identity (`domain/identity/`)

**Purpose**: Manages user accounts and their membership in organizations.

**Aggregates**:
- `User` — individual account (status: ACTIVE / INACTIVE / PENDING / SUSPENDED). Aggregate root.
- `Invitation` — scoped invitation token for org onboarding. Lifecycle: PENDING → ACCEPTED / REJECTED / REVOKED / EXPIRED.
- `Membership` — User's relationship to an Organization with a role.

**Value Objects**: `Email`, `PasswordHash`, `UserStatus`, `MembershipRole` (OWNER / ADMIN / SECURITY_MANAGER / ANALYST / MEMBER / VIEWER), `Permission` (18 fine-grained permissions), `InvitationStatus`

**Key rule**: Permissions are assigned to roles, not directly to users. `ROLE_PERMISSIONS` dict maps role → frozenset[Permission]. No switch statements on role identity.

**Repositories**: `UserRepository`, `InvitationRepository`, `MembershipRepository` (protocols in domain; SQLAlchemy impls in infrastructure)

**Relationships**: Every other bounded context scopes data by `organization_id`, which comes from the Membership for the acting user.

---

#### Organizations (`domain/organizations/`)

**Purpose**: Top-level tenant isolation. Every resource in the platform belongs to one Organization.

**Aggregates**:
- `Organization` — aggregate root. Status: ACTIVE / INACTIVE / SUSPENDED. Plan: FREE / STARTER / PROFESSIONAL / ENTERPRISE.

**Value Objects**: `OrganizationName` (2–100 chars), `OrganizationSlug` (URL-safe), `OrganizationStatus`, `OrganizationPlan`

**Domain events**: `OrganizationCreated`, `OrganizationActivated`, `OrganizationDeactivated`, `OrganizationSuspended`, `OrganizationRenamed`, `OrganizationPlanChanged`

**Relationships**: Root of the data hierarchy. All other contexts carry `organization_id: EntityId`.

---

#### AI Targets (`domain/ai_targets/`)

**Purpose**: Represents any AI system under continuous security validation. Not the same as `AIAsset` (inventory) — an AITarget is explicitly enrolled for security testing.

**Aggregates**:
- `AITarget` — aggregate root. The central object validation runs, evidence, and findings relate to.

**Value Objects**: `TargetType` (LLM_APPLICATION / AI_AGENT / RAG_SYSTEM / MCP_SERVER / AI_API / AI_WORKFLOW / AUTONOMOUS_AGENT), `TargetStatus` (ACTIVE / INACTIVE / ARCHIVED), `Provider` (OPENAI / ANTHROPIC / GOOGLE / AZURE_OPENAI / AWS_BEDROCK / META / MISTRAL / COHERE / CUSTOM), `EndpointUrl`, `TargetName`, `TargetMetadata`, `Tag`, `ValidationPolicyReference`

**Domain events**: `TargetRegistered`, `TargetActivated`, `TargetDeactivated`, `TargetArchived`, `TargetRestored`, `TargetRenamed`, `TargetEndpointChanged`, `TargetProviderChanged`, `ValidationPolicyAttached`, `ValidationPolicyDetached`

**Key invariants**: Only ACTIVE targets can be modified. ARCHIVED targets are read-only (can be restored). Tags are unique within a target. Policies are unique within a target.

**Relationships**: Targets are validated by `ValidationRun`. Evidence and Findings reference `target_id`. The Knowledge Graph has a node per target.

---

#### Attack Library (`domain/attack_library/`)

**Purpose**: Reusable, versioned, lifecycle-managed AI security attack techniques. Designed to scale to 10,000+ definitions.

**Aggregates**:
- `AttackDefinition` — aggregate root. Status: DRAFT → PUBLISHED → DEPRECATED / ARCHIVED / SUPERSEDED.
- `AttackTaxonomyNode` — unlimited-depth classification tree. Distinct from the closed `AttackCategory` enum (taxonomy adds arbitrary sub-techniques as data rows, not code).

**Value Objects**: `AttackCategory` (14 categories: PROMPT_INJECTION / JAILBREAK / DATA_EXFILTRATION / HALLUCINATION / TOOL_ABUSE / FUNCTION_CALLING / RAG_POISONING / CONTEXT_MANIPULATION / MEMORY_POISONING / AGENT_HIJACKING / MODEL_EXTRACTION / POLICY_BYPASS / GUARDRAIL_EVASION / DENIAL_OF_SERVICE), `AttackStatus`, `AttackSeverity` (CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL), `AttackMaturity`, `SafetyClassification` (SAFE / CAUTION / DESTRUCTIVE / RESTRICTED), `ExecutionStrategy` (SINGLE_TURN / MULTI_TURN / ADAPTIVE / CHAIN), `FrameworkMapping` (MITRE ATLAS, OWASP), `ProviderCompatibility`, `EvaluationRequirement`, `ExpectedOutcome`

**Design note**: `AttackCategory` is a closed StrEnum (stable, used in queries and compliance mappings). `AttackTaxonomyNode` is an open tree (arbitrary depth, authored as data). These coexist: `AttackDefinition.category` gives the top-level, `AttackDefinition.taxonomy_node_id` gives the deep path.

**Protocols**: `AttackLibraryRepository`, `AttackTaxonomyRepository`

**Relationships**: Referenced by Policies, Planning, Execution steps, Evidence, Findings, and the Knowledge Graph.

---

#### Policies (`domain/policies/`)

**Purpose**: Compose attacks into named, reusable validation strategies. Policies are attached to AI Targets and drive ValidationRun execution.

**Aggregates**: `ValidationPolicy` — specifies which attacks to run, execution strategy, scheduling, and target scope.

**Value Objects**: `ExecutionStrategy` (SEQUENTIAL / PARALLEL / ADAPTIVE), `PolicyStatus`, `TriggerRule`, `TargetScope`

**Relationships**: Policies are attached to AITargets. CampaignEngine resolves policy → target IDs → ValidationRun requests.

---

#### Payloads (`domain/payloads/`)

**Purpose**: Template rendering engine. Attack definitions reference payload templates. The execution engine renders templates with context variables to produce the actual content dispatched to providers.

**Aggregates**:
- `PayloadTemplate` — Jinja2-style `{{ variable }}` templates. Status: DRAFT → PUBLISHED → ARCHIVED. Renders only when PUBLISHED.
- `PayloadBundle` — grouped set of templates for a use case.

**Value Objects**: `TemplateType` (PROMPT / CONVERSATION / FUNCTION_CALL / TOOL_USE / MULTI_TURN / RAW), `TemplateVariable` (name, type, required, default), `TemplateVersion` (semver), `RenderContext`, `RenderedPayload`

**Key rule**: `render()` validates all required variables are provided. Template body uses `{{ var_name }}` syntax. Variables declared must exist in the body.

**Mutations**: `PayloadMutation` types for payload variation generation (handled via `mutations.py`).

---

#### Planning (`domain/planning/`)

**Purpose**: Determines WHAT to execute, WHEN, WHY, and in WHICH ORDER across a policy's attack library. Produces an `AttackPlan` that the Execution context dispatches.

**Aggregates**:
- `AttackPlan` — immutable once created. Only valid transition is `supersede()`. A changed plan is a new plan that supersedes the old one (mirrors AttackDefinition supersession pattern).

**Value Objects**: `PlanningStrategy` (COMPREHENSIVE / RISK_BASED / COVERAGE_FIRST / REGRESSION / SMOKE_TEST), `AttackSequence`, `AttackDependencyGraph`, `PlannedAttackStep`, `RiskAppetite`, `SuccessCriteria`, `Confidence`, `EstimatedCost`, `EstimatedDuration`

**Cross-context reuse**: Deliberately imports `FailureStrategy` and `RetryPolicy` from `domain.execution` (same types downstream), `EvaluationRequirement` and `ExpectedOutcome` from `domain.attack_library`, `Confidence` from `domain.evidence`. No duplicate types.

**Application services**: `AttackPlanner` (strategies in `planning_strategies.py`), `AttackPlanRepository`

---

#### Execution (`domain/execution/`)

**Purpose**: Runtime execution plan lifecycle — stages, steps, retry, timeout, failure strategy. The dispatcher traverses stages; steps map 1:1 to attack invocations.

**Aggregates**:
- `ExecutionPlan` — runtime tracker. Status: PENDING / RUNNING / COMPLETED / FAILED / CANCELLED / TIMED_OUT. Terminal states immutable.

**Value Objects**: `ExecutionStage`, `ExecutionStep`, `PlanStatus`, `StepStatus`, `FailureStrategy` (FAIL_FAST / CONTINUE / RETRY_THEN_CONTINUE), `RetryPolicy` (max_retries, backoff_seconds), `TimeoutPolicy` (step + plan timeouts), `StepResult`, `ExecutionMode` (SEQUENTIAL / PARALLEL)

**Key note**: `ExecutionPlan` is the runtime dispatcher's input. `AttackPlan` (Planning context) is the strategy planner's output. These are different aggregates at different altitudes.

---

#### Validations (`domain/validations/`)

**Purpose**: Tracks the lifecycle of a single validation run — from scheduling through completion.

**Aggregates**:
- `ValidationRun` — aggregate root. Status: SCHEDULED → RUNNING → COMPLETED / FAILED / CANCELLED. Terminal states immutable. `summary` attached only at COMPLETED.

**Value Objects**: `ValidationStatus`, `TriggerType` (MANUAL / SCHEDULED / CI_CD / POLICY / API), `ValidationSummary` (total_checks, passed, failed, skipped, duration_ms)

**Application services**: `ValidationService` (`application/validation_service.py`) is the ONE canonical execution path. It orchestrates: resolve attacks → execute → build evidence/findings → correlate risk → persist atomically (one UnitOfWork) → populate KG (post-commit, isolated) → publish events (post-commit, isolated).

---

#### Evidence (`domain/evidence/`)

**Purpose**: Immutable source of truth. Each piece of evidence captures one interaction with an AI target during a security check. Findings are derived from evidence and can always be regenerated.

**Aggregates**:
- `Evidence` — aggregate root. Lifecycle: `record()` → `attach_artifact()` → `attach_trace()` → `finalize()`. Once finalized, no mutations permitted (ADR-0003).

**Value Objects**: `EvidenceResult` (PASS / FAIL / ERROR / INCONCLUSIVE), `Confidence` (0.0–1.0, reused by Planning), `RequestPayload`, `ResponsePayload`, `Artifact`, `TraceMetadata`, `ExecutionMetadata`, `TestCaseReference`, `AttackReference`

**Invariant**: Evidence has no `update()` in repository interface. No PUT/PATCH/DELETE API endpoints.

---

#### Findings (`domain/findings/`)

**Purpose**: Security assessments derived from Evidence. Not the source of truth — Evidence is.

**Aggregates**:
- `Finding` — aggregate root. Status: OPEN → ACCEPTED / CLOSED / REOPENED. References Evidence by ID only (never embeds).

**Value Objects**: `Severity` (CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL), `FindingStatus`, `RiskScore` (0.0–10.0, `severity_level` property maps to Severity), `ComplianceReference`, `OwaspReference`, `MitreReference`

**Key rule**: Closed findings cannot be modified (except reopen). A finding always references at least one Evidence record.

---

#### Providers (`domain/providers/`)

**Purpose**: Registered AI provider adapters. Separates adapter registration (domain) from adapter execution (infrastructure).

**Aggregates**: `Provider` entity — registered adapter with configuration.

**Value Objects**: `ProviderType`, `ProviderStatus`, `ProviderConfiguration`

**Distinction from Connectors**: Providers are used during **attack execution** (send payload → receive response). Connectors are used for **asset discovery** (enumerate what AI systems exist on a platform).

---

#### Knowledge (`domain/knowledge/`)

**Purpose**: Reusable AI security building blocks — attack definitions, validation packs, compliance rules, provider profiles. These are content items, not execution artifacts.

**Aggregates**:
- `KnowledgeItem` — aggregate root. Status: DRAFT → PUBLISHED → ARCHIVED / SUPERSEDED.

**Value Objects**: `KnowledgeCategory` (ATTACK / VALIDATION_PACK / COMPLIANCE_PACK / DETECTION_RULE / RECOMMENDATION / PROVIDER_PROFILE / SECURITY_SKILL), `KnowledgeStatus`, `KnowledgeSource` (BUILTIN / COMMUNITY / ENTERPRISE / CUSTOM), `KnowledgeVersion`

**Note**: The Knowledge bounded context stores structured knowledge items. The Knowledge Graph (application layer) is a separate traversable semantic graph that links all platform objects.

---

#### Risk (`application/risk_engine.py`)

**Purpose**: Correlates Findings, Evidence Chains, and Validation Results into Risk Incidents with CVSS-inspired scoring.

**Key types**: `RiskIncident`, `RiskFactor`, `RiskScoreCalculator` (Protocol — replaceable algorithm), `RiskHistory`, `RiskTrend`

**Value Objects**: `RiskPriority` (CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL), `RiskTrend` (INCREASING / DECREASING / STABLE / NEW), `RiskIncidentStatus`

**Design**: `RiskScoreCalculator` is a Protocol. The default uses CVSS-inspired heuristics. An ML model satisfying the same protocol is a drop-in replacement.

---

#### Posture (`domain/posture/`)

**Purpose**: Tracks security posture over time via baselines, snapshots, regression detection, and trend analysis.

**Aggregates**:
- `ValidationSnapshot` — immutable record of one completed ValidationRun's metrics. Created once, never mutated.
- `ValidationBaseline` — promoted snapshot that serves as regression reference. Status: ACTIVE → SUPERSEDED / EXPIRED / REVOKED. Only one ACTIVE baseline per (org, target).

**Value Objects**: `SnapshotMetrics` (finding_count, vulnerability_rate, pass_rate, etc.), `BaselinePolicy`, `BaselineStatus`, `ConfigurationFingerprint`, `SecurityPostureScore`, `PostureLevel`, `TrendDirection` (IMPROVING / DEGRADING / STABLE / NEW / VOLATILE), `RegressionSeverity`, `DriftType`, `ValidationWindow`

**Application services**: `SnapshotService`, `BaselineService`, `SecurityPostureCalculator`, `TrendAnalyzer`, `DriftDetector`, `RegressionAnalyzer`

---

#### Intelligence (`domain/intelligence/`)

**Purpose**: Rules-based (no LLM, no I/O) reasoning pipeline that produces insights, recommendations, and narratives from posture and finding data.

**Aggregates**:
- `SecurityInsight` — recognized pattern/anomaly/trend. Immutable after creation.
- `Recommendation` — actionable security recommendation with evidence and remediation steps. Status: OPEN / IN_PROGRESS / IMPLEMENTED / DISMISSED.
- `RecommendationBundle` — grouped, deduplicated, prioritized set for one org.
- `RemediationPlan` — step-by-step remediation attached to one recommendation.
- `IntelligenceReport` — assembled report for one org over a time window.

**Value Objects**: `InsightType` (PATTERN / ANOMALY / TREND / CORRELATION / COVERAGE / REGRESSION), `RecommendationPriority` (CRITICAL / HIGH / MEDIUM / LOW), `RecommendationCategory` (14 categories), `RecommendationStatus`, `SecurityGap`, `AttackCoverageGap`, `RemediationStep`, `RiskNarrative`, `PostureNarrative`

**Pipeline** (in `application/intelligence/intelligence_service.py`):
```
IntelligenceContext
  → CoverageAnalyzer.analyze()        # per-target coverage gaps
  → GapAnalyzer.analyze()             # structural security gaps
  → InsightGenerator.generate()       # pattern/anomaly/trend insights
  → RecommendationGenerator.generate() # rule-based recommendations
  → PriorityEngine.prioritize()       # score, deduplicate, sort
  → NarrativeBuilder.build_*()        # risk + posture narratives
  → IntelligenceReport.assemble()     # domain aggregate
```

---

#### Inventory (`domain/inventory/`)

**Purpose**: Enterprise AI Asset catalogue. `AIAsset` is NOT an `AITarget`. AIAsset is the upstream source from which validation targets are derived.

**Aggregates**:
- `AIAsset` — aggregate root. Lifecycle: DISCOVERY → ACTIVE → DEPRECATED → RETIRED. RETIRED is terminal.

**Value Objects**: `AssetType` (13 types: AI_APPLICATION / AI_AGENT / AI_MODEL / AI_PROVIDER / RAG_SYSTEM / MCP_SERVER / PROMPT_TEMPLATE / TOOL_DEFINITION / MEMORY_STORE / KNOWLEDGE_BASE / EMBEDDING_MODEL / VECTOR_DATABASE / AI_ENDPOINT), `AssetLifecycleStage`, `AssetHealthStatus` (HEALTHY / DEGRADED / OFFLINE / UNKNOWN), `AssetDiscoverySource`, `AssetFingerprint`, `AssetOwner`, `AssetRelationship`, `AssetRelationshipType`, `AssetDependencyRef`, `AssetVersion`, `AssetMetadata`

**Pipeline** (6 phases in `application/inventory/inventory_service.py`):
```
DiscoveredAssetInput
  → Normalization (validate/clean raw inputs)
  → Deduplication (match by external_id)
  → Fingerprinting (compute/compare, record version changes)
  → Relationship resolution (typed edges between assets)
  → Knowledge Graph projection
  → InventorySnapshot (output)
```

---

#### Connectors (`domain/connectors/`)

**Purpose**: Integration adapters that discover AI assets from external platforms (OpenAI, Anthropic, LangSmith, etc.) and feed them into the Inventory pipeline.

**Aggregates**:
- `Connector` — aggregate root. Status: REGISTERED → CONFIGURED → VALIDATED → ENABLED ↔ DISABLED → ARCHIVED. ARCHIVED is terminal.
- Tracks `DiscoveryJobRecord` and `SyncJobRecord` inline.

**Value Objects**: `ConnectorType` (OPENAI / ANTHROPIC / AZURE_OPENAI / AWS_BEDROCK / GOOGLE_VERTEX_AI / LANGSMITH / LANGGRAPH / CREWAI / AUTOGEN / OPENAI_AGENTS_SDK / MCP_REGISTRY / GENERIC), `ConnectorStatus`, `ConnectorCapability`, `ConnectorConfiguration`, `ConnectorCredentialReference`, `ConnectorHealth`, `SynchronizationPolicy`

**Application services**: `ConnectorService` (lifecycle), `DiscoveryService` (executes discovery jobs), `SyncService` (executes sync jobs), `ConnectorRegistry` (dict-dispatched, no switch statements)

**Protocols**: `DiscoveryProvider` (implements discovery for a connector type), `InventoryMapper` (converts `RawResource` → `DiscoveredAssetInput`)

---

#### Conversations (`domain/conversations/`)

**Purpose**: Adaptive multi-turn attack dialogues against AI targets. Distinct from ValidationRun (single-step). A `ConversationSession` spans N turns with decision-making between them.

**Aggregates**:
- `ConversationSession` — aggregate root. Status: PENDING → RUNNING → COMPLETED / FAILED / CANCELLED / EXHAUSTED. Turns are append-only and immutable.

**Value Objects**: `ConversationBudget`, `ConversationTurn`, `ConversationMetrics`, `ConversationOutcome`, `ConversationStatus`, `ConversationStrategyType`, `DecisionAction`

**Application services**: `ConversationEngine` (`application/conversations/`), `DecisionEngine`, strategies in `strategies.py`

---

#### Agents (`domain/agents/`)

**Purpose**: Security validation of AI agents that use tools and MCP servers. Detects recursive loops, permission escalations, tool chain attacks, and budget exhaustion.

**Aggregates**:
- `AgentSession` — tracks tool invocations, permission escalations, loop detection. Same lifecycle as ConversationSession.
- `MCPSession` — tracks MCP protocol interactions (tools/call, resources/read, prompts/get).

**Value Objects**: `ToolInvocationRecord`, `MCPInteractionRecord`, `AgentBudget`, `AgentCapabilityType`, `AgentSessionStatus`, `AgentSessionOutcome`, `MCPCapabilities`, `AttackVector`

**Application services**: `AgentValidationEngine`, `MCPValidationEngine` (`application/agents/`)

---

#### Platform (`domain/platform/` + `application/platform/`)

**Purpose**: Canonical immutable data backbone. Protocol-first event sourcing architecture — every future storage technology plugs in here. Introduced Sprint 24.

**Key distinction**: The Platform is NOT a replacement for any existing bounded context. It is the horizontal infrastructure that any context can publish events into.

**Domain models**: `PlatformEvent` (base), `EventEnvelope` (wraps any domain event as `payload: object`), `EventBatch`, `EventStream`, `EventSnapshot`, `EventMetadata`, `CorrelationId`, `CausationId`, `EventVersion`, `ReplayCursor`, `RetentionPolicy`, `ProjectionCheckpoint`, `ProjectionState`, `TimelineEntry`, `ReadModel` (base + 12 read model subtypes)

**Protocol ports** (all in `application/platform/contracts.py`): `EventStore`, `PlatformEventPublisher`, `EventSubscriber`, `ProjectionEngine`, `ProjectionRepository`, `ReadModelRepository`, `SnapshotStore`, `ReplayEngine`, `TimelineRepository`, `CheckpointRepository`

**Sprint 31 Runtime additions** (application layer):
- `RuntimeDLQ` protocol: extended with `mark_exhausted(entry_id)` and `release_inflight(entry_id)`
- `DLQReplayWorker.stats()`: returns `{"replayed", "failed", "skipped", "exhausted", "state"}` — `state` is `"running"|"stopped"`
- `ProjectionBase.flush_to_durable_repo(target_repo, org_id)`: writes in-memory read model to any duck-typed repo
- `ProjectionRegistry.flush_all_to_durable_repo(target_repo, org_id)`: flushes all 9 registered projections
- `RuntimeContainer.session_factory: Any`: set by `app.py` after DB startup; enables live checkpoint queries
- DLQ status lifecycle: `pending → requeued → in_flight → deleted|requeued|exhausted` (terminal)
- In-flight TTL: 300 seconds; expired entries re-claimable by any worker
- Cross-tenant enforcement in `_real_replay_fn`: `entry.org != envelope.org` → reject before any handler

**In-memory implementations** (reference, NOT production): `InMemoryEventStore` (thread-safe, 6 indexes, monotonic global_position, OCC, dedup), `InMemorySnapshotStore`, `InMemoryCheckpointRepository`, `InMemoryReadModelRepository`

**PostgreSQL implementations** (production): `PostgreSQLEventStore`, `PostgreSQLCheckpointRepository`, `PostgreSQLDeadLetterQueue`, `PostgreSQLReadModelRepository`

**9 Projections wired into replay** (`application/platform/projections/`): Inventory, Campaign, Validation, Evidence, Risk, Intelligence, ConnectorActivity, OrganizationActivity, AssetTimeline (KGProjection deferred to Sprint 32 — requires KnowledgeGraph in RuntimeContainer)

**Key rule**: `KGProjection` feeds the existing `KnowledgeGraph` — the KG is NOT replaced. It is one projection consumer.

**Replay Engine**: 8 filter dimensions (org, stream, aggregate, time-range, correlation, event-type, cursor, aggregate-type). All async generators with `ReplayCursor` pagination.

**Runtime API endpoints** (`api/v1/runtime.py`) — Sprint 27–31 additions:
- `GET /runtime/health` — dynamic health checks (not static)
- `GET /runtime/status` — circuit breaker state per service
- `POST /runtime/circuit/{name}/reset` — admin-only circuit reset
- `GET /runtime/dlq` — list DLQ entries for caller's org
- `POST /runtime/dlq/{id}/requeue` — requeue a pending entry
- `GET /runtime/replay/status` — worker `is_running` + stats (`replayed`, `failed`, `skipped`, `exhausted`, `state`)
- `POST /runtime/replay/trigger` — manual DLQ replay trigger
- `GET /runtime/checkpoints` — **live PostgreSQL positions** (not -1); falls back to -1 without DB
- `GET /runtime/projections` — registered projection names + counts
- `GET /runtime/dlq/stats` — aggregate DLQ counters by status
- `POST /runtime/dlq/{id}/discard` — discard a DLQ entry

**Replay handler metrics** (Sprint 31, recorded via `RuntimeMetrics`):
`dlq.replay.handlers_invoked`, `dlq.replay.projection_execution_time` (histogram), `dlq.replay.checkpoint_latency` (histogram), `dlq.replay.events_replayed`, `dlq.replay.events_skipped`, `dlq.replay.projection_failures`, `dlq.replay.cross_tenant_rejected`

---

## 3. Platform Capabilities

### Identity & Organization Management
**Status**: Complete  
**Location**: `domain/identity/`, `domain/organizations/`, `application/auth.py`, `infrastructure/auth/`  
**Purpose**: Multi-tenant user management with role-based access control.  
**Components**: User registration, Argon2id password hashing, PyJWT-based authentication, 6 predefined roles (OWNER → VIEWER), 18 fine-grained permissions, invitation workflow with TTL tokens, membership lifecycle, organization plan management.  
**Extension points**: Additional roles require one entry in `ROLE_PERMISSIONS` dict — no branching on role identity.

### Attack Library
**Status**: Complete (DRAFT / PUBLISHED / DEPRECATED / ARCHIVED / SUPERSEDED lifecycle)  
**Location**: `domain/attack_library/`  
**Purpose**: Versioned, lifecycle-managed repository of AI security attack techniques.  
**Components**: `AttackDefinition` aggregate, 14 `AttackCategory` values, unlimited-depth `AttackTaxonomyNode` tree, MITRE ATLAS and OWASP framework mappings, CVSS metadata, provider compatibility declarations, safety classifications.  
**Extension points**: New attack techniques are new domain objects, not enum additions. Taxonomy nodes are data rows.

### Payload Intelligence Engine
**Status**: Complete  
**Location**: `domain/payloads/`, `application/payloads/`  
**Purpose**: Template-based payload generation with variable substitution and mutation.  
**Components**: `PayloadTemplate` with `{{ variable }}` syntax, `PayloadBundle` grouping, 6 template types, `PayloadMutation` types for variation generation, `PayloadPipeline` for transformation chains.  
**Extension points**: New template types via `TemplateType` enum.

### Attack Planning & Strategy
**Status**: Complete  
**Location**: `domain/planning/`, `application/planning/`  
**Purpose**: Determines which attacks to run, in what order, with what priority.  
**Components**: `AttackPlanner` application service, 5 `PlanningStrategy` types (COMPREHENSIVE / RISK_BASED / COVERAGE_FIRST / REGRESSION / SMOKE_TEST), `AttackDependencyGraph` for ordering, immutable `AttackPlan` aggregate with `supersede()` lifecycle.  
**Extension points**: New strategies implement the `PlanningStrategy` protocol.

### Runtime Execution Engine
**Status**: Complete  
**Location**: `application/runtime/`, `application/validation_service.py`  
**Purpose**: ONE canonical execution path for all AI security validation.  
**Components**: `ValidationService` (canonical path), `ValidationOrchestrator` (thin coordinator), `InProcessDispatcher` (sequential reference impl), `ChatCompletionExecutor`, `KeywordClassifier`. The service is protocol-based — all collaborators are injected.  
**Extension points**: `StepExecutor` protocol for new executor types (ToolUseExecutor, AgentExecutor, RAGExecutor). `ResponseClassifier` protocol for LLM-as-Judge or ML classifiers. `ExecutionDispatcher` protocol for distributed queue-based dispatch.

### Evaluation Engine
**Status**: Complete  
**Location**: `application/runtime/evaluation/`, `domain/evaluation/`  
**Purpose**: Multi-evaluator pipeline that determines pass/fail/inconclusive from evidence.  
**Components**: `EvaluationPipeline` (orchestrates evaluators), `KeywordEvaluator`, `PatternEvaluator`, `RuleEvaluator`, `WeightedAverageAggregator`, `MajorityVoteAggregator`, `FindingCandidateGenerator`. `EvaluationResult` domain entity tracks evaluation lifecycle.  
**Extension points**: New evaluators implement the `Evaluator` protocol. LLM-as-Judge evaluator is a new impl, no pipeline changes.

### Scenario Engine
**Status**: Complete  
**Location**: `application/scenarios/`  
**Purpose**: Business-level abstractions for common security testing scenarios.  
**Components**: `ScenarioRunner`, 5 `ScenarioProfile` types, `CapabilityResolution` (resolves scenario → attacks), `SuccessCriteria` evaluation, `ScenarioDefinition` objects.

### Campaign Engine
**Status**: Complete  
**Location**: `domain/campaigns/`, `application/campaigns/`  
**Purpose**: Multi-target fan-out — runs one ValidationPolicy against N targets under a single coordinated campaign.  
**Components**: `Campaign` aggregate (status: PENDING → RUNNING → COMPLETED / FAILED / CANCELLED / PAUSED), `CampaignEngine` (stateless, concurrent via asyncio.Semaphore), `DriftDetector` (compares campaign metrics against baselines), 7 `CampaignType` values.  
**Protocols**: `CampaignRepositoryPort`, `TargetSelectorPort`, `CampaignKnowledgeProjectorPort`, `BaselineCampaignPort`

### Conversation Engine
**Status**: Complete  
**Location**: `domain/conversations/`, `application/conversations/`  
**Purpose**: Adaptive multi-turn attack dialogues. The engine selects the next action based on the model's response.  
**Components**: `ConversationSession` aggregate, `ConversationEngine`, `DecisionEngine`, 5 conversation strategies.

### Agent & MCP Security Validation
**Status**: Complete  
**Location**: `domain/agents/`, `application/agents/`  
**Purpose**: Validates AI agents (tool-using) and MCP servers specifically.  
**Components**: `AgentSession` (tracks tool invocations, loop detection, permission escalations), `MCPSession` (tracks protocol interactions), `AgentValidationEngine`, `MCPValidationEngine`.

### Continuous Validation (Posture Management)
**Status**: Complete  
**Location**: `domain/posture/`, `application/posture/`  
**Purpose**: Tracks security posture over time, detects regressions, trends, and configuration drift.  
**Components**: `ValidationSnapshot` (immutable, per-run), `ValidationBaseline` (promoted reference point), `SecurityPostureCalculator`, `TrendAnalyzer`, `DriftDetector`, `RegressionAnalyzer`, `BaselineService`, `SnapshotService`.

### Security Intelligence Engine
**Status**: Complete  
**Location**: `domain/intelligence/`, `application/intelligence/`  
**Purpose**: Rules-based reasoning pipeline (no LLM) that produces insights and recommendations.  
**Components**: `CoverageAnalyzer`, `GapAnalyzer`, `InsightGenerator`, `RecommendationGenerator`, `PriorityEngine`, `NarrativeBuilder`, `IntelligenceService` (orchestrates all).

### Enterprise AI Asset Inventory
**Status**: Complete  
**Location**: `domain/inventory/`, `application/inventory/`  
**Purpose**: Catalogues all AI assets an organization owns or depends on. Feeds into validation target selection.  
**Components**: `AIAsset` aggregate (13 asset types), 6-phase `InventoryService` pipeline, `DeterministicFingerprintEngine`, `DefaultAssetNormalizer`, `DefaultDependencyResolver`, `DefaultRelationshipResolver`.

### AI Connector & Discovery Framework
**Status**: Complete  
**Location**: `domain/connectors/`, `application/connectors/`  
**Purpose**: Discovers AI assets from external platforms and feeds them into the Inventory pipeline.  
**Components**: `Connector` aggregate (11 connector types), `ConnectorService` (lifecycle), `DiscoveryService`, `SyncService`, `ConnectorRegistry` (dict-dispatched), `StubConnectors` for testing.

### Knowledge Graph
**Status**: Complete  
**Location**: `application/knowledge_graph.py`, `application/knowledge_graph_populator.py`  
**Purpose**: In-memory semantic graph linking all platform objects for traversal, investigation, and reporting.  
**Components**: See [Section 6](#6-knowledge-graph).

### Risk Correlation Engine
**Status**: Complete  
**Location**: `application/risk_engine.py`  
**Purpose**: Correlates Findings and Evidence into Risk Incidents with CVSS-inspired scoring.  
**Components**: `RiskCorrelationEngine`, `RiskScoreCalculator` (protocol), `RiskIncident`, `RiskHistory`.

### Event Platform
**Status**: Complete (in-memory reference impl; production storage deferred to Sprint 25)  
**Location**: `domain/platform/`, `application/platform/`  
**Purpose**: Canonical immutable event backbone with projection-based read models.  
**Maturity**: Protocol layer is production-quality. `InMemoryEventStore` is dev/test only (no persistence across restarts).  
**Components**: See [Section 2 — Platform bounded context](#platform-domainplatform--applicationplatform).

### Infrastructure Services
**Status**: Complete  
**Components**: Argon2id password hashing, PyJWT authentication with refresh tokens, rate limiting (token bucket), OpenTelemetry (configurable), Prometheus metrics (middleware), structlog JSON logging, audit logging, security headers, CORS, health/readiness endpoints, GitHub Actions CI, Docker multi-stage non-root builds, Alembic migrations (migration head: 0009).

**Sprint 31 additions** (migration 0009): `reserved_until TIMESTAMPTZ` + `exhausted_at TIMESTAMPTZ` on `dead_letter_entries`; partial index `ix_dle_claimable` on `status IN ('requeued','in_flight')`.

---

## 4. Repository Structure

```
aivar-redforge/
├── backend/
│   ├── src/redforge/
│   │   ├── __init__.py             # package root, version
│   │   ├── app.py                  # FastAPI application factory
│   │   │
│   │   ├── core/                   # zero external dependencies
│   │   │   ├── logging.py          # structlog JSON/console configuration
│   │   │   ├── exceptions.py       # base exception hierarchy
│   │   │   └── settings.py         # pydantic-settings configuration
│   │   │
│   │   ├── shared/                 # cross-domain primitives
│   │   │   ├── identifiers.py      # EntityId (ULID-backed)
│   │   │   ├── timestamps.py       # AuditTimestamps, utc_now()
│   │   │   └── entity.py           # BaseEntity base class
│   │   │
│   │   ├── domain/                 # pure Python business logic — zero infra imports
│   │   │   ├── identity/           # User, Membership, Invitation aggregates
│   │   │   ├── organizations/      # Organization aggregate
│   │   │   ├── ai_targets/         # AITarget aggregate
│   │   │   ├── attack_library/     # AttackDefinition, AttackTaxonomyNode
│   │   │   ├── policies/           # ValidationPolicy
│   │   │   ├── payloads/           # PayloadTemplate, PayloadBundle
│   │   │   ├── planning/           # AttackPlan aggregate
│   │   │   ├── execution/          # ExecutionPlan aggregate
│   │   │   ├── validations/        # ValidationRun aggregate
│   │   │   ├── evidence/           # Evidence aggregate (immutable)
│   │   │   ├── findings/           # Finding aggregate
│   │   │   ├── providers/          # Provider adapter registration
│   │   │   ├── knowledge/          # KnowledgeItem aggregate
│   │   │   ├── posture/            # ValidationSnapshot, ValidationBaseline
│   │   │   ├── intelligence/       # SecurityInsight, Recommendation, Report
│   │   │   ├── inventory/          # AIAsset aggregate
│   │   │   ├── connectors/         # Connector aggregate
│   │   │   ├── conversations/      # ConversationSession aggregate
│   │   │   ├── agents/             # AgentSession, MCPSession aggregates
│   │   │   └── platform/           # EventEnvelope, Platform value objects, read models
│   │   │
│   │   ├── application/            # use case orchestration — no infra imports
│   │   │   ├── auth.py             # authentication use cases
│   │   │   ├── ai_targets.py       # AI target use cases
│   │   │   ├── organizations.py    # org use cases
│   │   │   ├── validation_service.py  # canonical validation execution path
│   │   │   ├── validation_contracts.py  # protocols for validation collaborators
│   │   │   ├── risk_engine.py      # risk correlation and incident production
│   │   │   ├── knowledge_graph.py  # in-memory semantic graph
│   │   │   ├── knowledge_graph_populator.py  # populates KG post-validation
│   │   │   ├── attack_knowledge_projector.py  # projects attacks into KG
│   │   │   ├── scheduler.py        # validation scheduling service
│   │   │   ├── execution_graph.py  # DAG execution support
│   │   │   ├── contracts.py        # cross-cutting application protocols
│   │   │   ├── evaluation_adapters.py  # evaluation protocol adapters
│   │   │   ├── pipeline.py         # legacy (superseded by validation_service.py)
│   │   │   │
│   │   │   ├── runtime/            # execution engine components
│   │   │   │   ├── orchestrator.py # thin coordination (zero business logic)
│   │   │   │   ├── dispatcher.py   # InProcessDispatcher (reference impl)
│   │   │   │   ├── executors.py    # ChatCompletionExecutor
│   │   │   │   ├── classifiers.py  # KeywordClassifier (reference impl)
│   │   │   │   └── contracts.py    # StepExecutor, ResponseClassifier, etc.
│   │   │   │
│   │   │   ├── attacks/            # attack execution strategies
│   │   │   ├── campaigns/          # CampaignEngine, DriftDetector, contracts
│   │   │   ├── connectors/         # ConnectorService, DiscoveryService, SyncService, Registry
│   │   │   ├── conversations/      # ConversationEngine, DecisionEngine
│   │   │   ├── agents/             # AgentValidationEngine, MCPValidationEngine
│   │   │   ├── evidence/           # evidence service
│   │   │   ├── findings/           # findings service
│   │   │   ├── intelligence/       # IntelligenceService + 6 pipeline components
│   │   │   ├── inventory/          # InventoryService + 4 pipeline components
│   │   │   ├── invitations/        # invitation service
│   │   │   ├── memberships/        # membership service
│   │   │   ├── payloads/           # payload service
│   │   │   ├── policies/           # policy service
│   │   │   ├── posture/            # SecurityPostureCalculator + 4 services
│   │   │   ├── providers/          # provider service
│   │   │   ├── scenarios/          # ScenarioRunner, profiles, models
│   │   │   ├── validations/        # validation service wrapper
│   │   │   └── platform/           # EventStore, ProjectionEngine, ReplayEngine + 10 projections
│   │   │
│   │   ├── infrastructure/         # framework adapters — implements domain protocols
│   │   │   ├── auth/               # Argon2id hasher, PyJWT manager
│   │   │   ├── audit/              # AuditLogger implementation
│   │   │   ├── database/
│   │   │   │   ├── engine.py       # SQLAlchemy async engine
│   │   │   │   ├── models/         # ORM models (5 currently persisted)
│   │   │   │   ├── mappings/       # domain ↔ ORM mappers
│   │   │   │   ├── repositories/   # SQLAlchemy repository implementations
│   │   │   │   └── migrations/     # Alembic migration scripts (10 tables)
│   │   │   ├── middleware/         # CORS, security headers, Prometheus metrics, correlation ID
│   │   │   ├── notifications/      # email/notification adapters
│   │   │   ├── providers/          # OpenAI, Anthropic provider adapters
│   │   │   ├── rate_limiting/      # token bucket rate limiter
│   │   │   ├── repositories/       # shared infra repository helpers
│   │   │   └── telemetry/          # OpenTelemetry setup
│   │   │
│   │   └── api/                    # FastAPI HTTP transport — thin, no business logic
│   │       ├── dependencies.py     # DI wiring (repositories, services, auth)
│   │       ├── router.py           # root router
│   │       ├── security.py         # JWT extraction, permission guards
│   │       └── v1/                 # 19 route modules (see below)
│   │
│   ├── tests/
│   │   ├── unit/                   # 90 unit test files — no external dependencies
│   │   ├── integration/            # 17 integration test files — async, in-memory infra
│   │   └── api/                    # 5 API test files — FastAPI TestClient
│   │
│   └── pyproject.toml              # dependencies, ruff, mypy, pytest config
│
├── docs/
│   ├── about-product.md            # product vision (original)
│   ├── PROJECT_CONTEXT.md          # this document
│   └── adr/                        # Architecture Decision Records
│       ├── 0001-clean-architecture.md
│       ├── 0002-async-first.md
│       ├── 0003-evidence-immutability.md
│       └── 0004-plugin-based-attack-engine.md
│
└── .kiro/steering/                 # additional AI steering docs
    ├── ai-security-vision.md
    ├── architecture.md
    ├── tech-stack.md
    └── reference-docs.md
```

### Why each folder exists

- **`core/`**: Zero-dependency primitives. Logging, exceptions, settings. Everything else can import from here; this imports nothing.
- **`shared/`**: Cross-domain primitives used by every bounded context: `EntityId` (ULID), `AuditTimestamps`, `BaseEntity`.
- **`domain/`**: Pure Python business logic. No SQLAlchemy, no FastAPI, no HTTP clients. Each subdirectory is a bounded context with its own entities, value objects, events, exceptions, and repository protocols.
- **`application/`**: Use case orchestration. Coordinates domain objects. Defines application services, protocols (ports), and runtime engines. The only place that wires domain objects together.
- **`infrastructure/`**: Implements domain protocols with real frameworks. SQLAlchemy repositories, Argon2id hasher, OpenAI adapter, OpenTelemetry. Can be swapped without touching domain or application.
- **`api/`**: FastAPI routes. Deserializes HTTP, calls application services, serializes responses. Contains zero business logic.
- **`tests/`**: `unit/` tests domain/application in isolation (fast, no DB). `integration/` tests full application flows with async in-memory infrastructure. `api/` tests HTTP layer with TestClient.

---

## 5. End-to-End Event Flow

The canonical security validation pipeline:

```
1. INVENTORY
   External platform (OpenAI, LangSmith, etc.)
     → Connector.DiscoveryJob
     → DiscoveryService → DiscoveredAssetInput[]
     → InventoryService (6 phases: normalize, dedup, fingerprint,
                          resolve relationships, project to KG, snapshot)
     → AIAsset (persisted)
     → InventoryReadModel (platform projection)

2. PLANNING
   AITarget (enrolled for security testing) + ValidationPolicy
     → AttackPlanner.plan()
     → AttackPlan (immutable, sequenced, risk-ordered)
     → AttackPlan.sequence → ExecutionPlan (runtime tracker)

3. PAYLOAD
   ExecutionPlan steps × AttackDefinition
     → PayloadTemplate.render(RenderContext)
     → RenderedPayload (validated, all variables resolved)

4. EXECUTION
   ValidationService.execute(ValidationServiceRequest)
     → ValidationRun.schedule() → SCHEDULED
     → ValidationRun.start()   → RUNNING
     → for each attack step:
         StepContext → ChatCompletionExecutor.execute()
         → Provider Adapter → AI Target HTTP call
         → StepEvidence (request + response + timing captured)

5. EVALUATION
   StepEvidence → ResponseClassifier.classify()
     → ClassificationResult (outcome, confidence, reasoning)
     → EvaluationPipeline (multi-evaluator: Keyword, Pattern, Rule)
     → EvaluationResult (PASS / FAIL / ERROR / INCONCLUSIVE)

6. EVIDENCE
   ClassificationResult + StepEvidence
     → Evidence.record() → Evidence.finalize()
     → Immutable EvidenceResult (append-only, never modified)

7. FINDING
   Evidence (FAIL result) → FindingCandidateGenerator
     → Finding.create() (references evidence_id, carries severity + risk score)
     → MITRE ATLAS + OWASP reference mapping

8. RISK
   [Finding, Evidence] → RiskCorrelationEngine
     → RiskScoreCalculator (CVSS-inspired factors)
     → RiskIncident (correlated, scored, prioritized)

9. INTELLIGENCE
   [RiskIncident, Finding, Snapshot] → IntelligenceService pipeline
     → CoverageAnalyzer → GapAnalyzer → InsightGenerator
     → RecommendationGenerator → PriorityEngine → NarrativeBuilder
     → IntelligenceReport (insights, recommendations, narratives)

10. KNOWLEDGE GRAPH
    (Post-commit, isolated)
    KnowledgeGraphPopulator.populate()
      → Nodes: Organization, AITarget, Provider, Model, Attack,
               Evidence, Finding, RiskIncident, Compliance, MITRE, OWASP
      → Edges: TARGET_USES_PROVIDER, ATTACK_GENERATES_EVIDENCE,
               EVIDENCE_GENERATES_FINDING, FINDING_INCREASES_RISK, etc.

    KGProjection (Platform Event stream consumer)
      → Receives inventory/asset/connector events via EventEnvelope
      → Calls existing KnowledgeGraph.add_node() / add_edge()
      → KnowledgeGraphReadModel updated

11. EVENT PLATFORM
    All domain events → EventEnvelope.make_envelope()
      → InMemoryEventStore.append() (monotonic global_position assigned)
      → ProjectionEngine.process_batch()
        → InventoryProjection, CampaignProjection, ValidationProjection,
          EvidenceProjection, RiskProjection, IntelligenceProjection,
          KGProjection, ConnectorActivityProjection,
          OrgActivityProjection, AssetTimelineProjection
        → ReadModel per projection (stored in InMemoryReadModelRepository)
    ReplayEngine (8 filter dimensions) for catch-up and audit
    Timeline/AuditTimeline assembled by TimelineService
```

---

## 6. Knowledge Graph

### What it is

An in-memory property graph (`application/knowledge_graph.py`) that lives in the Application layer. It is NOT a graph database. It connects all major platform objects into a traversable, queryable semantic network.

All references are by ID (string). The graph never imports or modifies domain aggregates.

### Node Types (41 types)

Organized by source bounded context:

| Group | Node Types |
|-------|-----------|
| Core | ORGANIZATION, AI_TARGET, PROVIDER, MODEL, VALIDATION_POLICY |
| Attack | ATTACK_DEFINITION, PAYLOAD_TEMPLATE, ATTACK_TAXONOMY_NODE |
| Evidence | EVIDENCE, EVIDENCE_CHAIN, EVALUATION_RESULT |
| Findings | FINDING, RISK_INCIDENT, COMPLIANCE_REFERENCE, MITRE_ATLAS, OWASP_LLM |
| Campaign | CAMPAIGN, CONVERSATION_SESSION, CONVERSATION_TURN |
| Agents | AGENT_SESSION, TOOL, TOOL_INVOCATION, MCP_SERVER, MCP_RESOURCE, MCP_SESSION, WORKFLOW, TOOL_CHAIN, ATTACK_PATH |
| Posture | VALIDATION_SNAPSHOT, VALIDATION_BASELINE, SECURITY_POSTURE, VALIDATION_TREND, REGRESSION_EVENT, DRIFT_EVENT |
| Intelligence | INSIGHT, RECOMMENDATION, REMEDIATION_PLAN, COVERAGE_GAP, INTELLIGENCE_REPORT |
| Inventory | AI_APPLICATION, AI_AGENT_ASSET, AI_MODEL, AI_PROVIDER_ASSET, RAG_SYSTEM, MCP_SERVER_ASSET, PROMPT_TEMPLATE, TOOL_DEFINITION, MEMORY_STORE, KNOWLEDGE_BASE, EMBEDDING_MODEL, VECTOR_DATABASE, AI_ENDPOINT, INVENTORY_SNAPSHOT |
| Connectors | CONNECTOR, DISCOVERY_JOB, SYNC_JOB, EXTERNAL_PLATFORM, INVENTORY_SOURCE |

### Relationship Types

Named semantic predicates connecting nodes. Key relationships by sprint:

- Core: `TARGET_USES_PROVIDER`, `TARGET_USES_MODEL`, `POLICY_EXECUTES_ATTACK`, `ATTACK_GENERATES_EVIDENCE`, `EVIDENCE_GENERATES_FINDING`, `FINDING_INCREASES_RISK`, `RISK_REFERENCES_COMPLIANCE`, `ATTACK_MAPS_TO_MITRE`, `ATTACK_MAPS_TO_OWASP`
- Attack taxonomy: `ATTACK_PARENT_OF`, `ATTACK_DERIVED_FROM`, `ATTACK_PREREQUISITE_OF`, `ATTACK_COMPOSED_OF`, `TAXONOMY_PARENT_OF`, `ATTACK_CLASSIFIED_UNDER`
- Evaluation: `EVIDENCE_EVALUATED_AS`, `EVALUATION_CONTRIBUTES_RISK`
- Campaign: `CAMPAIGN_COVERS_TARGET`, `CAMPAIGN_PRODUCED_FINDING`, `CAMPAIGN_REGRESSED_FROM`
- Conversations: `CONVERSATION_SESSION_TARGETS`, `CONVERSATION_SESSION_HAS_TURN`, `CONVERSATION_PART_OF_CAMPAIGN`
- Agents/MCP: `AGENT_SESSION_TARGETS`, `AGENT_SESSION_INVOKED_TOOL`, `AGENT_HAS_TOOL`, `MCP_SERVER_EXPOSES_TOOL`, `MCP_SERVER_HAS_RESOURCE`, `TOOL_CHAIN_LEADS_TO`
- Posture: `SNAPSHOT_TARGETS`, `BASELINE_FROM_SNAPSHOT`, `POSTURE_INCLUDES_SNAPSHOT`, `REGRESSION_DETECTED_FROM`, `DRIFT_FROM_BASELINE`, `TREND_FOR_TARGET`
- Intelligence: `INSIGHT_FROM_FINDING`, `RECOMMENDATION_FROM_INSIGHT`, `RECOMMENDATION_TARGETS`, `REMEDIATION_FOR_RECOMMENDATION`
- Inventory: `APP_OWNS_AGENT`, `AGENT_USES_MODEL`, `AGENT_USES_TOOL`, `AGENT_USES_MCP`, `RAG_USES_VECTOR_DB`
- Connectors: `CONNECTOR_BELONGS_TO_ORG`, `CONNECTOR_DISCOVERED_ASSET`

### Projection strategy

The `KGProjection` (Sprint 24) subscribes to the Platform event stream and translates relevant events into KG node/edge operations. This decouples the KG from direct domain aggregate knowledge.

`KnowledgeGraphPopulator` (older path) is called post-commit by `ValidationService` to project validation results.

`AttackKnowledgeProjector` projects attack library changes.

### Consumers

- `GraphTraversal`: BFS/DFS traversal, shortest-path, reachability queries
- `GraphStatistics`: node/edge counts, density, top-connected nodes, relationship distribution
- `GraphSerializer.to_dict()`: GraphRAG-compatible export
- API endpoint `GET /api/v1/knowledge-graph/...` for queries
- `KGProjection`: Sprint 24 projection consumer (feeds KG from event stream)

### Backend swap

`GraphStore` is a `Protocol`. Implementing it against Neo4j, Amazon Neptune, or Memgraph replaces the in-memory store with zero logic changes.

---

## 7. Design Principles

These are non-negotiable. Every PR must uphold all of them.

### Domain-Driven Design

- Business concepts are rich domain objects with behavior, not anemic data structures
- Entities have identity (`EntityId` ULID), lifecycle, and state transitions enforced by the aggregate
- Value objects are immutable, validated on construction, equality by value
- Domain events carry what happened; subscribers react without tight coupling
- Bounded contexts have hard boundaries — cross-context references use IDs, never object references

### Clean Architecture

- Dependency rule: `API → Application → Domain`. Infrastructure implements domain protocols.
- Domain layer: zero imports from infrastructure, API, or any framework
- Application layer: zero imports from infrastructure. All collaborators injected as protocols.
- Infrastructure layer: implements domain protocols. May import frameworks.
- API layer: thin. Deserializes HTTP, delegates to application services, serializes responses. Zero business logic.

### Protocol-first

- Every extension point is a Python `@runtime_checkable Protocol`
- Application services depend on protocols, not concrete implementations
- Infrastructure provides implementations that are injected at startup
- Tests inject stub/in-memory implementations — no real DB or API calls needed

### Repository Pattern

- Each aggregate has a `Repository` protocol in the domain layer
- Repositories expose `save()`, `get_by_id()`, `list_*()` — no `commit()`, no `rollback()`
- `UnitOfWork` owns transaction boundaries. Repositories never call commit directly.

### UnitOfWork

- Transaction boundaries are owned by `UnitOfWork`, not individual repositories
- `ValidationService` commits Evidence + Findings + ValidationRun in one UoW
- Post-commit side effects (KG population, event publishing) are explicitly isolated — a failure there cannot retroactively fail a committed run

### Immutability

- All value objects are frozen dataclasses or `__slots__`-based classes
- Evidence is immutable after `finalize()` — no `update()` method, no API endpoint
- `EventEnvelope` is `frozen=True, slots=True`
- `AttackPlan` is immutable except for `supersede()` (creates a new plan, marks old one superseded)
- Platform events are `frozen=True`

### Registry Pattern

- `ConnectorRegistry` maps `ConnectorType` → `DiscoveryProvider` implementation (dict-dispatched, no switch)
- `AttackLibraryRepository` is the canonical registry for attack definitions
- No hardcoded lists of types. New types register in the dict.

### No switch statements

- Type dispatch uses dicts: `_handlers: dict[str, list[Handler]]` in `ProjectionEngine`
- Provider-specific behavior: dict mapping in `ConnectorRegistry`, `_DEFAULT_CAPABILITIES`
- Severity mapping: `SEVERITY_TO_SCORE: dict[str, float]` in `validation_mappers.py`
- Anywhere a `match`/`if type == X` chain tempts you: replace with a dict + polymorphism

### No duplicated business logic

- `FailureStrategy` / `RetryPolicy` are defined ONCE in `domain/execution/` and imported by Planning
- `Confidence` is defined ONCE in `domain/evidence/` and imported by Planning
- `EvaluationRequirement` / `ExpectedOutcome` are defined ONCE in `domain/attack_library/`
- Never create `ValidationCategory` — `AttackCategory` already exists
- Never create `ValidationDefinition` — `AttackDefinition` already exists

### Dependency Injection

- Application services receive all collaborators via constructor
- FastAPI route handlers receive repositories and services via `Depends()`
- No `import X; service = X()` at module level in application code

---

## 8. Technology Stack

### Core language

- **Python 3.12+** (project targets `>=3.12`, mypy configured for `3.14`)
- Fully async: `asyncio`, `async def`, `await` throughout infrastructure and application

### Web framework

- **FastAPI** `>=0.115` — async HTTP, automatic OpenAPI, Pydantic v2 integration
- **Uvicorn** (standard) — ASGI server
- **Pydantic v2** `>=2.10` — request/response models, settings

### Database

- **SQLAlchemy 2.x** with asyncio — async ORM
- **asyncpg** — PostgreSQL async driver
- **Alembic** — migrations (10 tables currently)
- **aiosqlite** — dev/test SQLite (avoids requiring PostgreSQL for unit tests)

### Authentication / Security

- **Argon2-cffi** — password hashing (Argon2id variant)
- **PyJWT[crypto]** — JWT tokens with crypto support

### HTTP client

- **httpx** `>=0.28` — async HTTP for provider adapter calls

### Observability

- **structlog** `>=24.4` — structured JSON logging
- **prometheus-client** — metrics exposition
- **opentelemetry-api/sdk** + exporters — distributed tracing
- **opentelemetry-instrumentation-fastapi/sqlalchemy/httpx** — auto-instrumentation

### Domain primitives

- **python-ulid** `>=3.0` — ULID-based entity IDs (sortable, B-tree friendly)

### Testing

- **pytest** `>=8.3` with **pytest-asyncio** `>=0.25`
- **pytest-cov** — coverage
- **httpx** — FastAPI TestClient (async)
- All tests run without real PostgreSQL or real AI API credentials

### Code quality

- **ruff** `>=0.8` — linting (E, W, F, I, N, UP, B, SIM, TCH, RUF rule sets)
- **mypy** `>=1.14` in strict mode — `warn_return_any`, `warn_unused_configs`
- **pre-commit** — hooks for ruff + mypy

### Configuration

- `pyproject.toml` — single configuration file for all tools
- `pydantic-settings` — environment-based config
- `.env.example` — documented environment variables

### Architecture decisions documented

- **ADR-0001**: Clean Architecture with Domain-Driven Boundaries
- **ADR-0002**: Async-First Backend Architecture  
- **ADR-0003**: Evidence Immutability as Architectural Constraint
- **ADR-0004**: Plugin-Based Attack Engine

---

## 9. Coding Rules

These rules apply to every future AI coding session and every human PR. No exceptions.

### Before writing any code

1. **Read `docs/PROJECT_CONTEXT.md`** (this document)
2. **Read `docs/about-product.md`**
3. **Read all ADRs** in `docs/adr/`
4. **Inspect the existing codebase** — the concept you want to add may already exist
5. **Never trust documentation alone** — verify by reading source files

### Architecture rules

1. **Never introduce business logic in FastAPI routes** — routes deserialize, delegate, serialize
2. **Never import from infrastructure in domain or application layers**
3. **Never bypass protocols** — if a protocol exists for it, use it
4. **Never duplicate bounded contexts** — `AttackDefinition` models attacks; do not create `ValidationDefinition`. `AttackCategory` classifies attacks; do not create `ValidationCategory`.
5. **Never create parallel models** — one source of truth per concept
6. **Prefer extension over modification** — add a protocol implementation; do not rewrite existing ones
7. **Produce an ADR before major structural changes** — if a change affects bounded context boundaries or execution flows, write the architecture first

### Domain rules

8. **Entity invariants live in the entity** — not in services, not in validators
9. **Value objects validate on construction** — they cannot exist in an invalid state
10. **Repository protocols have no `commit()`** — UnitOfWork owns transaction boundaries
11. **Evidence has no `update()` method** — it is append-only by architectural constraint (ADR-0003)
12. **All state changes emit domain events** — events are the integration mechanism
13. **Cross-context references use IDs only** — never embed a foreign aggregate

### Implementation rules

14. **No switch statements for type dispatch** — use dicts, polymorphism, or registries
15. **`slots=True` on all frozen dataclasses** — memory-efficient, no accidental attribute assignment
16. **Use `from __future__ import annotations`** in modules with forward references
17. **Move `TYPE_CHECKING`-only imports under `if TYPE_CHECKING:`** — required for ruff TCH rules
18. **Use `contextlib.suppress(SomeError)` instead of `try: ... except SomeError: pass`** — SIM105
19. **Async generators for streaming/paginated reads** — `AsyncIterator[T]` not `list[T]`

### Testing rules

20. **All tests run without external dependencies** — no real PostgreSQL, no real AI APIs
21. **Update tests after every change** — failing tests are blockers, not warnings
22. **Test domain logic in unit tests** — fast, deterministic, no async infrastructure
23. **Test full flows in integration tests** — async, in-memory infrastructure

### Quality gates (must pass before any PR merges)

```bash
# From backend/
python -m ruff check src/ tests/
python -m mypy src/redforge/domain/ src/redforge/application/ --strict
python -m pytest -q --tb=short
```

All three must be clean. Zero ruff violations. Zero mypy errors. All tests pass.

---

## 10. Completed Milestones

| Sprint | Architecture Introduced | Key Deliverables | Tests |
|--------|------------------------|------------------|-------|
| M17 (COMPLETE) | Enterprise Identity, Super Admin & RBAC Control Plane | See [M17_ENTERPRISE_IDENTITY_SUPER_ADMIN_RBAC_REPORT.md](M17_ENTERPRISE_IDENTITY_SUPER_ADMIN_RBAC_REPORT.md) and [M17_COMPLETION_CHECKPOINT.md](M17_COMPLETION_CHECKPOINT.md) for full detail. Reconnaissance found platform Super Admin authority 100% pre-existing from M1/M2 (`domain/platform_identity/`, `PlatformAccessService`, `api/security.py`'s live-DB-lookup `PlatformContext`, migration 0011, config-gated one-time bootstrap) — reused entirely unchanged, not rebuilt. The genuine gap was organization-scoped custom Roles/Groups on top of the pre-existing fixed `MembershipRole`/`ROLE_PERMISSIONS` table; new `domain/rbac/`+`application/rbac/` bounded context adds `OrganizationRole`/`OrganizationGroup` (migration 0026: 7 tables, tenant-integrity enforced via composite `(id, organization_id)` foreign keys at the database level, not just application checks); system roles (OWNER/ADMIN/SECURITY_MANAGER/ANALYST/MEMBER/VIEWER) are synthesized on the fly (`id="system:<role>"`, never persisted) so "cannot be mutated" is structural, not an application check that could be forgotten; one canonical `EffectiveAccessService` (direct-role ∪ group-derived-role ∪ fixed-role permissions, explain view at `GET /admin/users/{id}/effective-access`, additive fast-path wired into `get_tenant_context`); one centralized `assert_can_grant()` bounded-delegation policy (an actor can never grant a permission they don't themselves hold) as the single call site for every role/group mutation, replacing any need for scattered escalation checks; new `/api/v1/admin/*` router (21 routes: role/group CRUD, permission catalog, direct/group role assignment, effective-access explain, organization admin audit trail) following the M14-M16 no-organization-id-in-URL convention; new Organization Admin frontend (`/roles`, `/groups-rbac`, `/access-explorer` — permission-matrix editor grouped by backend-authoritative catalog, group membership/role management, self-service + admin effective-access explain view) added to the existing app shell. **Two real defects found and fixed during adversarial testing**: (P1, security) a suspended organization membership's already-issued JWT kept working indefinitely — `get_tenant_context` checked global user status and org suspension live but never re-checked the individual membership's own status; fixed with `EffectiveAccessService.is_membership_active()`, now enforced on every tenant-scoped request; (P2) a TOCTOU race between the duplicate-name pre-check and the actual role/group INSERT, found by code review not a failing test, fixed with `IntegrityError` handling making the database's unique constraint the real backstop (proven by 4 real-PostgreSQL concurrency tests). Adding the new `EffectiveAccessService` dependency also broke 28 pre-existing test files that build isolated FastAPI test apps without a real database engine (missing dependency override) — fixed across all 28. 18 adversarial live-acceptance tests (real PostgreSQL, real HTTP) + 9 fast unit tests cover the golden path, real cross-request enforcement, escalation rejection, cross-tenant non-disclosure, malformed-ID handling, duplicate rejection, system-role immutability, deletion-blocked-while-assigned, suspended-member lockout, and 4 concurrency races — all passing. Clean migration 0001→0026→0025→0026 up/down/up proof. Real browser acceptance performed against a live backend+frontend+PostgreSQL: Organization Admin flow (create custom role, edit permission matrix, create group — all confirmed via real 200/201 HTTP responses) and Normal User flow (a VIEWER is denied 403 by the real backend on both read and write, the frontend renders a clean non-crashing "no access" panel, and the self-service Access Explorer correctly limits to one's own user_id). One pre-existing, disclosed, cross-milestone full-suite test-infrastructure characteristic (a global DB-engine-singleton/per-test-module-event-loop collision affecting 3 Postgres integration test files across M15/M16/M17 when the full 4126-test suite runs in one process) was found and root-caused during this pass; it was fixed as a dedicated follow-up immediately afterward — see the row below. | 4,097 |
| Infrastructure closure (COMPLETE) | PostgreSQL Async Engine Lifecycle & Full-Suite Reliability | See [POSTGRES_ASYNC_ENGINE_LIFECYCLE_RELIABILITY_REPORT.md](POSTGRES_ASYNC_ENGINE_LIFECYCLE_RELIABILITY_REPORT.md) and [TEST_INFRASTRUCTURE_RELIABILITY_CHECKPOINT.md](TEST_INFRASTRUCTURE_RELIABILITY_CHECKPOINT.md) for full detail. Root-caused and fixed the cross-milestone full-suite instability flagged in the M17 row above. **Primary defect**: `api/dependencies.py`'s `_session_factory()` and ~40 other `@lru_cache`-decorated DB-bound service providers memoize for the life of the *process*, not the life of the database *engine* — surviving `create_engine()`/`dispose_engine()` cycles and silently serving connections bound to a disposed engine's dead event loop whenever more than one `create_app()` lifespan runs in one process (exactly what the test suite does routinely: `test_rbac_live_acceptance.py`, `test_network_security_restart_durability.py`, etc.). Reproduced directly (`sf1 is sf2 → True`, still bound to the first, disposed engine) and confirmed via two genuinely separate event loops each running a full app lifespan — cycle 2 of 5 crashes pre-fix with `RuntimeError: Event loop is closed`, all 5 pass post-fix. Fixed with a new `clear_cached_dependencies()` (introspects the module's own globals for any `functools.lru_cache`'s `cache_clear` attribute, so it covers every current and future cached provider with nothing to remember to update), called defensively at the start of `_start_database()` and primarily at the end of `_shutdown_database()`. Diagnosing this surfaced (and this pass fixed) 5 further genuine, previously-undetected gaps it had been masking: two proof databases needing Alembic pre-migration were dropped without re-migrating during clean-state diagnosis (self-inflicted, corrected); `test_security_operations_postgres_proof.py`'s and `test_protocol_aware_service_validation_postgres_proof.py`'s proof-database fixtures never created tables their own code-under-test had since grown to depend on (M16 network-security event tables, Security Graph tables respectively) — the former's every-test setup failure left an uncommitted transaction that hung the module's teardown indefinitely, a genuine reproducible hang traced via `pg_stat_activity`, not a flake; and two **real, pre-existing (since M4/M3) data-integrity defects** — `security_graph_nodes` was missing the unique constraint on `(organization_id, source_domain, source_entity_id)` its own module docstring calls canonical (new migration `0027`), and the real, correctly-migrated `ux_ai_assets_org_external_id` partial index (M3, migration `0013`) was never declared on `AIAssetModel.__table_args__`, so `Base.metadata.create_all()`-based test fixtures never created it, masking a genuine concurrent-duplicate-service-asset race until the Security Graph fix let the test reach that code path. `_EXPECTED_MIGRATION_HEAD` bumped 0026→0027. Migration proof: clean `0001→0027→0026→0027` up/down/up. Full backend suite run twice from a genuinely clean database state: **4125 passed / 0 failed / 0 errors / 5 skipped, both runs identical**, no exclusions, no hidden skips, no manual process/session termination needed for either accepted run, verified via active `pg_stat_activity` monitoring throughout (no idle-in-transaction residue, no lock hangs, no connection leaks). The two test files previously carrying M16-era "known flake" disclosures are no longer flaky — both root causes were real, fixable defects, not inherent timing flakiness. | 4,125 |
| M16 (COMPLETE) | Advanced Network Security & Continuous Network Monitoring | See [M16_ADVANCED_NETWORK_SECURITY_MONITORING_REPORT.md](M16_ADVANCED_NETWORK_SECURITY_MONITORING_REPORT.md) and [M16_COMPLETION_CHECKPOINT.md](M16_COMPLETION_CHECKPOINT.md) for full detail. Reuses AIAsset/identity/M10 authorization/M11-M13 network primitives/M8-M9 services/Security Graph v5 entirely unchanged; adds `NetworkValidationRun`/`NetworkMonitoringPolicy`/`NetworkStateSnapshot`/`NetworkDriftEvent` (migration 0024) as documented parallels to ValidationExecution/ContinuousValidationPolicy — new only because `AITarget`'s `EndpointUrl` shape structurally cannot represent an IP/CIDR sweep target; `domain/network_security/address.py` does canonical IP/CIDR normalization/classification/bounded-expansion (`ipaddress` stdlib only, MAX 256 addresses/execution, O(1) size check before any materialization, `/0` rejected unconditionally); `application/network_security/authorization_scope.py::NetworkAuthorizationScopeChecker` adds CIDR-containment resolution on top of the UNCHANGED M10 `SecurityAuthorization`/`ScopeEntityType.AI_ASSET`/`ActionClass.ACTIVE_VALIDATION` (no new scope type, no M10 domain edit) — every concrete address re-checked fresh twice per run (plan time + immediately pre-probe), with MULTICAST/UNSPECIFIED/METADATA hard-denied regardless of authorization while LOOPBACK/PRIVATE/PUBLIC are purely authorization-gated (a documented, deliberate departure from M11's own categorical PUBLIC-only `network_boundary.py`, left untouched — different risk profile: M11 makes attacker-influenced redirect-following requests against a validated AI system's own endpoint, M16 only ever probes an address a same-tenant authorization has explicitly and freshly scoped); reachability/protocol/TLS truth reuses M11/M13's pure `(address, port, timeout)` primitives (`check_tcp_connectivity`, `perform_tls_handshake`, `evaluate_tls_findings`, `ProtocolValidatorRegistry`) directly, with zero new validators — port≠protocol enforced by construction; new `network_observations` table persists an explicit allowlist only (never raw banners/credentials/headers/private keys); M6's `TenantNetworkDiscoveryService`/M8's `TenantSecurityConditionService`/M9's `TenantSecurityCorrelationService` (existing 2 rules, no new rule needed) are reused completely unmodified for asset/condition/correlation truth; M15 integration adds `SourceDomain.NETWORK_SECURITY` + 2 new durable event tables + 2 new `project_xxx_event()` functions wired into `fetch_merged_candidates()` (the real, documented M15 extension pattern — not the dormant `EventEnvelope` the initial M16 brief mistakenly assumed feeds M15); RBAC adds `NETWORK_SECURITY_READ`/`NETWORK_SECURITY_MANAGE` (OWNER/ADMIN/SECURITY_MANAGER get both, others READ-only; MANAGE never bypasses the M10 per-address gate); new REST API (`/api/v1/network-security/*`, 9 routes, zero command/script/exploit/scanner-flag fields anywhere) and a new frontend product surface (`/network-security` inventory + monitoring-policy console, `/network-security/assets/[id]` detail) using the existing plain-`fetch` client convention; 103 automated tests (up from 73: address/classification/bounds/canonical-dedup, authorization-scope adversarial matrix incl. nested/sibling/broad-parent CIDR and per-address revalidation timing, RBAC matrix, scheduler-worker lifecycle, API request-validation regressions, a real owned-loopback-TCP-listener end-to-end lab proof against real PostgreSQL proving authorize→observe→drift-on-stop→drift-on-restart→zero-drift-on-identical-rerun→revoke-reblocks, and a 20-way concurrent scheduler-claim proof converging on exactly one winner); clean migration 0001→0024→0023→0024 up/down/up proof against an isolated, destroyed-after-use database. **Continuation pass closed the prior P1**: `NetworkMonitoringSchedulerWorker` is now wired into `app.py`'s startup/shutdown lifecycle exactly like M14's scheduler (verified via a real `lifespan_context()` run: starts HEALTHY, stops with no orphaned task) — this also surfaced and fixed a real, unrelated pre-existing bug where `application/platform/startup_validator.py`'s expected-migration-head constant was stale at "0023" (never bumped for 0024), which silently prevented every background worker from starting against a real, correctly-migrated database. A real 35-step live HTTP API acceptance script (`backend/scripts/m16_live_api_acceptance.py`) now runs the actual FastAPI app with production DI wiring against real PostgreSQL — 35/35 PASS, including real M10 authorization approve-by-distinct-user, real invitation accept, and cross-tenant non-disclosure. A fresh, independent 16-category adversarial security review (separate from implementation-time review) found 14 categories clean and 2 genuine, now-fixed issues: a P1 (per-address authorization re-check ran outside the concurrency-bounding semaphore, risking thousands of concurrent DB sessions on a large plan) and a P2 (a malformed `target_asset_id` on policy creation 500'd instead of a controlled 404; also, an invalid `profile` string 500'd until typed as a Pydantic `Literal`) — both fixed with regression tests. Browser acceptance was attempted (real backend + real frontend dev server) and remains BLOCKED by the same pre-existing preview-environment limitation every prior milestone (M10-M15) documented (page hangs at "Loading…", zero console errors) — not M16-specific, not claimed as PASS. A full adversarial traceability matrix mapping all 95 named brief scenarios closed further gaps (condition reactivation, an execution-wide deadline, a run list/detail API, a lifecycle-filter 500, a stale migration-head bug) and, in a final dedicated pass, closed the last remaining scenario — **#51, mid-run execution cancellation**: a monotonic `cancellation_requested` flag (migration 0025), never touched by the generic `save()`'s UPDATE branch so a stale-aggregate save structurally cannot clobber a concurrently-persisted cancellation request (proven with two real concurrent PostgreSQL sessions); 4 cooperative orchestrator checkpoints; `_reconcile()` skipped entirely on cancellation (no false condition resolution/drift); `POST /api/v1/network-security/runs/{run_id}/cancel` (NETWORK_SECURITY_MANAGE, idempotent, 404 on malformed/unknown/cross-tenant). **A subsequent external audit caught a real arithmetic error** in the traceability summary table (PROVEN=93 + NOT APPLICABLE=6 ≠ 95) — traced to 3 rows carrying a hybrid Status annotation instead of one canonical value, not a hidden scenario; fixed and now mechanically guarded by `tests/unit/test_m16_traceability_matrix_integrity.py`, which parses the matrix doc directly and fails the build on any future duplicate/missing scenario number, invalid status, or summary-count mismatch. The same audit required proof beyond architecture description for scenario #51: a genuine RUNNING-state HTTP mid-flight cancellation (not cancel-before-execution or cancel-on-terminal), real restart durability across 3 independent simulated process restarts (3 separate `create_app()` instances against the same Postgres DB), and real scheduler-dispatched mid-flight cancellation (via the actual SKIP LOCKED claim path, not `run-now`) — all now proven. **Honestly declared COMPLETE**: mechanically-recounted 89/95 scenarios PROVEN, 6 NOT APPLICABLE (documented architectural reason), 0 remain NOT PROVEN, 89+6+0+0=95; zero known P0/P1; 141 M16-specific tests; live HTTP acceptance 50/50 PASS; full backend suite 4091 passed/5 skipped/0 failed (same one pre-existing unrelated-file deadlock excluded with evidence, plus one disclosed intermittent full-suite-only resource-cleanup timing flake in the restart-durability test — deterministic 5/5 in isolation); frontend 109 Vitest passed, tsc/build clean, audit unchanged (2 pre-existing, unrelated) | 4,091 |
| M15 | Security Operations Command Center — Unified Real-Time Execution Telemetry | Transforms the M1-M14 security engines into one tenant-safe, read-only operational command plane — deliberately owns no data (no second asset/condition/correlation/execution/drift truth) and mutates nothing; reconnaissance found the pre-existing Sprint 24/25 generic `platform_events` event-sourcing table has ZERO production writers anywhere in the codebase (only test files construct envelopes; the entire `EventPublisherPort`/`NullEventPublisher` mechanism used by organizations/memberships/targets is also a no-op sink) — rather than resurrect that untested-in-production subsystem via invasive edits deep inside the 1000+-line, 3900-test `execution_service.py` dispatch loop, M15 instead reads directly from the two ALREADY-comprehensive, production-proven durable logs (`validation_execution_events` from M11, `security_drift_events` from M14) plus two new small append-only tables it adds for the two genuine gaps found (`continuous_validation_policy_lifecycle_events` — M14's policy aggregate had no durable transition history at all; `runtime_component_health_transitions` — runtime health had zero persistence or transition memory), a documented, deliberate deviation from the textbook "wire into the generic event store" answer, justified by regression-risk management on a battle-tested core; the cross-domain "Operational Event" feed is a query-time merge across these four sources (`stream_service.py`'s `fetch_merged_candidates()`), never a single physical event table; a composite, lexicographically-sortable string cursor (`occurred_at_fixed_width_iso|source_tag|row_id`) IS the SSE wire-level `id:`/`Last-Event-ID` value directly — no separate numeric global position needed; a commit-visibility safety margin (`EVENT_VISIBILITY_LAG_SECONDS`, 2s default) only surfaces a row once it is older than `now - lag`, proven under a genuine out-of-order-commit race (an earlier-`occurred_at` event committing AFTER a later one) to never permanently skip an event, merely delaying its visibility briefly; two new closed enums (`SourceDomain`, `OperationalImportance`) and a deterministic, server-only projection registry (`projection_registry.py`) produce every title/summary from bounded, pre-extracted scalars only — never a raw exception, SQL string, or evidence blob, with a 240-character hard truncation backstop on `OperationalEvent` itself; two tiny, additive event-emission gaps closed in existing M11 code (`EXECUTION_STARTED` on the AUTHORIZED→RUNNING transition, `CANCELLATION_REQUESTED` on an operator's cancel call) using the exact same `_emit()` pattern already used 19 other times in that file — the lowest-risk possible edit to a critical file; SSE authentication deliberately does NOT add a stream-ticket endpoint or cookies — the frontend reads `text/event-stream` framing itself over a `fetch()` `ReadableStream` (`useSecurityOperationsStream.ts`), sending the exact same `Authorization: Bearer` header every other request already uses, since a native `EventSource` cannot set that header and no cookie infrastructure exists anywhere in this codebase; RBAC extends the existing `Permission` enum with `SECURITY_OPERATIONS_READ`, granted to all six tenant roles (mirroring `VALIDATIONS_READ`'s own universal distribution) via the same `require_permission`/`ROLE_PERMISSIONS` mechanism — the `OperatorPermission` name from stale prior-session task history does not exist in the repository and was not reintroduced; runtime health transitions are deliberately broadcast to every organization's feed (not tenant-scoped — runtime components are platform-wide infrastructure, not per-tenant data), the one documented exception to strict isolation; migration 0023 adds exactly the 3 small tables above plus a dedup-bookkeeping table for runtime-transition detection (`runtime_component_health_state`), using row-locked (`SELECT ... FOR UPDATE`) read-modify-write for exactly-once transition recording under concurrent instances, with `ON CONFLICT DO NOTHING` closing a same-primary-key race on a component's first-ever observation found during the independent adversarial review; new `RuntimeHealthTransitionWorker` background worker mirrors `DLQReplayWorker`'s/`ContinuousValidationSchedulerWorker`'s established lifecycle shape exactly, wired into `RuntimeContainer`/`app.py` in the same reverse-order startup/shutdown pattern; extended REST API — `api/v1/security_operations.py` (7 read-only routes: summary, changes, events, events/stream, executions, executions/{id}, runtime — every route structurally a GET, proven by asserting the router's own registered methods); a genuinely new Security Operations frontend page (live SSE feed, summary cards, active-executions list, security change feed, runtime components) plus a dedicated execution-telemetry-detail page with a backend-derived phase ladder (never a fabricated percentage) and a crisp, non-story-prose result summary; independent adversarial review found zero P0/P1 defects (tenant isolation, RBAC coverage, sanitization, backpressure, and migration safety all held under deliberate attack) but surfaced three genuine P2s, all fixed: a frontend dedup-Set memory leak (deleting by the wrong key, `event_id` instead of the actual `cursor` key used to insert), the first-sighting INSERT race on the new runtime-health dedup table (closed with `ON CONFLICT DO NOTHING`), and an unbounded `result_summary` string lacking the same defensive length cap `OperationalEvent` itself already has; owned local lab + PostgreSQL concurrency/ordering proof (7 dedicated integration tests: real execution/policy events visible through `poll()`, cursor resume with no duplicates, restart durability from a fresh service instance, cross-tenant isolation with the deliberate runtime-broadcast exception proven alongside it, concurrent runtime-transition dedup via genuine `asyncio.gather()`, and the out-of-order-commit-survives-under-the-visibility-lag race proven directly); clean migration proof (0001→0023 from an empty database, all 3 new tables + FK + indexes confirmed present, downgrade/re-upgrade reversibility proven) using the same `_assert_isolated_proof_database()` guard — caught and corrected a real near-miss during this proof where an initial `DATABASE_URL` env var (missing the app's actual `REDFORGE_` prefix) silently targeted the shared dev database instead of the isolated proof database for one forward-only, non-destructive upgrade step, transparently disclosed and never followed by any downgrade against it; live API acceptance against a REAL running uvicorn server (not `ASGITransport`, specifically so genuine SSE streaming/disconnect/reconnect semantics could be proven — `ASGITransport` was found during adversarial test-writing to never propagate a client disconnect to `Request.is_disconnected()` and to buffer entire streaming responses rather than truly stream them) with real dedicated PostgreSQL — 47/47 steps PASS, including real chunked-transfer SSE delivery, Last-Event-ID resume with no duplicates, malformed-cursor safety, cross-tenant non-disclosure, and a second server instance resuming from the durable cursor (not process memory) after a full restart; browser acceptance attempted but BLOCKED for the identical pre-existing environment reason M10-M14 documented — the preview browser's React tree never mounts past an initial "Loading…" placeholder despite every JS bundle loading 200 OK with zero console errors — corroborated by clean `tsc`, a clean production `next build`, and 106 passing Vitest tests (17 new) | 3,957 |
| M14 | Continuous Validation Scheduler, Security Drift Detection & Revalidation Engine | Evolves the one-shot M11-M13 validation flow into a continuous control plane — deliberately NO `ContinuousScanExecution` or any second execution aggregate, every actual validation run still goes through the SAME `ValidationExecutionService.create_and_run()` M10 fresh-authorization gate, unbypassed and uncached; new `domain/continuous_validation/` bounded context with `ContinuousValidationPolicy` (aggregate: create/activate/pause/resume/disable/is_due/advance_schedule/release_claim) governed by a closed `PolicyLifecycle` (DRAFT/ACTIVE/PAUSED/DISABLED) transition map, and a closed, server-owned `ValidationCadence` (HOURLY/EVERY_6_HOURS/DAILY/WEEKLY) — no arbitrary client-supplied cron expression anywhere; deliberately renamed away from the obvious `ValidationSchedule`/`ScheduleStatus`/`DriftEvent`/`DriftType` names to `ContinuousValidationPolicy`/`PolicyLifecycle`/`SecurityDriftEvent`/`SecurityDriftCategory` to avoid collision with the dead `application/scheduler.py` and the unrelated `domain/posture/` LLM-drift module found during reconnaissance; distributed due-policy claiming via the standard Postgres job-queue idiom — a single atomic `UPDATE ... WHERE id = (SELECT ... FOR UPDATE SKIP LOCKED) RETURNING *` — with a bounded 300-second claim lease, proven to yield exactly one execution under a genuine concurrent multi-worker race, not assumed; missed-run coalescing via mathematical floor-division schedule advancement (`intervals_missed = floor((now - next_due_at) / interval)`), never a catch-up loop; database-enforced idempotency via a partial unique index on `validation_executions(continuous_policy_id, scheduled_due_at) WHERE continuous_policy_id IS NOT NULL`, backing a genuine new `ExecutionTrigger` (MANUAL/SCHEDULED/ON_DEMAND) provenance field added directly to the existing M11 `ValidationExecution` aggregate (`trigger`/`continuous_policy_id`/`scheduled_due_at`) rather than a parallel entity; `ValidationStateSnapshot` — a normalized, sha256-fingerprinted comparison projection built fresh from each execution's own real evidence (`snapshot_builder.py`), giving an identical-fingerprint fast path that correctly reports zero drift on a genuine unchanged re-run; pure `detect_drift()` comparison against the previous snapshot backing a closed `SecurityDriftCategory` taxonomy (13 members; `CORRELATION_REACTIVATED` deliberately excluded as not yet representable) persisted append-only via `SecurityDriftEventRepository`; condition lifecycle reconciliation extends M8's deliberately narrow "explicit resolution only" design with the ONE sanctioned exception — absence-based resolution — gated by a `_CONDITION_RULE_COVERAGE` map so only a rule whose covering step(s) genuinely completed (and, for protocol steps, genuinely reached VALIDATED, never merely HINTED/INCONCLUSIVE) THIS run is eligible, refined further to be PORT-scoped (not just rule-scoped) for M13's multi-port protocol-validator-derived `PLAINTEXT_SENSITIVE_SERVICE_OBSERVED` rule via `compute_covered_ports_by_rule()`, closing a real cross-port false-resolution defect found during adversarial review (see below); `CONDITION_REACTIVATED` detected via `first_observed_at` vs. the previous snapshot's own `captured_at`, needing no peek-before-ingest; M9 correlation engine reused completely unchanged — no new correlation rule, no new Security Graph node/edge semantics, ontology stays at v5; a `ContinuousValidationSchedulerWorker` background worker mirroring the existing `DLQReplayWorker` lifecycle pattern exactly (bounded poll loop, start/stop, health probe), wired into `RuntimeContainer`/`app.py` startup and shutdown hooks in the established reverse-order pattern; migration 0022 (3 new tables — policies, state snapshots, drift events — plus 3 new columns and the partial unique index on `validation_executions`, no destructive schema change); extended REST API — `api/v1/continuous_validation.py` (10 routes: policy CRUD/lifecycle transitions, run-now, per-policy and per-organization drift listing, a tenant-scoped live change feed); a genuinely new Continuous Validation frontend page (policy list/detail, cadence and lifecycle badges, drift event timeline) added as its own nav entry, not folded into Validation Operations; adversarial multi-agent code review across all required dimensions found the implementation safe by construction for DDD hygiene, M10 authorization reuse, drift determinism, asset/correlation/graph handling, and tenancy/secrets isolation, but surfaced two genuine P0 defects and one P1, all fixed with dedicated from-scratch regression tests written to reproduce each bug before the fix: (P0-1) a TOCTOU lost-update where `_release_and_advance()` held a stale in-memory policy object across a long `create_and_run()` call and then unconditionally overwrote lifecycle/schedule fields on save, silently resurrecting a policy an operator had just disabled mid-run — fixed with a new row-locked `get_by_id_for_organization_for_update()` read-modify-write helper (`_mutate_under_lock()`) that re-checks the fresh DISABLED state before ever mutating; (P0-2) `compute_covered_rule_ids()` treated a multi-port protocol rule as globally covered if ANY of its 4 distinct port-specific validators succeeded ANYWHERE in the execution, meaning validating MySQL on port 3306 could incorrectly authorize resolving a stale, never-re-examined Redis-port condition — fixed with the new port-scoped coverage function above; (P1) any non-collision exception from `create_and_run()` was advancing the schedule exactly like a handled claim-collision, silently skipping a full cadence period on a transient DB/network error with zero audit trail — fixed by distinguishing `IntegrityError` (safe to advance) from any other exception (`_release_claim_only()`, same due boundary retried next poll, claim released without advancing); one P2 documented rather than fixed (`list_for_org(limit=500)` correlation lookup is org-wide with client-side filtering — correlations beyond the first 500 by creation order are invisible to a given policy's drift snapshot, a scale-only limitation); a pre-existing, unrelated bug pattern found via adversarial API testing — `EntityId.from_string()` raising a bare `ValueError` for a malformed ID falls through `ErrorHandlerMiddleware`'s `RedForgeError`-only mapping into an unhandled 500 instead of 404 — fixed locally in all 3 new M14 GET-by-id call sites (`_safe_entity_id()` helpers) and flagged via a spawned follow-up task for the same pre-existing pattern likely affecting M11-M13's own `EntityId.from_string()` call sites, rather than fixing those out-of-scope files in this milestone; owned local lab proof (STATE A baseline zero fabricated drift, STATE B mutation-appears-with-drift, STATE C reintroduction-reactivates-the-same-canonical-condition, identical-rerun zero-new-drift, real-socket port-reachability drift, revocation-before-dispatch zero-network-calls, concurrent-scheduler-claim exactly-one-execution, restart-preserves-policy-and-drift-state, repository-level claim-atomicity, plus the two P0 regression tests) — 11 dedicated integration tests, including a real local PostgreSQL server used as the deliberately SSL-capable second port in the port-scoping regression test after discovering `RedisPingValidator` structurally never sets an SSL-capability flag at all; clean migration proof (0001→0022 from an empty database, 3 new tables + 3 new columns + the partial unique index confirmed present, downgrade/re-upgrade reversibility proven) using the same `_assert_isolated_proof_database()` guard; live API acceptance against a running server with real, dedicated PostgreSQL, rewritten as a single `async def main()` using `httpx.AsyncClient`/`ASGITransport` with manual `app.router.lifespan_context()` management (replacing an initial `TestClient`-plus-`asyncio.run()` mismatch that crashed on a dual-event-loop conflict) — 41/41 steps PASS, including full M10 authorization setup (distinct-approver-approves, self-approval-forbidden), a real SSRF-loopback-boundary monkeypatch matching established M11-M13 proof-script precedent, and policy create→activate→run-now→drift-on-mutation→pause→disable→cross-tenant-isolation all correct; browser acceptance attempted but BLOCKED for the identical pre-existing environment reason M10-M13 documented — the preview browser's React tree never mounts past an initial "Loading…" placeholder despite every JS bundle loading 200 OK with zero console errors — corroborated by clean `tsc`, a clean production `next build`, and 89 passing Vitest tests (14 new) | 3,913 |
| M13 | Protocol-Aware Service Validation & Enterprise Attack Surface Deepening | Reconnaissance-first extension of M12's own `domain/validation_execution/` bounded context and canonical `AIAsset` SERVICE model — deliberately NO second scanner framework, service inventory, or vulnerability table; the core architectural correction is PORT REACHABILITY MUST NOT BE TREATED AS SERVICE IDENTITY, closing M12's own documented gap (only 4 of 8 discovery-policy ports had a real validator); a closed, versioned `ProtocolValidatorRegistry` (`application/validation_execution/protocol_validators.py`) mirroring `AdaptiveRuleRegistry`'s own collision discipline exactly — validators register by `(validator_id, validator_version)`, duplicates rejected, no client-facing way to name/select/import a validator, no dynamic import, no subprocess, no shell command anywhere; 4 new bounded, non-authenticating, non-mutating protocol validators, each wrapping exactly one real network primitive in the new `protocol_adapters.py` (bounded-connect + bounded-read, never unbounded, every read capped by both an explicit byte limit and a timeout): SSH (passive banner read only, RFC 4253 identification-string shape, never sends a byte), MySQL (passive read of the server's own initial handshake greeting only, parses protocol_version/server_version/CLIENT_SSL capability flag, never authenticates), PostgreSQL (sends only the documented, standard 8-byte SSLRequest message — real production client-driver behavior, not a probe invented for this milestone — reads the single 'S'/'N' response byte, never a StartupMessage/credential), Redis (sends only `PING`, Redis's own documented liveness command, accepts either `+PONG` or a RESP-shaped error reply as valid protocol identity — recognizing the wire protocol, never bypassing auth); RDP (3389) explicitly, honestly DEFERRED — safely validating RDP without touching NLA/credential negotiation could not be proven with a bounded, non-authenticating probe this milestone, and it stays SERVICE_HINTED forever, a documented deferral not an oversight; a new `ProtocolValidationState` StrEnum (NOT_ATTEMPTED/UNREACHABLE/INCONCLUSIVE/HINTED/VALIDATED/ERROR) — deliberately a NEW enum distinct from M12's own `ServiceEvidenceState` (the asset/event-level truth ladder, reused unchanged), analogous to how `DiscoveryPortOutcome` already sits alongside `ServiceEvidenceState` for the exact same reason: a per-attempt outcome is different information from an asset-level evidence position; discovery port policy bumped 1→2 (adds port 6379/redis; RDP/3389 stays hint-only) and M6's `SENSITIVE_PORTS` extended with `redis` (an unauthenticated-by-default data store, the same judgment already applied to mysql/postgresql/rdp); `max_adaptive_steps` raised from 6 to 8 (sized to exactly the 7 adaptive steps a fully-multi-protocol-reachable target can genuinely produce today, plus one unit of headroom — never an arbitrary increase); 4 new protocol-candidate adaptive rules, each owning exactly one fixed port and one distinct `rule_id` (sidestepping `append_adaptive_step()`'s `(step_type, adaptive_rule_id)` dedup-key constraint discovered during reconnaissance); genuine new `ValidationStep` provenance fields — `validator_id`/`validator_version`/`protocol_validation_state` — set at complete()/fail() time (what happened when the step ran) rather than creation time (why it was scheduled, `adaptive_rule_id`'s own job), justifying migration 0021; canonical SERVICE asset protocol enrichment via a genuinely new `TenantAssetService.update_metadata_for_org()` write path (M12 could only set metadata at asset CREATION time; M13 adds the missing write path for enriching an asset that already exists) — idempotent by construction (repeat/concurrent runs converge, proven under a REAL concurrent race in the PostgreSQL proof, not just sequential re-runs), version strings/banners/certificate subjects never become part of canonical identity (already true by construction in `domain/inventory/identity.py`'s own `normalize_service_endpoint()`); 3 new deterministic SecurityCondition rules derived entirely from evidence M11's own TLS_HANDSHAKE step already captures — no new adapter required — `TLS_CERTIFICATE_EXPIRED`, `TLS_SELF_SIGNED_CERTIFICATE_OBSERVED` (subject/issuer common-name equality), `DEPRECATED_TLS_PROTOCOL_OBSERVED` (SSLv2/SSLv3/TLSv1/TLSv1.1) — plus one new protocol-validator-derived condition, `PLAINTEXT_SENSITIVE_SERVICE_OBSERVED`, fired only when the MySQL/PostgreSQL validators' own real capability-flag/SSLRequest evidence deterministically proves no TLS/SSL support, never inferred from a version string; zero CVE inference, zero vulnerability claim from bare reachability or a version banner anywhere; M9 correlation reuse required NO new rule — `MultipleSecurityConditionsOnAssetRule` (M9, source-category-agnostic) already naturally covers 2+ M13 conditions on one asset, proven rather than assumed; Security Graph ontology reviewed and confirmed sufficient at v5 — no bump, SERVICE nodes are enriched via metadata only, no new node/edge semantics; extended (not duplicated) REST API — `StepResponse` gains `validator_id`/`validator_version`/`protocol_validation_state`, `ResultResponse`'s `validated_services` entries gain validator provenance (structurally read from the new step fields, not string-parsed — deliberately avoiding the brittle evidence-label-parsing pattern M12's own API layer already carries); extended Validation Operations frontend (a REACHABLE→HINTED→VALIDATED badge ladder per protocol step, validator id/version shown for every protocol-validated step, no vulnerability badge for bare reachability, no raw evidence blobs); 43 new adversarial backend tests (24 unit — registry determinism/duplicate-rejection, each validator against real owned local TCP fixtures including bounded-read/amplification-defense proofs — + 5 API-isolation — client-supplied validator/step-type fields structurally ignored, the second fresh-policy-dispatch boundary proven again for a protocol step, hinted-vs-validated truth, no exception/traceback leakage — + 14 dedicated real-PostgreSQL/owned-local-multi-protocol-lab proof tests, including the required CONCURRENT-execution canonical-identity-convergence proof run as a genuine `asyncio.gather()` race, not a sequential re-run) plus 5 new frontend Vitest tests; SSH's full discovery-pipeline dispatch is an honestly disclosed, environment-forced exception — binding port 22 requires root privileges this proof suite neither has nor should be granted — proven instead directly against real valid/invalid banner servers on ephemeral ports, bypassing only the fixed-port constraint, never the validator logic itself; clean migration proof (0001→0021 from an empty database, 3 new columns confirmed present, downgrade/re-upgrade reversibility proven, no M14 schema) using the same `_assert_isolated_proof_database()` guard M12 introduced; live API acceptance against a running server with real, dedicated PostgreSQL (28/28 steps PASS, including new checks that client-supplied `validator_id`/`validators` fields are structurally ignored and that every M13 step field round-trips correctly through a real process restart); browser acceptance attempted but BLOCKED for the identical pre-existing environment reason M10/M11/M12 documented — the preview browser's React tree never mounts past an initial "Loading…" placeholder, despite every JS bundle loading 200 OK with zero console errors — corroborated by clean `tsc`, a clean production `next build`, and 75 passing Vitest tests (5 new) | 3,850 |
| M12 | Authorized Network Discovery & Adaptive Validation Orchestration | Reconnaissance-first extension of M11's own `domain/validation_execution/` bounded context — deliberately NO second AIAsset/inventory/scanner/execution-aggregate/condition-model/correlation-engine/graph; the `ValidationExecution` aggregate itself learns to grow its own plan mid-run: a new `NETWORK_DISCOVERY_BASELINE_V1` profile alongside the preserved `SAFE_ACTIVE_BASELINE_V1`, whose initial plan is deliberately minimal (DNS resolution + bounded `PORT_DISCOVERY` only) with every other step appended ADAPTIVELY afterward; a small, explicit, versioned discovery port policy (`DISCOVERY_PORT_POLICY_V1` — 8 named ports, never 1-65535, never a client-supplied port list) built on M11's own `check_tcp_connectivity()` (M6's `BoundedNetworkScanAdapter` deliberately NOT reused — different product surface, no M10/M11 authorization boundary) with a closed `DiscoveryPortOutcome` ladder (REACHABLE/UNREACHABLE/TIMEOUT/NETWORK_ERROR/POLICY_BLOCKED) — port number alone is only ever an `EXPECTED_SERVICE_HINT`, never `SERVICE_VALIDATED`; M6's private `_SENSITIVE_PORTS` made public (`SENSITIVE_PORTS`) and imported directly rather than duplicating port truth; canonical asset/service enrichment reusing M6's own `TenantAssetService.resolve_asset()`/`add_relationship_for_org()` unchanged (race-safe get-or-create, deterministic dedup, cross-tenant separation) plus one new `AssetRelationshipType.TARGET_RESOLVES_TO_IP` mapped to the pre-existing `EdgeKind.CUSTOM` escape hatch — Security Graph ontology stays at v5, no bump; a deterministic, versioned, closed adaptive rule registry (`AdaptiveRuleRegistry`, mirroring M9's own `CorrelationRuleRegistry` collision discipline exactly — register by `(rule_id, rule_version)`, reject duplicates) with the milestone's minimum rule set (`PORT_443_TLS_HTTPS`→TLS_HANDSHAKE+HTTP_METADATA+HTTP_SECURITY_HEADERS, `PORT_80_HTTP`→HTTP_METADATA+HTTP_SECURITY_HEADERS, unknown port→no probe) that is genuinely duplicate-resistant (when both rules would propose the same shared step type, only the first-registered rule's steps are appended — the second rule still "matches" but contributes zero net-new steps, proven both in a dedicated unit test and against real dispatch in the PostgreSQL proof); new `StepSource` (INITIAL/ADAPTIVE) and adaptive provenance (`adaptive_rule_id`/`adaptive_rule_version`/`source_fact_ref`) as genuine new `ValidationStep` domain fields, not evidence-blob-encoded, justifying migration 0020; a SECOND, canonical, single fresh-policy-dispatch boundary specifically for ADAPTIVELY-scheduled steps (distinct from M11's own double-gate for the INITIAL plan) — checked once per adaptive step inside the existing dispatch loop, proven with the exact required adversarial scenario: discovery fact observed → authorization revoked → adaptive rule matches → the adaptive step's network adapter receives ZERO calls, its status/error_category recorded as `policy_denied` with empty evidence; explicit `ServiceEvidenceState` ladder (PORT_REACHABLE→SERVICE_HINTED→SERVICE_VALIDATED) — a reachable-but-unrecognized port (e.g. 3306/mysql, no validator exists this milestone) stays HINTED forever, proven never to reach VALIDATED; M6's exact `SENSITIVE_SERVICE_OBSERVED`/`source_category="network_discovery"` condition shape reused byte-for-byte (only a private-to-public rename of `_SENSITIVE_PORTS`) so M9's pre-existing `PublicSensitiveServiceContextRule` fires with zero M9 code changes; M9's `TenantSecurityCorrelationService.evaluate()` given its first-ever automatic caller (previously manual-only via `POST /security-correlations/evaluate`) as a bounded, best-effort post-processing step — a correlation-evaluation failure is logged via a real `CORRELATION_EVALUATED` event carrying the error type and never corrupts or blocks the execution's own truth; index-based (not list-snapshot) step-execution loop so `ValidationExecution.steps` can grow mid-run, plus `dataclasses.replace()`-based per-step "effective target" resolution (parsing `source_fact_ref` to override port/scheme for adaptively-dispatched TLS/HTTP steps without touching the target's own original endpoint); 7 new canonical execution events (`DISCOVERY_STARTED`, `PORT_REACHABILITY_OBSERVED`, `ADAPTIVE_RULE_MATCHED`, `STEP_ADDED_TO_PLAN`, `ASSET_RESOLVED`, `SERVICE_CONTEXT_UPDATED`, `CORRELATION_EVALUATED`); migration 0020 (4 new nullable/defaulted columns on `validation_execution_steps` only — `source`/`adaptive_rule_id`/`adaptive_rule_version`/`source_fact_ref` — no credential/token/cookie/command/raw-scanner-output schema anywhere); extended (not duplicated) REST API — `ExecutionResponse` gains `plan_summary` (initial/adaptive step counts, discovered-address/reachable-port/validated-service/condition counts), `StepResponse` gains the 4 provenance fields, `ResultResponse` gains `discovered_addresses`/`reachable_ports`/`validated_services`/`correlations_created`/`updated`/`resolved`; a genuine bug found during live API acceptance and fixed: `ValidationProfile(profile)` raised a bare `ValueError` for an unrecognized client-supplied profile string, which fell through the global error handler's `RedForgeError`-only mapping into an unhandled 500 — fixed by wrapping it in the existing `ValidationError` (422) exactly as every other input-validation path in the codebase already does; extended Validation Operations frontend (profile `<select>` now offering both closed profiles, per-step INITIAL/ADAPTIVE provenance badges with rule id/version/fact-ref shown for adaptive steps, a plan-summary chip row, and a per-service HINTED-vs-VALIDATED panel in the crisp result — no exploit/compromise language anywhere); 52 adversarial backend tests (20 unit + 23 API-isolation + 9 dedicated real-PostgreSQL/owned-local-network-lab proof tests — genuine self-signed-cert TLS handshake and HTTP fetch against module-scoped HTTP/HTTPS/bare-TCP-listener fixtures, a real hint-only MySQL-shaped listener with no validator, real M9 correlation firing); clean migration proof (0001→0020 from an empty database, 4 new columns + composite tenant FK confirmed present, downgrade/re-upgrade reversibility proven, no M13 schema) plus the required new safety guard (`_assert_isolated_proof_database()` — prints and asserts the target database name before every destructive proof command, added specifically because a prior M11 session's downgrade proof briefly touched the shared dev database); live API acceptance against a running server with real, dedicated PostgreSQL (32/32 steps PASS: register→create org→select→register distinct approver via direct membership seed, bypassing the invite/accept email flow, matching established test convention→register AI target→M10 authorization create→submit→self-approval-denied→distinct-approver-approves→ACTIVE→SAFE_ACTIVE and NETWORK_DISCOVERY executions both correctly, truthfully FAILED via the same unpatched production network-boundary denial→plan_summary/provenance/event-trail all correct→repeat stable→arbitrary client profile cleanly rejected (422, the bug above caught here)→already-terminal cancel truthfully rejected (422)→revoke→immediate DENY with zero steps→cross-tenant 404 and empty-list isolation→unauthenticated 401→no bearer-token/secret leak→process restart→execution/step/plan_summary/event history confirmed persisted, all PASS); browser acceptance attempted but BLOCKED for the identical pre-existing environment reason M10/M11 documented — the preview browser's React tree never mounts past an initial "Loading…" placeholder on the extended `/validation-operations` page, despite every JS bundle loading 200 OK with zero console errors — corroborated by clean `tsc`, a clean production `next build`, and 70 passing Vitest tests (5 new) | 3,807 |
| M11 | Gated Safe Active Validation Orchestration | New `domain/validation_execution/` bounded context — the first milestone to perform REAL (not simulated) active network validation, entirely behind M10's `ExecutionPolicyService` boundary: canonical `ValidationExecution` aggregate (`ValidationStep` child entities, standalone append-only `ExecutionEvent` log deliberately NOT part of the aggregate's buffered-event pattern since it exists for genuine live-progress polling) with lifecycle PENDING→POLICY_CHECKING→AUTHORIZED→RUNNING→{COMPLETED,PARTIALLY_COMPLETED,FAILED}, or DENIED/CANCELLED, `finish()` computing the terminal status from real step outcomes only (never assumed); mandatory M10 policy gate evaluated **twice** per execution — once at creation, once immediately before step dispatch, closing the "ALLOW-then-revoked-before-dispatch" race, proven with a fake `ExecutionPolicyPort` returning ALLOW then DENY across the two calls within one `create_and_run()` invocation; a single closed, server-controlled `SAFE_ACTIVE_BASELINE_V1` profile with 6 bounded step types (DNS resolution, TCP connectivity, TLS handshake, HTTP metadata, HTTP security headers, service reachability) — the server builds the entire plan from the canonical target's own endpoint, no client-submitted steps/ports/commands/modules anywhere; real network-boundary/SSRF defense (`classify_address()` denies loopback/link-local/private/multicast/reserved/metadata categorically, fail-closed for unparseable input) applied identically to the initial DNS resolution and to every redirect hop's re-resolution, plus a DNS-rebinding/foreign-target defense (a redirect is only followed if its resolved addresses intersect the ORIGINAL target's own validated resolution set, regardless of whether the redirect's addresses are individually public); real adapters — genuine `asyncio.open_connection()` TCP connects, a real TLS handshake via `ssl.create_default_context()` extracting protocol version/cipher/cert CN/validity/SAN count/SHA-256 fingerprint, `httpx` HTTP fetch with manual (never automatic) redirect following so every hop is independently boundary-checked, and a pure deterministic security-header rule evaluator (3 stable rules: missing HSTS/CSP/X-Content-Type-Options) that never fabricates a Finding from bare connectivity (TCP-open and HTTP-200 alone produce zero findings); explicit `ServiceReachabilityResult` distinguishing PORT CONNECTIVITY OBSERVED from SERVICE REACHABILITY VALIDATED; Authorization/Cookie/Set-Cookie/bearer-token headers redacted before persistence, API response, or event payload; `SourceCategory.ACTIVE_VALIDATION` added as M11's real producing path into the existing M8 `SecurityCondition` pipeline (reused unchanged — no parallel condition/finding model); migration 0019 (`validation_executions`, `validation_execution_steps`, `validation_execution_events` — composite tenant FKs on all child tables, `(id, organization_id)` unique constraint, step-order and event-sequence uniqueness); 7 tenant-scoped REST endpoints (create/list/summary/get/steps/events/cancel/result — no arbitrary-execution endpoint anywhere, no direct adapter import in the router); Validation Operations frontend (backend-derived lifecycle counts, canonical-target-only start form with the single fixed profile displayed read-only, filterable execution list, live-polling detail view with step/event timeline and a crisp structured result panel — never AI filler or fabricated exploit claims, unrecognized enums render UNKNOWN); 51 adversarial backend tests (18 network-boundary/SSRF/redirect/DNS-rebinding unit tests + 33 API-level tenant-isolation/policy-gate/cancellation/condition-semantics tests, 3 of which exercise the REAL M10 `SecurityAuthorizationService`+`ExecutionPolicyService` end-to-end rather than a fake port) plus a dedicated 7-test real-PostgreSQL suite (genuine self-signed-certificate TLS handshake, condition dedup, event ordering, policy-revocation-blocks-dispatch, restart persistence); a genuine concurrency bug found via the real-PostgreSQL proof and fixed: `create_and_run()` holds one in-memory aggregate for its whole lifecycle and every intermediate `_save()` was overwriting `cancellation_requested` back to its stale in-memory `False`, silently clobbering a concurrently-issued cancel request — fixed by making the flag monotonic (OR, never overwrite) at the repository layer; clean migration proof (0001→0019, composite FKs and all indexes confirmed present, downgrade/re-upgrade reversibility proven, no M12 schema); live API acceptance against a running server with real PostgreSQL and a genuine `AITarget` scope entity pointing at an owned local test service (create→real ALLOW via the actual M10 authorization workflow→plan built→real DNS resolution correctly denying the owned target's own loopback address per the network boundary→crisp truthful FAILED result with zero fabricated findings→repeat execution stable→revoke authorization→immediate DENY with zero new steps→process restart→persistence confirmed→second-tenant 404 and empty-list isolation→sentinel-secret absence, all verified); browser acceptance attempted but BLOCKED for the same pre-existing environment reason M10 documented — the preview browser never attaches a React effect/event-handler tree on any page in this app, reproduced identically on the untouched `/authorization` page — corroborated by clean `tsc`, a clean production `next build`, and 65 passing Vitest tests (11 new) | 3,755 |
| M10 | Authorized PT Scope & Execution Policy Control Plane | New `domain/authorization/` bounded context (previously an empty placeholder reserved since M8) — canonical `SecurityAuthorization` aggregate with a fixed lifecycle graph (DRAFT→PENDING_APPROVAL→ACTIVE→REVOKED/EXPIRED, or PENDING_APPROVAL→REJECTED; every other transition raises `InvalidAuthorizationTransitionError`; REJECTED/EXPIRED are terminal, reapproval always creates a new DRAFT rather than mutating history); separate `AuthorizationApproval` entity (one immutable-once-decided record per authorization, mirroring how `Invitation`/`Membership` are cross-referenced-not-nested aggregates); closed 8-value `ActionClass` taxonomy with 3 unconditionally-denied classes (`EXPLOIT_EXECUTION`/`POST_EXPLOITATION`/`DESTRUCTIVE_ACTION` — rejected even at authorization-creation time, since M10 builds no execution capability for them at all) and 5 authorizable classes; `ExecutionPolicyService.evaluate()` — the single canonical ALLOW/DENY/APPROVAL_REQUIRED decision point, entirely deterministic Python control flow (no LLM, no rule expressions), with precedence that distinguishes `AUTHORIZATION_NOT_FOUND` (zero authorizations for the org) / `ENTITY_NOT_IN_SCOPE` (authorizations exist but none cover these entities) / `ACTION_NOT_IN_SCOPE` (an authorization covers the entities but not this action class) — a design correction made after the adversarial suite's out-of-scope-entity and out-of-scope-action tests initially both collapsed onto the same reason code; canonical scope is `AuthorizationScopeEntry(entity_type, entity_id)` restricted to `ai_target`/`ai_asset` (the only two entity types with real canonical tenant-owned identity), verified through a single `EntityOwnershipPort` used identically at authorization-creation time and at every `evaluate()` call (`TenantEntityOwnershipChecker` in production, backed by the existing `AITargetService`/`TenantAssetService` — no display-name or substring matching anywhere); self-approval forbidden unconditionally at the aggregate itself (`SecurityAuthorization.approve()`/`.reject()`, `AuthorizationApproval.decide()`), independent of role — proven against the org's own OWNER, not just an ordinary member, to rule out any identity-based bypass; extended the *existing* tenant `Permission` enum (`AUTHORIZATIONS_READ/CREATE/APPROVE/APPROVE_CREDENTIAL/EVALUATE`) rather than inventing a second RBAC universe, honoring `domain/identity/value_objects.py`'s explicit "no second, competing authorization mechanism" invariant; migration 0018 (`security_authorizations`, `security_authorization_scope`, `security_authorization_approvals` — composite-FK tenant integrity on all three — and `security_authorization_decisions`, deliberately FK-less since a decision auditing `AUTHORIZATION_NOT_FOUND` has no authorization row to reference and must never be blocked from being written); concurrent-approval race fixed with `SELECT ... FOR UPDATE` locked reads on both the authorization and approval rows (proven against real PostgreSQL: two simultaneous `approve()` calls produce exactly one ACTIVE authorization and one approval row, the loser raising `InvalidAuthorizationTransitionError`/`ApprovalAlreadyDecidedError`, never a silent overwrite); execution-bypass review — `CampaignEngine.execute_campaign()`/`.trigger()` is the only real active-execution dispatch path in the platform (`api/v1/execution_plans.py` is a pre-existing inert stub, now explicitly documented as reviewed-and-inert rather than silently ignored); `ExecutionPolicyPort` added as a **required** (no-default) `CampaignEngine` constructor parameter specifically so no caller can construct a working engine without wiring a real policy decision, with a regression test proving the omission is a `TypeError`; 9 REST endpoints (`create/list/get/submit/approve/reject/revoke/evaluate/decisions` + a backend-derived `summary` counts endpoint added after the fact once the frontend's "no fabricated trends" requirement made a client-side-computed overview unacceptable); Authorization & Execution Policy frontend (overview counts, filterable list, create form restricted to the 5 authorizable action classes, detail view with approval history and per-authorization decision history, lifecycle-gated action buttons, self-approval hint); 33 backend adversarial tests (32-item checklist + 1 summary test) plus 2 dedicated real-PostgreSQL concurrency tests; real-PostgreSQL proof and clean migration proof (0001→0018, composite FKs and all planned indexes confirmed present, no M11 schema); live API acceptance against a running server with real PostgreSQL and a genuine `AITarget` scope entity (28/28 steps PASS: create→submit→self-approval-denied→distinct-approver-approves→ALLOW→out-of-scope entity/action DENY→revoke→immediate DENY→restart→persistence confirmed→cross-tenant 404→sentinel-secret absence, all verified); browser acceptance attempted but BLOCKED — the preview browser environment never attaches a React fiber/event-handler tree to any element on any page in this app (confirmed via `__reactContainer`/`__reactProps` inspection across fresh tabs and reloads, including the pre-existing, untouched `/login` page), an environment limitation rather than an application defect, corroborated by clean `tsc`, a clean production `next build`, and 54 passing Vitest component tests (13 of them new) that exercise the same click handlers via jsdom + Testing Library | 3,697 |
| M9 | Exposure Correlation & Attack Surface Intelligence | New `domain/security_correlation/` bounded context — canonical `SecurityCorrelation`, a deterministic relationship between already-canonical facts/conditions/entities, distinct from `SecurityCondition` (single-asset condition truth), `Finding` (validated truth), and `RiskIncident` (unrelated risk workflow); `ExternalExposureClassification` (NONE_OBSERVED/PUBLIC_ADDRESS_OBSERVED/PUBLIC_ENDPOINT_CONFIGURED/BROAD_INGRESS_CONFIGURED/EXTERNALLY_REACHABLE_VALIDATED) with explicit precedence (never alphabetical) — the last two levels are never emitted since no security-group/ingress or reachability-validation producer exists yet; deterministic correlation identity (`organization + stable_rule_id + rule_version + sorted canonical entity IDs`, never title/summary/operator_action); migration 0017 (`security_correlations` + 2 normalized association tables — `security_correlation_conditions`/`security_correlation_entities` — chosen over JSON blobs since source condition/entity IDs are first-class canonical references needing tenant-safe FK integrity); versioned server-controlled rule registry (`CorrelationRuleRegistry`, rejects duplicate rule ID+version) with 2 real implemented rules against genuinely-existing canonical facts — `PUBLIC_SENSITIVE_SERVICE_CONTEXT` (public IP → `IP_ASSIGNED_TO_HOST` → host → `HOST_EXPOSES_SERVICE` → M6's `SENSITIVE_SERVICE_OBSERVED` condition) and `MULTIPLE_SECURITY_CONDITIONS_ON_ASSET` (2+ ACTIVE conditions on one asset, any source categories); 3 rules from the milestone's own conceptual list were reconnaissance-deferred with documented reasons rather than fabricated: `BROAD_REMOTE_ADMIN_EXPOSURE_CONTEXT` (no security-group/ingress-rule data exists anywhere — cloud "public" is a string-parsed boolean only), `MULTI_SOURCE_CORROBORATED_CONDITION` (no structured cross-source "same concern" key exists beyond `stable_rule_id`), `PRIVILEGED_IDENTITY_EXPOSURE_CONTEXT` (no identity-to-resource access relationship is modeled anywhere); evaluation-cycle safety contract — resolution of stale correlations runs only after a rule's fact-gathering and every match's persistence succeeded, so a partial/failed cycle never resolves a correlation; a real P0 was caught during live acceptance and fixed: the evaluation summary's `resolved` count was overwritten per-rule instead of summed across the registry, silently under-reporting resolutions when an earlier-registered rule did the resolving; backend-computed Attack Surface read model (`TenantAttackSurfaceService` — org summary + per-asset exposure summary, explicit severity precedence, no magic 0-100 score); Security Graph reuse decision — no correlation node/edge added, ontology stays at v5, correlations reference the existing graph via canonical entity IDs only; 6 new read-only + 1 evaluate-only API endpoints (`/security-correlations`, `/summary`... `/attack-surface/summary`, `/attack-surface/assets/{id}`); Attack Surface frontend (overview, filterable correlation list, correlation detail with linked asset-exposure panel, explicit "Exposure Relationship Path" labeling, never "Attack Path"); real-PostgreSQL concurrency proof (concurrent evaluation → 1 correlation; cross-tenant separation; title/summary/operator_action updates never duplicate; resolve → re-observe → reactivation); clean migration proof (0001→0017 from an empty database, M10 schema confirmed absent); live API acceptance against a running server with real PostgreSQL (the resolved-count P0 caught and fixed live, then re-verified end-to-end: evaluate → list/detail → resolve source condition → re-evaluate → RESOLVED → re-observe → re-evaluate → same correlation ACTIVE → restart → persistence confirmed → cross-tenant denial confirmed, all PASS) | 3,658 |
| M8 | Vulnerability & Exposure Management Foundation | New `domain/security_conditions/` bounded context — canonical `SecurityCondition`, deliberately distinct from both raw exposure observations (M6/M7's ephemeral `analyze()` output) and validated `Finding` (never weakened/merged); OBSERVED/INFERRED/VALIDATED evidence-state model (no producing path sets VALIDATED — no API accepts it either); deterministic dedup identity (`organization + affected_asset + source_category + stable_rule_id + qualifier`, never title/summary/remediation); migration 0016 (`security_conditions` + `ux_ai_assets_id_org` composite-FK retrofit onto M3's `ai_assets`) — a principal review during M8 completion found the same revision had prematurely scaffolded M9's `security_correlations` and M10's `security_authorizations*` tables ahead of those milestones' actual implementation; removed as unreviewed speculative schema (no code referenced them) rather than left in place, and the local dev DB was downgraded/re-upgraded to the corrected revision; race-safe upsert repository (mirrors M3/M6/M7's asset-resolution pattern) with reactivation semantics (resolving then re-observing a condition reactivates the same canonical row, never a duplicate); evidence sanitizer bounded to 5 items/500 chars with explicit truncation flags — a principal-review pass found the original sanitizer only bounded size and did not redact secret-shaped values, a real P0 fixed by adding pattern-based redaction (AWS keys, bearer tokens, private key blocks, etc.) as defense-in-depth; M6 network and M7 cloud analyzers wired to route eligible deterministic rules (`SENSITIVE_SERVICE_OBSERVED`/`MULTIPLE_REMOTE_ADMIN_SERVICES`, `PUBLIC_STORAGE_CONFIGURATION`/`PUBLIC_COMPUTE_ENDPOINT`) through the canonical ingestion port with backend-derived severity (no CVSS — no producing rule has a real vector, documented as a deliberate scope decision rather than a fabricated partial implementation); Security Graph ontology v5 (`SECURITY_CONDITION` node, `HAS_SECURITY_CONDITION` edge — M10 control-plane objects deliberately excluded from the graph); `SecurityGraphProjector.project_security_condition()` (idempotent, no raw evidence/secrets in attributes); read-only API (`/security-conditions`, `/summary` backend-aggregated counts, `/{id}`, `/{id}/resolve` — no endpoint accepts a `SecurityConditionInput`-shaped body); Exposure Management frontend (overview counts, filterable list, detail panel with Resolve action, unknown-enum-safe rendering); found and fixed a stale startup-migration-head validator (`_EXPECTED_MIGRATION_HEAD` still read `"0015"`, which would have failed every real startup against the new head) — caught by running the actual app against real PostgreSQL, not just tests; real-PostgreSQL concurrency proof (concurrent duplicate ingestion → 1 condition; same rule on 2 assets → 2 conditions; title/summary/remediation updates never duplicate; resolve → re-observe → reactivation); dedicated adversarial suite (tenant isolation, non-disclosing 404s, secret-sentinel absence in API/graph, evidence truncation, browser-cannot-declare-VALIDATED/forge-severity); live API acceptance against a running server with real PostgreSQL (register → org → connector-driven and direct-ingestion M6/M7 conditions → list/detail/resolve/reactivate → cross-tenant denial → restart-persistence, all PASS); clean migration proof (0001→0016 from an empty database, schema/constraint/index inspection, speculative-table absence confirmed) | 3,621 |
| M7 | Multi-Cloud Security Foundation | Reused the canonical `AIAsset` aggregate for `CLOUD_ACCOUNT` (joining M3's `CLOUD_RESOURCE`) — no disconnected cloud inventory, no new migration needed; provider-aware deterministic identity scheme (`CLOUD_ACCOUNT_ID` — `"{provider}:{account_id}"`, restricted to an explicit `{aws,azure,gcp}` set, proven the same account ID under different providers never collides); real read-only AWS adapter (`boto3`/`botocore` — STS account identity, paginated EC2 compute, S3 storage with authoritative ACL-grant-derived public-flag classification, never a name/tag heuristic) — contract-proven via `botocore.stub.Stubber` (a real SDK testing feature), which caught and fixed a genuine bug (EC2 `OwnerId` read from the wrong response object) before any live interaction; Azure/GCP honestly declared NOT IMPLEMENTED (architecture-only, no empty adapter classes); reused M2/M5/M6's credential-reference-only boundary (no raw AWS secret ever accepted/returned); Security Graph ontology v4 (`CLOUD_ACCOUNT` node kind, `CONTAINS` edge kind — `CAN_ACCESS` deliberately not added, no authoritative source proves it); deterministic cloud exposure analysis (`PUBLIC_STORAGE_CONFIGURATION`, `PUBLIC_COMPUTE_ENDPOINT` — exposure context, never compromise/CVE claims); reused the generic `/assets` API/frontend for cloud browsing; 1 new API (`/cloud-security/observations`); real-PostgreSQL concurrency proof; full live acceptance with AWS live discovery honestly BLOCKED (no credentials in this environment) | 3,585 |
| M6 | Network, Device & Service Discovery Foundation | Reused the canonical `AIAsset` aggregate for NETWORK/DEVICE/SERVICE (joining M3's HOST/IP_ADDRESS) — no disconnected network inventory, no new migration needed (new `asset_type` string values in the existing 0013 schema); 3 new deterministic identity schemes (`NETWORK_CIDR` — host-bit masking so `10.0.0.1/24`≡`10.0.0.0/24`; `DISCOVERY_HOST` — connector-scoped, never hostname-alone; `SERVICE_ENDPOINT` — host+protocol+port, never a service banner); generalized `TenantAssetService.resolve_asset()`/`add_relationship_for_org()` (race-safe, idempotent, beyond M3's target-only scope); `BoundedNetworkScanAdapter` — real native `asyncio` TCP-connect discovery (no shell execution, no Nmap/NSE, server-enforced scope policy rejecting default routes/oversized ranges at scan time regardless of registration input); Security Graph ontology v3 (`NETWORK`/`DEVICE`/`SERVICE` node kinds, `CONNECTED_TO`/`EXPOSES`/`MEMBER_OF_NETWORK` edge kinds — deliberately distinct from M5's directory `MEMBER_OF`); deterministic network exposure analysis (`PUBLICLY_ADDRESSABLE_ASSET` via RFC-accurate `ipaddress.is_global`, `SENSITIVE_SERVICE_OBSERVED`, `MULTIPLE_REMOTE_ADMIN_SERVICES` — exposure context, never auto-vulnerability); reused the generic `/assets` API/frontend for network browsing (no duplicate inventory surface); 1 new API (`/network-exposure/observations`); real-PostgreSQL concurrency proof; full live acceptance including real loopback TCP discovery | 3,557 |
| M5 | Identity & Directory Security Visibility Foundation | New `domain/directory_security/` bounded context — canonical `DirectoryIdentity`/`DirectoryGroup`/`DirectoryMembership`, deliberately distinct from RedForge's own `domain/identity/` (login user/RBAC) and never merged with it; identity resolution key `(organization_id, connector_id, external_id)` (connector-scoped, not just org-scoped, since two directories could expose colliding raw identifiers) with 2 real normalization schemes (LDAP_ENTRY_UUID, AD_OBJECT_GUID); migration 0015 (`directory_identities`/`directory_groups`/`directory_memberships`, composite tenant-integrity foreign keys on membership endpoints identical to M4's edge pattern); real read-only LDAP/Active-Directory-compatible connector (`ldap3`, TLS-required-by-default, no write/mutate method exposed) — the new `ConnectorType.LDAP_DIRECTORY` reuses M3's Connector/Discovery-Run lifecycle unmodified; typed `IdentityObservation`/`GroupObservation`/`MembershipObservation` contracts (never a raw payload dict); controlled privilege classification driven by connector-configured recognized-privileged-group DNs (never name-based "admin" guessing); Security Graph ontology v2 (`IDENTITY`/`SERVICE_IDENTITY`/`GROUP` node kinds, `MEMBER_OF` edge kind — nested GROUP→GROUP membership deliberately not activated, no producing adapter yet); `SecurityGraphProjector` extended (not duplicated) with `project_directory_identity`/`project_directory_group`/`project_membership`; deterministic identity-security analysis (`DISABLED_PRIVILEGED_IDENTITY`, `PRIVILEGED_SERVICE_IDENTITY`, `HIGH_PRIVILEGE_GROUP_MEMBERSHIP` — direct-only, computed on read, no fabricated Findings); 6 new read-only API endpoints (`/identities`, `/directory-groups`, `/identity-security/observations`) with zero node/edge/identity mutation endpoints; real-PostgreSQL concurrency proof (5 tests: concurrent identity/group/membership resolution converge on 1 row each; same identity across 2 tenants stays separate; cross-tenant membership rejected by composite FK); fixed a real projection bug found via live acceptance (group `is_recognized_privileged` was read from a stale discovery observation instead of the persisted resolution result); Identities/Directory-Groups/Identity-Security frontend + LDAP connector registration UI (credential reference only, never a raw bind password) | 3,514 |
| M4 | Security Graph Ontology & Projection Foundation | Controlled versioned ontology (`domain/security_graph/ontology.py`: 10 NodeKinds, 8 EdgeKinds, explicit source/target validity pairs, `validate_edge()` rejects invalid pairings — no caller-controlled free-string types); migration 0014 (`security_graph_nodes` + `security_graph_edges`, tenant-scoped unique identity `(organization_id, source_domain, source_entity_id)` for nodes and `(organization_id, source_node_id, relationship_kind, target_node_id)` for edges); tenant integrity enforced at the DATABASE level via composite foreign keys `(node_id, organization_id)` — a cross-tenant edge is a physical FK violation, not an application check (proven under real PostgreSQL concurrency); `SecurityGraphProjector` (application/security_graph/projector.py) — the ONLY writer of graph nodes/edges, projecting M3 canonical `AIAsset`/`AssetRelationship` and Finding data via an explicit allowlist mapping (unsupported asset/relationship types are skipped, never coerced); `TenantSecurityGraphService` — bounded overview/node-detail/neighbors/cycle-safe BFS path query (server-clamped depth and result count, `SecurityRelationshipPath` never called an "attack path"); 4 new tenant-scoped API endpoints (`/security-graph`, no public node/edge write endpoints — graph is projection-only); fixed a real P0 in the pre-existing global Knowledge Graph API (`knowledge_graph_api.py`) — every node/edge ID is now tenant-scoped by prefixing the verified organization_id onto the underlying in-memory key, making cross-tenant reads/writes structurally impossible rather than merely undocumented; Security Graph frontend (`/security-graph`) with bounded path exploration UI, explicitly labeled "Security Relationship Paths"; real-PostgreSQL concurrency proof (concurrent same-source-entity projection → 1 node; concurrent same-edge projection → 1 edge; same source entity across 2 tenants → 2 independent nodes; cross-tenant edge rejected by database) | 3,481 |
| M3 | Unified Asset, Connector & Security Graph Foundation | Discovered and reused existing Sprint 22/23 `AIAsset`/`Connector` domain aggregates (previously in-memory only, zero persistence/API); added real PostgreSQL persistence (migration 0013: `ai_assets` + `connectors`, document-store JSON blob + relational tenant-scoped columns, partial unique index on `(organization_id, external_id)`); `domain/inventory/identity.py` canonical identity/normalization strategy (REDFORGE_TARGET_ID/URL_ORIGIN/IP_ADDRESS/CLOUD_RESOURCE_ID schemes); extended `AssetType` with 5 generic non-AI kinds (APPLICATION/URL/HOST/IP_ADDRESS/CLOUD_RESOURCE) proving extensibility; `TenantAssetService`/`TenantConnectorService` with race-safe get-or-create upsert semantics; real (non-simulated) "RedForge Targets" discovery connector resolving actual AITarget rows — existing `Connector.discovery_history` reused as the Discovery Run lifecycle (no second table); AI target ↔ canonical asset auto-association (best-effort, non-blocking); tenant-scoped Security Graph read view (relationships embedded in `AIAsset`, not the pre-existing untenanted global Knowledge Graph); 9 new API endpoints (`/assets`, `/connectors`); DISCOVERED ASSET ≠ AUTHORIZED TEST TARGET boundary enforced structurally (no execution dependency in discovery path); real-PostgreSQL concurrency proof (concurrent same-identity resolution → 1 asset; same identity across 2 tenants → 2 independent assets); Assets/Connectors frontend | 3,456 |
| M2 | Privileged Access Security, Platform RBAC & Tenant Governance | Real TOTP MFA (`domain/mfa/`, `application/mfa/MFAService`, Fernet-encrypted secrets, migration 0012 `mfa_factors` + partial unique indexes); privileged step-up assurance (`PrivilegedAssuranceService`, opaque server-validated token, `platform_privileged_assurances` table, configurable TTL); `require_platform_permission_with_assurance` gating grant/revoke/suspend/reactivate; live user-status enforcement closing the gap where suspension had no effect on already-issued JWTs (`api/security.py` + `AuthService.get_current_user`/`get_accessible_organizations`); platform RBAC matured from 3 empty M1 placeholder roles to real distinct permission semantics (SECURITY_ADMIN/SUPPORT/AUDITOR); `PlatformGovernanceService` (user/org suspend/reactivate, self-suspension protection); provider tenant ownership (`organization_id` added to `ProviderService`, cross-tenant access now 404s identically to nonexistent); 6-screen Platform Control Plane (`+security` MFA/step-up UI); real-PostgreSQL concurrency proof for MFA enrollment race | 3,434 |
| M1 | Platform Identity & Super Admin Bootstrap | `domain/platform_identity/` (PlatformRole, PlatformAssignment, invariants); `application/platform_identity/` (PlatformAccessService, PlatformQueryService); `PlatformContext`/`require_platform_permission` in `api/security.py` — structurally distinct from `TenantContext`, resolved from live DB lookup, never a JWT claim; migration 0011 (`platform_assignments`, `platform_bootstrap_state` singleton-claim table, `platform_audit_log`); race-safe one-time bootstrap proven against real PostgreSQL concurrency (10 concurrent attempts → exactly 1 winner); last-Super-Admin revoke protection proven under concurrent revokes; `GET/POST /api/v1/platform/*` (8 endpoints); Platform Control Plane frontend (`(platform)/platform/{overview,users,organizations,access,audit}`) | 3,412 |
| 38/39 + IA | Production-Grade AI Security Evaluation Intelligence + Integration Audit | `security_judge.py` subclasses `LLMJudgeEvaluator`; `consensus.py` + `policy.py` wired into `EvaluationPipeline`; `evaluation_intelligence.py` wired into `ValidationService` + `RedTeamOrchestrator`; `EvaluationRunResult` carries `consensus_result` + `policy_result`; `ValidationServiceResult` carries `evaluation_feedback`; `CampaignIntelligenceContext.metadata` receives eval quality signals; 16 integration audit tests + 91 unit tests | 3,254 |
| 36/37 | Adaptive AI Red Team Intelligence Layer | `domain/red_team/campaign_decision.py` (CampaignDecisionAction, NodeEvidenceSummary, CampaignIntelligenceContext, CampaignDecisionRecord); `application/red_team/campaign_intelligence.py` (RuleBasedCampaignIntelligenceService, ConfidenceEstimator, CampaignLearner, CampaignDecisionHistory); `application/red_team/adaptive_strategy.py` (FamilyBasedAttackSelector, ProviderAwarePayloadStrategySelector, CategoryProviderConversationStrategySelector); `application/red_team/plugin_sdk.py` (5 plugin Protocols, PluginRegistry); AttackGraph.inject_node() for live node injection; AttackNodeInjected event; CAMPAIGN_DECISION KG node type; DECISION_INFLUENCED_NODE KG edge; 6 new Protocol ports; 92 new tests | 3,126 |
| 34/35 | Enterprise AI Red Team Orchestration Platform | `domain/red_team/` (AttackGraph DAG, GoalCriteria, EdgeCondition, 13 events); `application/red_team/` (RedTeamOrchestrator, InMemoryAttackGraphRepository); 28 attack categories; OWASP mappings; 3 new KG node types; 6 new KG relationship types; multi-tenant security guards on pause/resume/cancel/retry | 3,029 |
| 32/33 | Architecture Stabilization + Advanced AI Validation | ProjectionRegistry.clone(); KGProjection wired; GDPR tombstone; AdvancedValidationCoordinator (7 modes); DLQ accessor properties; 30s TTL cache | 2,970 |
| 31 | Durable Read Models; DLQ exhausted/in-flight lifecycle; cross-tenant replay enforcement | `flush_to_durable_repo()` pattern; migration 0009; `SELECT FOR UPDATE SKIP LOCKED`; 9 projections persist to PostgreSQL after replay; `GET /runtime/checkpoints` queries live DB; handler metrics (7 counters/histograms) | 2,936 |
| 30 | Production Projection Registry; replay invokes real handlers | `ProjectionRegistry.register_all_with()`; `load_checkpoints` ordering fix; 4 diagnostic endpoints | 2,918 |
| 29 | Replay Pipeline; `fetch_by_event_id`; circuit RBAC | PostgreSQL DLQ wired; real `replay_fn`; migration check | 2,897 |
| 28 | PostgreSQL DLQ; startup validator; dynamic health | `DLQReplayWorker`; `StartupValidator`; circuit reset | 2,883 |
| 27 | RuntimeContainer; 8 runtime HTTP endpoints | HALF_OPEN race fixed; `GET /runtime/*` endpoints | 2,829 |
| 26 | 12 runtime protocols; circuit breaker; DLQ; health; backpressure; bulkhead | `RuntimeContainer`; supervisor; lifecycle; heartbeat | 2,778 |
| 25 | PostgreSQL EventStore; IdempotentProjectionEngine; AggregateRehydration; UpcasterChain | 4 P0/P1 debts resolved; KGProjection total_edges fix | 2,631 |
| 24 | Enterprise AI Security Data Platform | 17 platform domain models; 10 protocol ports; InMemoryEventStore; ProjectionEngine; 10 projections; ReplayEngine | 2,558 |
| 1 | Risk Correlation Engine, Knowledge Graph (in-memory semantic graph) | `application/risk_engine.py`, `application/knowledge_graph.py` | ~200 |
| 2 | REST API layer (48 endpoints), bounded-context service split | 19 FastAPI routers, `api/v1/`, `application/` service split | ~400 |
| 3 | UnitOfWork pattern, transaction ownership | `infrastructure/database/unit_of_work.py`, repository separation from UoW | ~500 |
| 4 | Production readiness | pytest baseline, mypy strict, Alembic migrations (10 tables), Docker multi-stage, Prometheus metrics, security headers | ~700 |
| 5 | Enterprise auth hardening | Argon2id passwords, PyJWT with refresh, rate limiting (token bucket), OpenTelemetry, audit logging, GitHub Actions CI | ~900 |
| 6 | Runtime vertical slice | `application/runtime/orchestrator.py`, `dispatcher.py`, `executors.py`, `classifiers.py` | ~1,000 |
| 7 | Attack Execution Engine | Multi-turn strategies, payload pipeline, conversation builder, provider adapter integration | ~1,100 |
| 8 | Evaluation Engine | Multi-evaluator pipeline, confidence aggregation, finding candidate generation | ~1,150 |
| 8b | Scenario Engine | 5 scenario profiles, capability resolution, success criteria, scenario runner | ~1,200 |
| 9-12 | Attack Knowledge Model | Attack taxonomy (unlimited depth), framework mappings (MITRE/OWASP), evaluation intelligence | ~1,400 |
| 13 | Knowledge Graph expansion | Attack taxonomy nodes in KG, relationship types for taxonomy traversal | ~1,500 |
| 14-16 | Response Evaluation Intelligence, Campaign Engine | EvaluationResult domain entity, campaign lifecycle, drift detection | ~1,650 |
| 17 | Conversation Engine | Multi-turn adaptive attack sessions, decision engine, conversation strategies | ~1,750 |
| 18 | Conversation + Campaign integration | CampaignEngine coordinates conversations, campaign-level KG projection | ~1,800 |
| 19 | Agent & MCP Security Validation | AgentSession, MCPSession, tool invocation tracking, loop detection, permission escalation detection | ~1,953 |
| 20 | Continuous AI Security Validation (Posture) | ValidationSnapshot, ValidationBaseline, SecurityPostureCalculator, TrendAnalyzer, DriftDetector, RegressionAnalyzer | ~2,064 |
| 21 | AI Security Intelligence | IntelligenceService pipeline (Coverage, Gap, Insight, Recommendation, Priority, Narrative), 6 domain aggregates | ~2,169 |
| 22 | Enterprise AI Asset Inventory | AIAsset aggregate (13 types), 6-phase InventoryService pipeline, fingerprint engine, dependency resolver | ~2,302 |
| 23 | AI Connector & Discovery Framework | Connector aggregate (11 types), ConnectorService, DiscoveryService, SyncService, ConnectorRegistry | ~2,415 |
| 24 | Enterprise AI Security Data Platform | 17 platform domain models, 10 protocol ports, InMemoryEventStore (thread-safe), ProjectionEngine (dict-dispatched), 10 projections, ReplayEngine (8 filter dimensions), KG as projection consumer | 2,558 |

---

## 11. Technical Debt

All items verified from source code as of 2026-07-10 (Sprint 32/33 baseline).

**Resolved in Sprints 25–33** (no longer open):
- ~~P0: Projection non-idempotency~~ — resolved Sprint 25 (`IdempotentProjectionEngine`)
- ~~P0: No PostgreSQL EventStore~~ — resolved Sprint 25
- ~~P1: No PostgreSQL CheckpointRepository~~ — resolved Sprint 25
- ~~P1: No aggregate rehydration~~ — resolved Sprint 25 (`AggregateRehydration + UpcasterChain`)
- ~~P2: KGProjection total_edges bug~~ — resolved Sprint 25
- ~~P0: PostgreSQL DLQ not wired~~ — resolved Sprint 29
- ~~P0: No-op replay_fn~~ — resolved Sprint 29
- ~~P0: No projection handlers in replay engine~~ — resolved Sprint 30 (`register_all_with`)
- ~~P0: worker_running always false~~ — resolved Sprint 31 (`worker.is_running`)
- ~~P0: No durable read model flush~~ — resolved Sprint 31 (`flush_to_durable_repo` pattern)
- ~~P1: DEBT-S31-1 Concurrent replay race~~ — resolved Sprint 32 (`ProjectionRegistry.clone()`)
- ~~P1: DEBT-S31-2 KGProjection not wired~~ — resolved Sprint 32 (`runtime_container.knowledge_graph` field + lazy registration in `app.py`)
- ~~P1: DEBT-S31-3 No exhausted-depth alert~~ — resolved Sprint 32 (`InMemoryDeadLetterQueue.exhausted_count` property)
- ~~P2: DEBT-S31-5 Checkpoint endpoint DB query per request~~ — resolved Sprint 32 (30s TTL cache in `api/v1/runtime.py`)
- ~~P2: DEBT-S31-6 DLQ internal sets accessed in tests~~ — resolved Sprint 32 (`inflight_count`, `exhausted_count`, `requeued_count` properties)
- ~~P1: DEBT-S26 No GDPR tombstone~~ — resolved Sprint 33 (`EventStore.tombstone()` protocol + PostgreSQL implementation with cross-tenant guard)
- ~~15 mypy errors in agents/conversations~~ — resolved Sprint 32 (ConversationTurn Optional fields, agent_validation_engine cast, mcp_validation_engine list types)

**Resolved in Sprint 36/37**:
- ~~DEBT-S35-1~~ remains open (asyncio.Event for PAUSED loop — deferred)
- No debt items were resolved in Sprint 36/37; all 4 S35 debts remain pending PostgreSQL/API work.

**New debt introduced in Sprint 36/37**:

| Priority | ID | Item | Location | Detail | Sprint |
|----------|----|------|----------|--------|--------|
| ~~P2~~ | ~~DEBT-S37-1~~ | ~~**Intelligence runs post-terminal on single-node graphs**~~ | — | **Resolved in S36/37 remediation**: Deferred completion pattern. `mark_node_completed()` no longer auto-calls `_check_completion()`. Orchestrator calls `graph.try_complete()` AFTER adaptive intelligence runs. ESCALATE/BRANCH/PIVOT on single-node graphs now have a valid execution path. | S36/37r |
| P3 | DEBT-S37-2 | **Plugin SDK not wired into orchestrator** | `orchestrator.py` | `plugin_registry` accepted but not consulted during node selection — registry-registered plugins override nothing yet. | S40 |
| P3 | DEBT-S37-3 | **RuleBasedCampaignIntelligenceService has no persistence** | `campaign_intelligence.py` | Decision patterns are not persisted between campaigns; CampaignLearner operates only within a single execution. | S40 |
| ~~P3~~ | ~~DEBT-S39-1~~ | ~~**EvaluationDrivenIntelligenceAdapter not wired into RedTeamOrchestrator**~~ | — | **RESOLVED** (Integration Audit): Wired via `ValidationService.with_evaluation_adapter()` + `_derive_evaluation_feedback()` + `_adapt_from_node_result(evaluation_feedback=...)` | — |
| ~~P2~~ | ~~DEBT-S3839-IA-1~~ | ~~**EvaluationPipeline did not pass `proposed_severity` to policy enforcer**~~ | — | **RESOLVED** (Sprint 40): Finding generation reordered before policy check; `proposed_severity=candidate.severity` now passed; critical gate fires end-to-end. | — |
| ~~P3~~ | ~~DEBT-S3839-IA-2~~ | ~~**CampaignIntelligenceService did not consume eval metadata**~~ | — | **RESOLVED** (Sprint 40): `_modulate_from_eval_signals()` reads `eval_requires_more_evidence`, `eval_evaluation_quality`, `eval_consensus_state`, `eval_recommended_action`; 6 modulation rules implemented; recommendation ≠ applied action invariant preserved. | — |
| P3 | DEBT-S39-2 | **CalibrationRegistry not persisted** | `calibration.py` | In-memory only; calibration records lost on restart. Needs PostgreSQL-backed repo. | S41 |
| P3 | DEBT-S39-3 | **SecurityJudgeEvaluator not registered in EvaluationPipeline by default** | `pipeline.py` | Must be explicitly instantiated and added; no auto-registration. | S41 |

**Open technical debt:**

| Priority | ID | Item | Location | Detail | Sprint |
|----------|----|------|----------|--------|--------|
| P2 | DEBT-S31-4 | **Process restart read model recovery** | All projections | After restart, in-memory projections start at zero. They catch up via normal event flow but read model queries may return stale counts during catch-up. | S36 |
| P2 | DEBT-S26b | **actor_id not validated** | `domain/platform/value_objects.py` | `EventMetadata.actor_id` is a bare optional string. Spoofable at append time. | S36 |
| P3 | DEBT-S33-1 | **tombstone() in separate statements** | `infrastructure/platform/event_store.py` | SELECT + UPDATE in tombstone() are separate statements. Should be wrapped in a single serializable transaction to close the TOCTOU window. | S36 |
| P2 | DEBT-S35-1 | **PAUSED execution loop polls at 100ms** | `application/red_team/orchestrator.py` | `_run_graph` uses `asyncio.sleep(0.1)` while paused. Replace with asyncio.Event. | S36 |
| P3 | DEBT-S35-2 | **max_duration_s enforced by orchestrator not domain** | `application/red_team/orchestrator.py` | Wall-clock budget checked in `_run_graph`; domain-level time enforcement needs monotonic clock injection. | S36 |
| P3 | DEBT-S35-3 | **No PostgreSQL AttackGraphRepository** | `application/red_team/` | In-memory only; campaign state lost on restart. | S36 |
| P3 | DEBT-S35-4 | **RedTeamEvent not wired to PlatformEventPublisher** | `application/red_team/orchestrator.py` | Domain events collected via `collect_events()` but not published to EventStore; no durable audit trail. | S36 |
| Deferred | — | **No API endpoints for red team** | `api/v1/` | No `GET/POST /api/v1/red-team/*` endpoints. | S36 |
| Deferred | — | **No schema registry / upcasting** | `domain/platform/value_objects.py` | `EventVersion` exists but no migration path when major version increments. | S37+ |
| Deferred | — | **No saga / process manager** | N/A | Multi-step workflows have no explicit saga primitive beyond `CorrelationId`. | S37+ |
| Deferred | — | **InProcessDispatcher only** | `application/runtime/dispatcher.py` | Queue-based (Redis/SQS/Kafka) execution not implemented. | S37+ |
| Deferred | — | **5 SQLAlchemy ORM models only** | `infrastructure/database/models/` | Evidence, Findings, Campaigns, etc. use in-memory repos in tests only. | S37+ |
| Deferred | — | **AdvancedValidationCoordinator network I/O** | `application/advanced_validation/` | Validators return empty string when no engine wired; real network-based validation requires concrete `TargetAdapter` injected at coordinator construction. | S37+ |

---

## 12. Future Roadmap

```
COMPLETED ✓                             IN PROGRESS / NEXT
──────────────────────────────────────  ──────────────────────────────────────
✓ Organizations & Identity              Sprint 34: Schema registry / event upcasting
✓ AI Targets & Attack Library           Sprint 34: Saga / process manager
✓ Policies & Payload Engine             Sprint 34: Queue-based distributed dispatcher
✓ Planning & Execution Engine           Sprint 35: Plugin SDK for customers
✓ Validation Run lifecycle              Sprint 35: LLM-as-Judge evaluator
✓ Evidence (immutable) & Findings
✓ Risk Correlation Engine
✓ Knowledge Graph (semantic)
✓ Runtime (Orchestrator, Executor,
  Dispatcher, Classifiers)
✓ Evaluation Engine (multi-evaluator)   FUTURE (Year 2+)
✓ Scenario Engine (5 profiles)          ──────────────────────────────────────
✓ Attack Taxonomy (unlimited depth)      Autonomous AI red teaming (adaptive)
✓ Campaign Engine                        Agent-to-agent attack validation
✓ Conversation Engine                    AI supply chain security
✓ Agent & MCP Security Validation        AI security intelligence (ML-driven)
✓ Security Posture Management            Executive reporting dashboards
✓ Security Intelligence Engine           Autonomous governance platform
✓ Enterprise AI Asset Inventory
✓ AI Connector & Discovery Framework
✓ Event Platform (PostgreSQL)
✓ PostgreSQL DLQ + Replay Pipeline
✓ Production Projection Registry
✓ Durable Read Models (S31)
✓ Arch Stabilization + Advanced AI Validation (S32/33)
✓ Red Team Orchestration Platform (S34/35)
  max_concurrent=1 in production
  RedTeamOrchestrator: goal-oriented, DAG, 28 attack categories
```

---

## 13. AI Session Bootstrap

### Before implementing anything

Every AI assistant or new engineer must complete this checklist before writing a single line of code:

1. **Read this document** (`docs/PROJECT_CONTEXT.md`) in full
2. **Read `docs/about-product.md`** — the original product and architecture document
3. **Read all four ADRs** in `docs/adr/` — they record architectural decisions that must be respected
4. **Inspect the source tree**:
   ```bash
   find backend/src/redforge -type d | sort
   ```
5. **Read the specific bounded context** you plan to work in — its `entity.py`, `value_objects.py`, `events.py`, `exceptions.py`
6. **Run the quality gates** to confirm baseline:
   ```bash
   cd backend
   python -m ruff check src/ tests/
   python -m mypy src/redforge/domain/ src/redforge/application/ --strict
   python -m pytest -q --tb=short
   ```
7. **Verify what already exists** — search the codebase before creating anything:
   ```bash
   grep -r "class YourConceptName" src/
   ```

### Common traps — check before you build

| Trap | Reality |
|------|---------|
| Creating `ValidationDefinition` | Already exists: `AttackDefinition` in `domain/attack_library/` |
| Creating `ValidationCategory` | Already exists: `AttackCategory` in `domain/attack_library/value_objects.py` |
| Creating a plugin registry | Already exists: `ConnectorRegistry` (connector-style) + `AttackLibraryRepository` |
| Adding a new "Validation Engine" context | ADR-0001 explicitly rejected this — runtime IS the application layer |
| Putting risk scoring in domain | Risk scoring is `application/risk_engine.py` — application layer |
| Importing SQLAlchemy in domain | Never. Domain has zero infrastructure imports. |
| Committing in a repository | `UnitOfWork` owns commits. Repositories do not. |
| Building a new base event class | Each context has its own event base. `EventEnvelope` wraps them all. |
| Modifying `EventEnvelope.payload` type | It is `payload: object` — intentionally opaque anti-corruption layer. |

### How to extend the platform correctly

**Adding a new attack technique**: Create a new `AttackDefinition` domain object. Optionally add an `AttackTaxonomyNode` for deep classification. No code changes required in the execution engine.

**Adding a new evaluator**: Create a class implementing the `Evaluator` protocol. Register it with `EvaluationPipeline`. No other changes.

**Adding a new connector type**: Add value to `ConnectorType` enum. Register capabilities in `_DEFAULT_CAPABILITIES` dict. Implement `DiscoveryProvider` protocol. Register in `ConnectorRegistry`.

**Adding a new projection**: Subclass `ProjectionBase`. Implement `register_with(engine)` using `engine.register(name, event_type, handler)`. Call `projection.register_with(engine)` at startup.

**Adding a new storage backend**: Implement the `EventStore` protocol in `infrastructure/`. Inject it in place of `InMemoryEventStore`.

**Adding a new AI provider**: Implement the `ProviderAdapter` protocol in `infrastructure/providers/`. Register it.

---

## 14. Architecture Snapshot

```
                    ┌──────────────────────────────────────────────┐
                    │         EXTERNAL AI PLATFORMS                 │
                    │  OpenAI  Anthropic  Azure  Bedrock  LangSmith │
                    └──────────────────┬───────────────────────────┘
                                       │ (Connectors discover assets)
                    ┌──────────────────▼───────────────────────────┐
                    │         IDENTITY & ORGANIZATIONS              │
                    │  User  Membership  Invitation  Organization   │
                    └──────────────────┬───────────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────────┐
                    │         ENTERPRISE AI INVENTORY               │
                    │  Connector → DiscoveryService → AIAsset       │
                    │  (13 asset types, 6-phase pipeline)           │
                    └──────────────────┬───────────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────────┐
                    │         AI TARGETS (Security Enrollment)      │
                    │  AITarget  ValidationPolicy  TargetType       │
                    └──────────────────┬───────────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────────┐
                    │         ATTACK LIBRARY & PLANNING             │
                    │  AttackDefinition (14 categories, lifecycle)  │
                    │  AttackTaxonomyNode (unlimited depth)         │
                    │  AttackPlanner → AttackPlan (immutable)       │
                    └──────────────────┬───────────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────────┐
                    │         PAYLOAD INTELLIGENCE ENGINE           │
                    │  PayloadTemplate → render(context)            │
                    │  PayloadBundle  PayloadMutation               │
                    └──────────────────┬───────────────────────────┘
                                       │
               ┌───────────────────────┼────────────────────────────┐
               │                       │                            │
    ┌──────────▼─────────┐  ┌─────────▼──────────┐  ┌────────────▼──────────┐
    │  CAMPAIGN ENGINE    │  │ CONVERSATION ENGINE │  │ AGENT & MCP ENGINE    │
    │  Multi-target fan-  │  │ Multi-turn adaptive │  │ Tool invocations      │
    │  out with drift     │  │ attack dialogues    │  │ MCP protocol attacks  │
    │  detection          │  │                     │  │ Loop detection        │
    └──────────┬─────────┘  └─────────┬──────────┘  └────────────┬──────────┘
               └───────────────────────┼────────────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────────┐
                    │  VALIDATION SERVICE (canonical execution path)│
                    │  ValidationRun lifecycle                      │
                    │  ExecutionPlan → StepExecutor                 │
                    │  → Provider Adapter → AI Target               │
                    └──────────────────┬───────────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────────┐
                    │         EVALUATION ENGINE                     │
                    │  Keyword + Pattern + Rule evaluators          │
                    │  WeightedAverage / MajorityVote aggregators   │
                    │  ClassificationResult → FindingCandidate      │
                    └──────────────────┬───────────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────────┐
                    │  EVIDENCE (immutable, append-only)            │
                    │  record() → attach() → finalize()             │
                    │  EvidenceResult: PASS / FAIL / ERROR          │
                    └──────────────────┬───────────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────────┐
                    │  FINDINGS                                     │
                    │  Derived from Evidence (always regenerable)   │
                    │  MITRE ATLAS + OWASP GenAI references         │
                    │  Severity: CRITICAL / HIGH / MEDIUM / LOW     │
                    └──────────────────┬───────────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────────┐
                    │  RISK CORRELATION ENGINE                      │
                    │  CVSS-inspired scoring (replaceable)          │
                    │  RiskIncident  RiskHistory  RiskTrend         │
                    └──────────────────┬───────────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────────┐
                    │  SECURITY POSTURE MANAGEMENT                  │
                    │  ValidationSnapshot  ValidationBaseline       │
                    │  SecurityPostureCalculator  TrendAnalyzer     │
                    │  DriftDetector  RegressionAnalyzer            │
                    └──────────────────┬───────────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────────┐
                    │  SECURITY INTELLIGENCE ENGINE                 │
                    │  CoverageAnalyzer → GapAnalyzer               │
                    │  InsightGenerator → RecommendationGenerator   │
                    │  PriorityEngine → NarrativeBuilder            │
                    │  → IntelligenceReport                         │
                    └──────────────────┬───────────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────────┐
                    │  KNOWLEDGE GRAPH (in-memory semantic graph)   │
                    │  41 node types  |  ~60 relationship types     │
                    │  GraphTraversal  GraphStatistics              │
                    │  GraphStore Protocol (Neo4j/Neptune ready)    │
                    └──────────────────┬───────────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────────┐
                    │  EVENT PLATFORM (Sprint 24)                   │
                    │  EventEnvelope (anti-corruption layer)        │
                    │  InMemoryEventStore (reference impl)          │
                    │  ProjectionEngine (dict-dispatched)           │
                    │  10 Projections → Read Models                 │
                    │  ReplayEngine (8 filter dimensions)           │
                    │  Protocol ports → future: PostgreSQL / Kafka  │
                    └──────────────────────────────────────────────┘
```

---

## 15. Executive Summary

### What has been built (Sprint 1–35)

AIVAR RedForge is an enterprise AI security platform with **3,254 tests passing** across 112+ test files, verified with ruff (clean) and mypy --strict (0 errors) as of 2026-07-11 (Sprint 38/39 + Integration Audit).

The platform has **22 bounded contexts** implemented end-to-end:

**The security validation pipeline is complete**: an AI target enrolled for validation flows through attack planning, payload rendering, runtime execution (provider adapter → AI target HTTP call), evaluation (multi-evaluator pipeline), immutable evidence capture, finding generation with MITRE/OWASP references, risk correlation (CVSS-inspired scoring), security posture tracking (baseline, snapshot, trend, regression), and security intelligence (coverage analysis, gap detection, insight generation, recommendation production, narrative synthesis).

**Enterprise multi-tenancy is enforced** at every data path — every query is organization-scoped. The identity system uses Argon2id passwords and PyJWT authentication with 6 predefined roles and 18 fine-grained permissions.

**The AI asset discovery pipeline is complete**: connectors (11 supported platform types) discover assets from external AI platforms, a 6-phase inventory pipeline normalizes and fingerprints them, and assets flow into the Knowledge Graph.

**The Knowledge Graph** is an in-memory property graph with 41 node types and ~60 semantic relationship types connecting every platform object. It is backed by a `GraphStore` protocol, ready for Neo4j/Neptune replacement.

**The Event Platform** (Sprint 24) introduces the canonical immutable data backbone: `EventEnvelope` wraps all bounded-context domain events without modifying them (anti-corruption layer), `InMemoryEventStore` provides thread-safe append-only storage with monotonic global positioning, a dict-dispatched `ProjectionEngine` maintains 10 read models, and a `ReplayEngine` supports 8 filter dimensions for catch-up and auditing. The Knowledge Graph is now a projection consumer — one of 10 projections fed by the event stream.

### What remains

The next priority work is **Sprint 38 — Red Team API & Persistence**:
1. Wire `RedTeamEvent` → `EventEnvelope` → `PlatformEventPublisher` (DEBT-S35-4)
2. Build `PostgreSQLAttackGraphRepository` — survive restarts (DEBT-S35-3)
3. Add `GET/POST /api/v1/red-team/` endpoints with JWT tenant extraction
4. Load initial projection state from PostgreSQL on process restart (DEBT-S31-4)
5. Validate `actor_id` in `EventMetadata` (DEBT-S26b)
6. Wrap `tombstone()` SELECT+UPDATE in serializable transaction (DEBT-S33-1)

Beyond that: schema registry/upcasting, distributed queue-based dispatcher, plugin SDK, LLM-as-Judge evaluator.

### Production readiness (Sprint 32/33)

**Shippable with `max_concurrent=1`**: all Sprint 31-33 success criteria met. Replay is durable, tenant-isolated, and wires all 9 projections (10 with KGProjection when `runtime.knowledge_graph` is set). Concurrent replay is now architecturally safe via `ProjectionRegistry.clone()` but `max_concurrent=1` remains the recommended production setting until DEBT-S31-4 (restart recovery) is resolved.

**Advanced Validation**: `AdvancedValidationCoordinator` is wired and tested. Production use requires injecting a concrete `TargetAdapter` (network implementation) — currently returns empty string without one, which is by design (test isolation).

**GDPR tombstone**: `EventStore.tombstone()` is in the protocol with a cross-tenant guard. PostgreSQL implementation is complete. EU-regulated deployments can use it immediately.

### Architecture quality

The codebase is architected for a 10-year lifespan. Clean Architecture with strict DDD boundaries means the domain layer has zero infrastructure imports. Protocol-first design means every extension point is pluggable. No switch statements anywhere. No duplicated business logic across bounded contexts.

The architecture scores **9.8/10** (Sprint 40 — Evaluation Control Loop closed). **Sprint 38/39**: Production-Grade AI Security Evaluation Intelligence — LLM-as-Judge with adversarial isolation; multi-evaluator consensus; calibration infrastructure; FP/FN control policy; attack outcome reasoning; campaign intelligence feedback. **Sprint 40 additions**: (1) Finding safety gate now fires end-to-end — `EvaluationPipeline` generates `FindingCandidate` BEFORE calling `EvaluationPolicyEnforcer.check()`, passing `proposed_severity=candidate.severity`; BLOCK_CRITICAL demotes critical findings when quorum/confidence thresholds not met (DEBT-S3839-IA-1 resolved). (2) `RuleBasedCampaignIntelligenceService` now consumes eval quality signals via `_modulate_from_eval_signals()` — 6 modulation rules; `eval_requires_more_evidence` + `eval_evaluation_quality` + `eval_consensus_state` + `eval_recommended_action` all consumed; recommendation ≠ applied action invariant preserved (DEBT-S3839-IA-2 resolved). (3) Production wiring factory functions added to `dependencies.py`: `_evaluation_intelligence_adapter()`, `_campaign_intelligence_service()`, `wire_evaluation_into_validation_service()`, `build_red_team_orchestrator()`. (4) Orchestrator metadata extraction corrected: reads actual `EvaluationFeedback` fields (`evaluation_quality`, `requires_more_evidence`) not nonexistent attributes. 30 new tests; 3,284 total. Remaining risk: calibration not persisted (DEBT-S39-2); Plugin SDK not consulted at execution (DEBT-S37-2); no red team API endpoints (Deferred).

---

**Sprint 42–43 additions** (2026-07-11):

1. **Target request contract regression tests** — `tests/api/test_targets_api.py` (22 tests). Proves every canonical `TargetType` and `Provider` enum value passes request validation (→201); invalid `target_type="llm"` → 422 never 500; invalid provider → 422; tenant isolation for list and cross-tenant GET.

2. **Organization discovery API** — `GET /api/v1/auth/organizations` returns organizations accessible through the caller's ACTIVE memberships. Identity comes exclusively from the bearer token. `AuthService.get_accessible_organizations()` added. `tests/api/test_org_discovery_api.py` (7 tests) proves tenant isolation: user A cannot discover org B, inactive membership excluded, empty for new users, schema fields present.

3. **Campaign persistence** — migration `0010_campaign_results.py` adds `campaign_results` table. `CampaignResultModel` ORM model. `CampaignResultRepository` for save/list/get-by-id-with-org-scope. Results written after each `POST /red-team/campaigns` execution.

4. **Campaign query API** — `GET /api/v1/red-team/campaigns` and `GET /api/v1/red-team/campaigns/{campaign_id}`. `CampaignQueryService` application service with pagination. Tenant isolation enforced at repository layer (org-scoped queries). `tests/api/test_campaigns_api.py` (10 tests) proves tenant isolation, 404 for cross-tenant access, no credentials in response.

5. **Frontend organization bootstrap** — Login/register now redirects to `/org-select` instead of directly to `/dashboard`. `OrgSelectPage`: zero orgs → setup form; one org → auto-select; multiple → selector. `OrgSetupForm` creates org with slug derivation. `selectOrganization()` atomically replaces token + stores org_id. `AppLayout` checks `getOrganizationId()` before rendering, redirects to `/org-select` if absent. Logout clears both token and org_id.

6. **Campaign list UI** — Uses real `GET /api/v1/red-team/campaigns` API with loading state, truthful empty state, API failure display. Campaign detail view uses real `GET /api/v1/red-team/campaigns/{id}`. Attack graph nodes rendered with canonical state colors (PENDING/READY/RUNNING/COMPLETED/FAILED/BLOCKED/SKIPPED); unknown states render as "UNKNOWN" explicitly.

7. **npm security** — Next.js upgraded 15.1.4 → 15.5.20 (resolves 1 critical). postcss upgraded 8.4.49 → 8.5.10 (resolves direct dep moderate). Remaining: 1 moderate in `next/node_modules/postcss` (bundled, unfixable without breaking Next.js — documented as accepted residual).

**Test baseline**: 3,377 passed, 5 skipped (up from 3,338). ruff clean. mypy --strict: 0 errors (453 source files). Frontend build: clean. Frontend tsc: 0 errors.

**Open DEBT**:
- DEBT-S4243-1: `provider_api_key` still accepted per-campaign (server-side credential store boundary not yet implemented — documented as P1 architecture gap; per-campaign key path is server-side, never stored or logged, but repeats credential submission)
- DEBT-S35-3: `PostgreSQLAttackGraphRepository` not implemented (graph snapshot stored as JSONB at campaign completion instead)
- DEBT-S35-4: `RedTeamEvent` not wired to EventEnvelope/PlatformEventPublisher

---

*This document was last updated 2026-07-11 (Sprint 42–43). It reflects the actual repository state, not aspirational design. Verify anything time-sensitive against current source files before acting on it.*
