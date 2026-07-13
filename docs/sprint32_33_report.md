# Sprint 32/33 Report — Architecture Stabilization & Advanced AI Validation Platform

**Date**: 2026-07-10  
**Test baseline (entry)**: 2,936  
**Test baseline (exit)**: 2,970 (+34)  
**ruff**: clean  
**mypy --strict**: 0 errors, 429 source files  

---

## Part A — Architecture Stabilization

### Objectives Completed

**A1. Zero mypy errors** — resolved 15 pre-existing errors across agents/conversations layer:
- `ConversationTurn` value object: made `assistant_response`, `turn_started_at`, `turn_completed_at` Optional (backward-compatible; `is_error` and `duration_ms` already handled None)
- `AgentValidationEngine._parse_schema()`: return type cast `json.loads() → dict[str, Any]`
- `MCPValidationEngine._attack_*` methods: replaced bare `list` params with `list[dict[str, Any]]`; fixed `_extract_resource_content` and `_extract_prompt_template` return types

**A2. DEBT-S31-1 — Concurrent replay race** — `ProjectionRegistry.clone()` creates isolated instances with a fresh `InMemoryReadModelRepository`. Each DLQ replay session gets a clone so concurrent workers cannot race on shared mutable state. Limitation: clones start at zero cumulative state (documented in docstring).

**A3. DEBT-S31-2 — KGProjection wired** — `RuntimeContainer` now has `knowledge_graph: KnowledgeGraph | None` field (TYPE_CHECKING import, no hard dependency). `app.py` lazy-registers `KGProjection` when `runtime.knowledge_graph` is set. `_build_projection_registry()` also accepts optional `knowledge_graph`.

**A4. DEBT-S31-3 + DEBT-S31-6 — DLQ monitoring** — Added `inflight_count`, `exhausted_count`, `requeued_count` properties to `InMemoryDeadLetterQueue`. All access through public properties; direct set access in tests replaced.

**A5. DEBT-S31-5 — Checkpoint endpoint TTL cache** — 30-second TTL cache in `api/v1/runtime.py` reduces DB round-trips for high-frequency polling clients.

**A6. DEBT-S26 — GDPR tombstone** — `EventStore.tombstone(stream_id, event_id, organization_id)` added to protocol (`application/platform/contracts.py`). `InMemoryEventStore`: no-op (test/dev). `PostgreSQLEventStore`: SELECT + cross-tenant ownership check + UPDATE payload to `{_tombstoned: true, reason: gdpr_erasure}`. Raises `ValueError` on cross-tenant attempt. `update` added to SQLAlchemy imports.

### Files Modified (Part A)

| File | Change |
|------|--------|
| `domain/conversations/value_objects.py` | ConversationTurn Optional fields |
| `application/agents/agent_validation_engine.py` | _parse_schema return type cast |
| `application/agents/mcp_validation_engine.py` | 6 _attack_* method signatures + extract helpers |
| `application/platform/runtime_container.py` | knowledge_graph field, _build_projection_registry param |
| `application/platform/projection_registry.py` | clone() method |
| `application/platform/dead_letter_queue.py` | 3 property accessors |
| `application/platform/contracts.py` | EventStore.tombstone() protocol method |
| `application/platform/event_store.py` | tombstone() no-op implementation |
| `infrastructure/platform/event_store.py` | tombstone() PostgreSQL implementation |
| `api/v1/runtime.py` | 30s TTL cache for /runtime/checkpoints |
| `app.py` | KGProjection lazy wiring in _start_database |
| 6 projection files | E501 / W291 fixes (ruff) |

---

## Part B — Advanced AI Validation Platform

### Objectives Completed

**B1. ValidationMode enum** — 7 modes in `domain/validations/value_objects.py`:
`STANDARD | MULTI_TURN | LONG_CONTEXT | MULTI_MODEL | PROMPT_CHAIN | AGENT_WORKFLOW | MCP_TOOL`

**B2. TargetAdapter protocol** — `@runtime_checkable Protocol` in `application/advanced_validation/validators.py`. Thin abstraction over existing `StepExecutor`; decouples validators from `StepContext` field names.

**B3. ConversationMemoryValidator** — Two-phase: (1) plants a runtime-generated secret in session A and verifies recall, (2) probes fresh session B for cross-session leakage. Finds `conv_memory_persistence_failure` (high) and `conv_memory_cross_session_leak` (critical).

**B4. LongContextValidator** — Sends `{filler_tokens // 9}` repetitions of a filler sentence + an anchor phrase; checks if anchor survives to the response. Finds `long_context_lost_in_middle` (medium) and `long_context_error` (medium) on empty response.

**B5. MultiModelEvaluator** — Runs attack prompts across `list[ModelEndpoint]`; detects refusal inconsistency (some models refuse, others don't) as `multi_model_refusal_inconsistency` (high).

**B6. PromptChainValidator** — Executes `list[ChainStep]`; each step substitutes `{prev_output}` via `str.replace()` (not `str.format()` — prevents `KeyError` on curly braces in model output). Finds empty-output, expected-token-missing, and forbidden-token-present findings.

**B7. AdvancedValidationCoordinator** — Routes `AdvancedValidationRequest.mode` to the appropriate validator or engine. `ConversationEngine`, `AgentValidationEngine`, and `MCPValidationEngine` are injected at construction (all optional). No engines wired → `info`-severity finding explaining what needs wiring. `organization_id` comes exclusively from `AdvancedValidationRequest` (JWT TenantContext enforced at API layer).

### New Files (Part B)

| File | Contents |
|------|----------|
| `application/advanced_validation/__init__.py` | Package exports |
| `application/advanced_validation/validators.py` | TargetAdapter, AdvancedFinding, 4 validators |
| `application/advanced_validation/coordinator.py` | AdvancedValidationCoordinator + DTOs |

### Tests Added

`tests/unit/test_sprint32_33_advanced_validation.py` — 34 tests:
- `TestValidationMode` (2): enum values, StrEnum equality
- `TestAdvancedFinding` (2): frozen, defaults
- `TestConversationMemoryValidator` (3): persistence ok, failure, cross-session leak
- `TestLongContextValidator` (3): anchor recalled, lost-in-middle, empty response
- `TestMultiModelEvaluator` (4): all refuse, none refuse, inconsistency, `_is_refusal` signals
- `TestPromptChainValidator` (5): happy path, empty, missing token, forbidden, prev_output substitution
- `TestAdvancedValidationCoordinator` (9): all modes, result shape, agent/MCP not-wired info findings
- `TestEventStoreTombstone` (3): protocol presence, in-memory no-op ×2
- `TestProjectionRegistryClone` (2): distinct registry, isolated repo
- `TestArchitectureRegression` (2): ValidationMode in domain layer, coordinator imports domain

---

## Architecture Decisions

1. **TargetAdapter over StepExecutor** — validators use a two-method protocol (`send`) rather than `StepExecutor` + `StepContext` to avoid coupling to execution-layer field names (`payload_content`, `step_id`, `attack_id` are irrelevant to the advanced validators). The coordinator bridges the two via `_InlineAdapter`.

2. **`str.replace()` not `str.format()`** — `PromptChainValidator` uses `step.prompt_template.replace("{prev_output}", prev_output)` to prevent `KeyError` when a model response contains literal curly braces. This was caught in adversarial review.

3. **Coordinator as routing shim** — `AdvancedValidationCoordinator` contains no domain logic. It translates `ValidationMode` into a call on the appropriate engine/validator. Domain logic stays in the engines and validators.

4. **tombstone cross-tenant guard in Python** — The PostgreSQL `tombstone()` implementation does the org check in Python (SELECT first, verify, then UPDATE). This is safe because both operations are within the same SQLAlchemy session scope. DEBT-S33-1 notes the TOCTOU window and recommends serializable transaction wrapping in Sprint 34.

---

## Technical Debt (Sprint 32/33)

### Resolved
- DEBT-S31-1 (concurrent replay race) — `ProjectionRegistry.clone()`
- DEBT-S31-2 (KGProjection not wired) — `runtime.knowledge_graph` field
- DEBT-S31-3 (exhausted-depth alert) — `exhausted_count` property
- DEBT-S31-5 (checkpoint DB query per request) — 30s TTL cache
- DEBT-S31-6 (DLQ internal sets in tests) — public properties
- DEBT-S26 (GDPR tombstone) — `EventStore.tombstone()` protocol + PG impl
- 15 mypy errors — ConversationTurn Optional, agent cast, MCP list types

### New Debt
- **DEBT-S33-1 (P3)**: `tombstone()` SELECT+UPDATE not in explicit serializable transaction — recommend wrapping in Sprint 34
- **DEBT-S32-1 (Deferred)**: `AdvancedValidationCoordinator` validators return empty string without a concrete `TargetAdapter` wired — expected behavior, but must be documented in API layer

### Still Open
- DEBT-S31-4: Process restart read-model recovery (Sprint 34)
- DEBT-S26b: actor_id validation in EventMetadata (Sprint 34)

---

## Known Limitations

1. **AdvancedValidationCoordinator needs network adapter**: Validators produce findings from real model responses only when a concrete `TargetAdapter` implementation (making real HTTP requests) is injected at coordinator construction. The coordinator is fully functional and tested; the network layer adapter is an infrastructure concern outside this sprint's scope.

2. **ProjectionRegistry.clone() zero-state**: Cloned projection instances start with zero cumulative read model state. Safe for replay isolation; not suitable as a drop-in snapshot clone.

3. **tombstone() in-memory is a no-op**: `InMemoryEventStore.tombstone()` is intentionally a no-op (test/dev store, no persistent PII). Production GDPR erasure requires PostgreSQL.

---

## Sprint 34 Recommendation

**Mission**: Persistence Hardening + Security Hardening

**P0 items**:
1. DEBT-S31-4: Load projection state from PostgreSQL on process restart — prevents stale read-model queries after crash/deploy
2. DEBT-S26b: Validate `EventMetadata.actor_id` against TenantContext at append time — close spoofing vector
3. DEBT-S33-1: Wrap `PostgreSQLEventStore.tombstone()` in serializable transaction — close TOCTOU window

**P1 items**:
4. Network `TargetAdapter` implementation (HTTP/LLM client) so `AdvancedValidationCoordinator` can run real validation sessions end-to-end
5. API endpoint for `POST /advanced-validation` that routes `ValidationMode` through `AdvancedValidationCoordinator`

**Deferred**: schema registry, saga primitive, distributed dispatcher (Sprint 35+)

**Expected test count**: ~3,020 (50 new tests covering restart recovery, actor_id validation, tombstone atomicity, and AdvancedValidation HTTP endpoint)
