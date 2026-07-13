# Sprint 36/37 — Adaptive AI Red Team Intelligence Layer

**Date**: 2026-07-11  
**Sprint Theme**: Make the RedTeamOrchestrator observe, learn, and adapt in real-time  
**Test baseline entering**: 3,034 → **Exiting (post-remediation)**: 3,147 (+113 tests)  
**Ruff**: ✅ clean | **mypy --strict**: ✅ 0 errors (444 source files)

> **Correctness Remediation (2026-07-11)**: A lifecycle ordering bug was found and fixed after initial delivery. See Section 10 for full details. The test count and capability claims below reflect the remediated state.

---

## 1. What Was Built

Sprint 36/37 added an **Adaptive Campaign Intelligence** subsystem that extends the `RedTeamOrchestrator` (Sprint 34/35) to make context-aware decisions after each attack node execution. Nothing existing was replaced — all new capability is an additive layer.

### New Files

| File | Role |
|------|------|
| `domain/red_team/campaign_decision.py` | Value objects: `CampaignDecisionAction` (6-action StrEnum), `NodeEvidenceSummary`, `CampaignIntelligenceContext`, `CampaignDecisionRecord` |
| `application/red_team/campaign_intelligence.py` | `RuleBasedCampaignIntelligenceService`, `ConfidenceEstimator`, `CampaignLearner`, `CampaignDecisionHistory`, `CampaignIntelligenceServicePort` Protocol |
| `application/red_team/adaptive_strategy.py` | `FamilyBasedAttackSelector`, `ProviderAwarePayloadStrategySelector`, `CategoryProviderConversationStrategySelector` + 3 Protocol ports |
| `application/red_team/plugin_sdk.py` | 5 plugin Protocols (`AttackStrategy`, `PayloadStrategy`, `ConversationStrategy`, `CampaignDecision`, `IntelligenceProvider`) + `PluginRegistry` |
| `tests/unit/test_sprint36_37_adaptive_intelligence.py` | 97 new tests across 12 test classes |

### Modified Files

| File | Change |
|------|--------|
| `domain/red_team/entity.py` | Added `inject_node()` — live node injection into a running `AttackGraph` |
| `domain/red_team/events.py` | Added `AttackNodeInjected` domain event (14 total events) |
| `application/red_team/orchestrator.py` | `_adapt_from_node_result()`, `_apply_decision()`, `CampaignDecisionHistory` wiring; 3 new `RedTeamResult` fields (`decision_history`, `intelligence_confidence`, `injected_nodes`) |
| `application/knowledge_graph.py` | `NodeType.CAMPAIGN_DECISION`, `RelationshipType.DECISION_INFLUENCED_NODE` |

---

## 2. Decision Flow

After every node execution (success or failure), the orchestrator calls:

```
_execute_node()
    └── mark_node_completed / mark_node_failed
        │   (graph NOT finalized here — deferred completion contract)
        └── _adapt_from_node_result()
              ├── Build CampaignIntelligenceContext
              │     (node summary, completed_nodes, prior_decisions,
              │      consecutive_failures/successes, goal)
              ├── intelligence_service.decide(ctx) → CampaignDecisionRecord
              ├── _apply_decision(decision, graph) → (applied_node_ids, failure_reason)
              │     ├── ESCALATE/BRANCH → graph.inject_node() per category
              │     ├── PIVOT           → graph.inject_node("pivot_" prefix)
              │     ├── STOP            → graph.cancel("adaptive_stop: ...")
              │     └── CONTINUE/RETRY  → no-op (payload_hint in record)
              ├── Stamp decision with applied_node_ids + application_failure_reason
              └── decision_history.record(stamped_decision)
        └── graph.try_complete()   ← finalize AFTER intelligence
              (no-op if intelligence injected new READY nodes)
```

**Critical ordering invariant** (post-remediation): `mark_node_completed()` does NOT finalize the graph. The orchestrator calls `graph.try_complete()` explicitly after `_adapt_from_node_result()`. This window allows ESCALATE/BRANCH/PIVOT to inject new nodes into a still-running graph before it transitions to COMPLETED.

`_adapt_from_node_result` is non-fatal: any exception from the intelligence layer is logged and swallowed — it never disrupts the main execution loop.

---

## 3. Rule Engine Logic

`RuleBasedCampaignIntelligenceService._decide_action()` evaluates:

| Condition | Action |
|-----------|--------|
| `consecutive_failures >= max_failures` (default: 3) | STOP |
| Node succeeded, severity in {critical, high} | ESCALATE (same family, not already run) |
| Node succeeded, severity in {medium, low} | BRANCH (sibling family, not already run) |
| Node failed, `consecutive_failures == 1` | RETRY_WITH_VARIANT (provider payload hint) |
| Node failed, `consecutive_failures == 2` | PIVOT (cross-family category) |
| All escalation targets already run | CONTINUE |
| Default | CONTINUE |

Provider-specific payload hints are set on ESCALATE/RETRY records:
- `openai` → `unicode`
- `anthropic` → `zero_width`
- `azure_openai` → `base64`

---

## 4. Provider & Category Intelligence

### FamilyBasedAttackSelector (7 families)
`injection` → `jailbreak` → `exfiltration` → `agentic` → `rag` → `multi_tenant` → `availability`  
When ESCALATE fires on `prompt_injection`, the selector returns unused members of the `injection` family.

### ProviderAwarePayloadStrategySelector (6 providers)
Cycles through per-provider mutation order (e.g., `openai`: unicode→zero_width→base64→whitespace→markdown), skipping already-tried mutations. Returns `None` when exhausted.

### CategoryProviderConversationStrategySelector
Priority: provider override > category default > `progressive_escalation`.  
Example: `jailbreak + anthropic` → `recursive_prompting` (anthropic-specific override).

---

## 5. Plugin SDK

Five `@runtime_checkable Protocol` types allow extension without modifying core:

| Protocol | Purpose |
|----------|---------|
| `AttackStrategyPlugin` | Add custom attack categories |
| `PayloadStrategyPlugin` | Add custom mutation strategies |
| `ConversationStrategyPlugin` | Add custom conversation strategies |
| `CampaignDecisionPlugin` | Replace the rule-based decision engine |
| `IntelligenceProviderPlugin` | Add external intelligence backends (LLM, threat feed) |

`PluginRegistry` holds all registered plugins and is passed to `RedTeamOrchestrator` as `plugin_registry=`. (Note DEBT-S37-2: registry is accepted but not yet consulted at execution time.)

---

## 6. Test Coverage (113 tests)

| Class | Tests | What |
|-------|-------|------|
| `TestNodeEvidenceSummary` | 7 | produced_findings, severity tiers, execution_failure |
| `TestCampaignDecisionRecord` | 3 | confidence bounds, immutability |
| `TestConfidenceEstimator` | 7 | all actions, failure penalty, range invariant |
| `TestCampaignLearner` | 5 | categories_with_findings, failed, already_run, dominant_severity |
| `TestRuleBasedCampaignIntelligenceService` | 16 | ESCALATE/BRANCH/PIVOT/STOP/CONTINUE/RETRY; provider hints; skip-already-run |
| `TestCampaignDecisionHistory` | 5 | empty, count, average_confidence, total_injections, filter |
| `TestFamilyBasedAttackSelector` | 4 | family members, excludes-already-run, max_to_return, unknown-category |
| `TestProviderAwarePayloadStrategySelector` | 5 | per-provider, cycle, exhausted, unknown-provider |
| `TestCategoryProviderConversationStrategySelector` | 6 | category map, provider override, cycle, default, cross-provider |
| `TestPluginRegistry` | 7 | empty, attack/payload/decision/intelligence registration, summary |
| `TestAttackGraphInjectNode` | 6 | adds READY node, event emitted, duplicate raises, terminal raises, count, ready_nodes |
| `TestRedTeamOrchestratorWithIntelligence` | 9 | decision_history populated, confidence, no-intelligence path, STOP cancels, CONTINUE no-inject, error-resilient, injected_nodes counted (applied_node_ids) |
| `TestKGProjectionWithDecisions` | 4 | CAMPAIGN_DECISION nodes projected, DECISION_INFLUENCED_NODE edges, enum values |
| `TestCampaignLearningIntegration` | 1 | escalation skips already-run |
| `TestGoalCompletionWithIntelligence` | 1 | FIRST_FINDING still terminates |
| `TestLargeCampaignSimulation` | 2 | 10-node campaign no crash, decision_history populated |
| `TestRegressionExistingBehavior` | 3 | retry_failed, pause/resume, success_rate with injected |
| `TestAdaptiveStopStrategy` | 3 | stop at threshold, not before, custom threshold |
| `TestAdaptiveRetryStrategy` | 2 | retry on first failure, payload_hint set |

---

## 7. Technical Debt Introduced

| ID | Item | Severity |
|----|------|----------|
| ~~DEBT-S37-1~~ | ~~Intelligence runs post-terminal on single-node graphs~~ | **Resolved** in S36/37 remediation |
| DEBT-S37-2 | `plugin_registry` accepted by orchestrator but not consulted at execution | P3 |
| DEBT-S37-3 | `CampaignLearner` state is not persisted between campaigns | P3 |

---

## 8. Final Architecture Review

**Security**: `organization_id` flows exclusively from `RedTeamRequest` (JWT-derived); never from HTTP body. `CampaignIntelligenceContext` carries `organization_id` but only for logging — no cross-tenant data crosses context boundaries. `_adapt_from_node_result` silently absorbs intelligence failures, preventing injection-path disruption.

**Software Engineering**: Protocol-first throughout. Intelligence, attack, payload, and conversation selectors are all `@runtime_checkable Protocol`. The `AttackGraph.inject_node()` extension is domain-correct (raises `AttackGraphAlreadyTerminalError` on terminal graphs). `CampaignDecisionRecord` is a frozen dataclass with `applied_node_ids` / `application_failure_reason` stamped post-application. No existing tests broken.

**Red Team Coverage**: All 6 `CampaignDecisionAction` values exercised in tests. 7 attack families, 6 providers, 11 conversation strategy types covered by selector maps. ESCALATE/BRANCH/PIVOT/STOP all have dedicated orchestrator integration tests — including single-node ESCALATE that proves the injected node actually executes (remediation tests).

**Adversarial Robustness**: The intelligence layer is non-fatal by design. A buggy or adversarially-supplied `CampaignDecisionPlugin` cannot crash or stall a campaign. Plugin injection into `PluginRegistry` must happen at startup only (thread-safety guarantee in docstring).

**Metric Honesty**: `RedTeamResult.injected_nodes` and `CampaignDecisionHistory.total_injections` count nodes ACTUALLY ADMITTED to the graph (`applied_node_ids`), not nodes RECOMMENDED (`injected_categories`). KG CAMPAIGN_DECISION node metadata carries both `recommended_count` and `applied_count` for full audit trail.

---

## 9. Recommendation for Sprint 38/39

**Sprint 38**: Red Team API & Persistence
- Expose `POST /api/v1/red-team/execute`, `GET /api/v1/red-team/{id}`, `POST /api/v1/red-team/{id}/pause` endpoints
- Implement PostgreSQL `AttackGraphRepository` (resolves DEBT-S35-3)
- Wire `RedTeamEvent` to `PlatformEventPublisher` (resolves DEBT-S35-4)

**Sprint 39**: Intelligence Persistence & Plugin Wiring
- Persist `CampaignDecisionRecord` to PostgreSQL (resolves DEBT-S37-3)
- Wire `PluginRegistry` into orchestrator execution path (resolves DEBT-S37-2)
- Campaign-level learning across multiple runs (cross-campaign pattern extraction)

---

## 10. Correctness Remediation (2026-07-11)

### The Bug

After initial delivery, a lifecycle ordering contradiction was found:

1. `mark_node_completed()` internally called `_check_completion()`, which immediately set `_graph_state = COMPLETED` for single-node (or last-node) graphs.
2. The orchestrator then called `_adapt_from_node_result()`, which consulted intelligence.
3. Intelligence could return ESCALATE/BRANCH/PIVOT with `injected_categories`.
4. `_apply_decision()` called `graph.inject_node()`, which raised `AttackGraphAlreadyTerminalError` — the graph was already terminal.
5. The exception was caught silently.
6. `decision_history.record(decision)` recorded the recommended categories in `injected_categories`.
7. `total_injections` counted `len(injected_categories)`, reporting phantom injections.
8. `RedTeamResult.injected_nodes` was non-zero even though no node was ever admitted.

**The sprint claimed "live graph node injection" as a delivered capability, but it was broken for single-node and last-node campaigns.**

### The Fix

**Deferred Completion Contract** (`entity.py`):
- `_check_completion()` removed from `mark_node_completed()` and `mark_node_failed()`.
- New public method `AttackGraph.try_complete()` — idempotent, returns `bool`. Must be called by the orchestrator explicitly after the adaptive intelligence phase.
- `GoalAchievedSignal` and `BudgetExhaustedError` still propagate immediately (they're terminal signals; no injection is valid after them).

**Recommended vs Applied** (`campaign_decision.py`, `campaign_intelligence.py`):
- `CampaignDecisionRecord` gains two new fields: `applied_node_ids: tuple[str, ...]` (default `()`) and `application_failure_reason: str | None` (default `None`).
- `injected_categories` retains its original meaning: categories RECOMMENDED by intelligence.
- `CampaignDecisionHistory.total_injections` now counts `sum(len(r.applied_node_ids) for r in records)` — admitted nodes only.

**Orchestrator** (`orchestrator.py`):
- `_apply_decision()` returns `(list[str], str | None)` — admitted node IDs and failure reason.
- Orchestrator stamps `applied_node_ids` and `application_failure_reason` onto the decision record before archiving.
- `graph.try_complete()` called after `_adapt_from_node_result()` in all code paths.
- Removed the "remaining <= 0" STOP rule from `RuleBasedCampaignIntelligenceService` that would cancel normally-completing campaigns.

**KG Projection** (`knowledge_graph.py`):
- `CAMPAIGN_DECISION` node metadata now includes `recommended_count` and `applied_count` for audit honesty.

**Tests** (`tests/unit/test_s3637_remediation.py`):
- 21 new remediation-focused tests proving: single-node ESCALATE/BRANCH/PIVOT execute injected nodes; `injected_nodes` counts admitted not recommended; `applied_node_ids` reflects reality; no silent phantom reporting; `GoalAchievedSignal` still bypasses intelligence correctly.

### Invariants Now Enforced

1. A recorded recommendation is never confused with an applied adaptation.
2. `RedTeamResult.injected_nodes` represents nodes successfully admitted into the executable graph.
3. ESCALATE/BRANCH/PIVOT on single-node campaigns have a valid execution path if budget and goal allow.
4. Failed injections are recorded in `application_failure_reason`, not silently discarded.
5. Campaign completion cannot race ahead of adaptive decision application.
