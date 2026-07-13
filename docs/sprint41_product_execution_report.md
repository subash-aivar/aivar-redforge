# Sprint 41 — Product Execution Validation Report

**Date**: 2026-07-08  
**Classification**: CONTROLLED-BOUNDARY EXECUTABLE PRODUCT  

---

## Quality Gates (Final)

| Gate | Result |
|------|--------|
| ruff | All checks passed |
| mypy --strict | Success: no issues in 449 source files |
| pytest | **3338 passed, 5 skipped** (35.77s) |

---

## Production Bugs Found and Fixed

| # | Bug | Impact | Fix |
|---|-----|--------|-----|
| 1 | `TriggerType` missing `RED_TEAM = "red_team"` | `ValidationService.execute()` crashes constructing `ValidationRun` | Added enum value to `domain/validations/value_objects.py` |
| 2 | `RedTeamOrchestratorFactory` wired `KeywordClassifier` into `EvaluationPipeline` evaluators list | `EvaluationPipeline` exception handler accesses `evaluator.name` which `KeywordClassifier` doesn't have → `AttributeError` masks original error | Replaced with `KeywordEvaluator` (correct protocol implementation) |
| 3 | `EvaluationPipeline` exception handler accesses `evaluator.name` unsafely | If evaluator lacks `.name` property, error reporting raises secondary `AttributeError` masking the original failure | Fixed with `getattr(evaluator, "name", type(evaluator).__name__)` |
| 4 | Sprint 41 tests used invalid EntityId strings (`"org-test"`, `"tgt-payload"`) | `EntityId.from_string()` requires valid 26-char ULIDs | Replaced with valid ULIDs |
| 5 | Tests assumed `httpx.ASGITransport` triggers ASGI lifespan | It does not — `app.state.runtime` must be set manually for tests | Documented; tests use `_make_app_with_runtime()` explicitly |

---

## 17-Category Verification Matrix

| # | Category | Status | Evidence |
|---|----------|--------|----------|
| 1 | REAL ASGI BOOT | VERIFIED_CONTROLLED_BOUNDARY | App created via `create_app(settings)`, all middleware registered, routes mounted. Lifespan not triggered by ASGITransport (documented limitation). |
| 2 | REAL FASTAPI ROUTE | VERIFIED_REAL | `POST /api/v1/red-team/campaigns` returns 201 through real FastAPI routing. |
| 3 | REAL JWT / TENANT CONTEXT | VERIFIED_REAL | `JWTTokenService` mints real JWT; `TenantContext` extracts org_id from token. Unscoped tokens rejected (401/403). |
| 4 | REAL RUNTIME CONTAINER | VERIFIED_REAL | `build_runtime_container(settings)` constructs real `RuntimeContainer` with `RedTeamOrchestratorFactory`. |
| 5 | REAL RED TEAM FACTORY | VERIFIED_REAL | `RedTeamOrchestratorFactory()` constructs with real `EvaluationPipeline`, `ConsensusEngine`, `EvaluationPolicyEnforcer`, `AttackLibraryResolver`. |
| 6 | REAL ATTACK GRAPH | VERIFIED_REAL | `RedTeamOrchestrator.execute()` builds real `AttackGraph` with nodes per attack category. Multi-node graph verified (2+ nodes). |
| 7 | REAL VALIDATION SERVICE | VERIFIED_REAL | `ValidationService` executes with real `ChatCompletionExecutor`, real `EvaluationPipeline`, real `AttackLibraryResolver`. |
| 8 | REAL CHAT COMPLETION EXECUTOR | VERIFIED_REAL | `ChatCompletionExecutor` constructs messages and calls `provider_adapter.chat_completion()`. |
| 9 | CONTROLLED PROVIDER BOUNDARY | VERIFIED_CONTROLLED_BOUNDARY | `ControlledProviderAdapter` intercepts at the HTTP boundary. Records all calls. Returns structured responses. |
| 10 | REAL EVALUATION PIPELINE | VERIFIED_REAL | `EvaluationPipeline` runs `KeywordEvaluator`, aggregates via `WeightedAverageAggregator`, applies consensus + policy. |
| 11 | REAL CONSENSUS ENGINE | VERIFIED_REAL | `ConsensusEngine` processes evaluator results within the pipeline. |
| 12 | REAL POLICY ENFORCER | VERIFIED_REAL | `EvaluationPolicyEnforcer` applies `STRICT_POLICY` gates. |
| 13 | REAL EVALUATION INTELLIGENCE | VERIFIED_REAL | `EvaluationDrivenIntelligenceAdapter` is wired via `ValidationService.with_evaluation_adapter()`. |
| 14 | REAL CAMPAIGN INTELLIGENCE | VERIFIED_REAL | `RuleBasedCampaignIntelligenceService` decides campaign actions based on node results. |
| 15 | REAL POSTGRESQL PERSISTENCE | BLOCKED_EXTERNAL_INFRASTRUCTURE | No PostgreSQL daemon available. No Docker. UoW is mocked at the persistence boundary. |
| 16 | REAL LIVE PROVIDER HTTP EXECUTION | BLOCKED_EXTERNAL_CREDENTIAL | No `OPENAI_API_KEY` or equivalent in environment. Provider boundary is controlled. |
| 17 | REAL RESTART RECOVERY | NOT_VERIFIED | Requires durable persistence (PostgreSQL) + process restart. |

---

## Blocker Analysis

### PostgreSQL (BLOCKED_EXTERNAL_INFRASTRUCTURE)

- **Dependency**: `asyncpg` driver, PostgreSQL-specific `JSONB` columns
- **Migration head**: `0004` (verified via `alembic heads`)
- **Production URL format**: `postgresql+asyncpg://user:pass@host:5432/redforge`
- **First blocked operation**: `UnitOfWork.__aenter__()` → `session_factory()` → `asyncpg.connect()`
- **Command to verify when available**:
  ```bash
  docker run -d --name redforge-pg -e POSTGRES_USER=redforge -e POSTGRES_PASSWORD=redforge -e POSTGRES_DB=redforge -p 5432:5432 postgres:16-alpine
  REDFORGE_DATABASE_URL=postgresql+asyncpg://redforge:redforge@localhost:5432/redforge alembic upgrade head
  pytest tests/integration/test_postgres_validation.py -v
  ```

### Live Provider (BLOCKED_EXTERNAL_CREDENTIAL)

- **Required**: `OPENAI_API_KEY` environment variable
- **Provider adapter**: `OpenAIAdapter` (base_url: `https://api.openai.com/v1`)
- **Transport boundary**: `httpx.AsyncClient.post("/chat/completions")`
- **Controlled boundary test** validates the exact point where execution would cross into live HTTP.

---

## Sprint 41 Test Inventory

| Category | Count | Purpose |
|----------|-------|---------|
| Application boot | 3 | Health, route registration, RuntimeContainer |
| Auth/tenant | 3 | JWT required, org-scoped, body isolation |
| Full HTTP campaign | 3 | E2E through FastAPI, org_id from JWT, error handling |
| Evaluation control loop | 4 | Pipeline execution, adapter wiring, multi-node graph |
| Tenant isolation | 2 | Cross-org namespace separation |
| Failure handling | 1+ | Provider exception → graceful degradation |
| Evaluator contract | 3 | Protocol satisfaction, adversarial broken evaluator, structural verification |
| **Total new (Sprint 41)** | **~20** | |

---

## Principal Review Verdict

| Question | Answer |
|----------|--------|
| Did the real ASGI app boot? | YES (via `create_app`, not lifespan — ASGITransport limitation) |
| Did the real FastAPI campaign route execute? | YES (201 response through real routing) |
| Did authentication and TenantContext execute? | YES (real JWT minting + validation) |
| Did RuntimeContainer composition execute? | YES (`build_runtime_container` with real factory) |
| Did RedTeamOrchestratorFactory execute? | YES (constructs real pipeline singletons) |
| Did ValidationService execute? | YES (builds steps, calls executor, runs evaluation) |
| Did ChatCompletionExecutor reach the provider boundary? | YES (controlled adapter records calls) |
| Did EvaluationPipeline execute? | YES (KeywordEvaluator runs, aggregation runs) |
| Did ConsensusEngine execute? | YES (within pipeline) |
| Did EvaluationPolicyEnforcer execute? | YES (STRICT_POLICY applied) |
| Did evaluation intelligence execute? | YES (adapter wired, modulates campaign) |
| Did CampaignIntelligenceService execute? | YES (decides campaign actions) |
| Did a real PostgreSQL transaction execute? | NO — BLOCKED_EXTERNAL_INFRASTRUCTURE |
| Did a live LLM provider HTTP request execute? | NO — BLOCKED_EXTERNAL_CREDENTIAL |
| Did restart persistence execute? | NO — requires PostgreSQL |

### Classification

**C. Controlled-boundary executable product**

The full application logic path executes end-to-end through real production code. Two external boundaries (database persistence, live LLM HTTP) are intercepted with controlled adapters. These are infrastructure blockers, not architectural gaps.

---

## Files Modified (This Sprint Continuation)

| File | Change |
|------|--------|
| `src/redforge/application/runtime/evaluation/pipeline.py` | Defensive fix: safe evaluator identity resolution in exception handler |
| `tests/unit/test_sprint41_product_execution.py` | Added 3 evaluator contract tests; fixed unused variable |

---

## Remaining Technical Debt

| Priority | Item |
|----------|------|
| P0 | Run full E2E with real PostgreSQL (requires Docker or hosted DB) |
| P0 | Run full E2E with real OpenAI API key |
| P1 | ASGI lifespan test using real lifespan context (not ASGITransport) |
| P2 | Restart recovery test (persist campaign state → kill → resume) |
