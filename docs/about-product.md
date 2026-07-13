# AIVAR RedForge — Product & Architecture Document

**Classification**: Internal Engineering  
**Version**: 1.0  
**Last Updated**: 2026-07-08  
**Audience**: Engineering team, AI coding agents, architecture reviewers  

---

## 1. Product Vision

### What is AIVAR RedForge?

AIVAR RedForge is an **Enterprise Continuous AI Security Validation & AI Red Teaming Platform**. It validates the security posture of AI systems — LLM applications, AI agents, RAG systems, MCP servers, multi-agent workflows, and any AI-powered service — through automated, continuous, and intelligent security testing.

### Why does it exist?

Every enterprise deploying AI systems faces a new attack surface that traditional security tools cannot address. Prompt injection, jailbreaks, data exfiltration through conversational interfaces, tool abuse in agentic systems, and RAG poisoning are fundamentally different from web application vulnerabilities. They require purpose-built security validation infrastructure.

### What problems does it solve?

1. **Continuous AI security posture management** — not one-time pentests
2. **Automated red teaming at enterprise scale** — thousands of attacks across hundreds of targets
3. **Provider-agnostic validation** — same framework tests OpenAI, Anthropic, local models, MCP servers
4. **Compliance-driven security objectives** — map validation results to OWASP, MITRE ATLAS, SOC2, ISO 27001
5. **Intelligence-driven testing** — the platform learns from results and adapts attacks
6. **Enterprise multi-tenancy** — isolated, auditable, governed

### How is it different?

| Tool | Nature | RedForge Difference |
|------|--------|-------------------|
| **Traditional pentest** | Manual, point-in-time, human-driven | Automated, continuous, scalable |
| **Vulnerability scanners** (Nessus, Qualys) | Network/infra focused, signature-based | AI-interaction focused, behavioral |
| **Promptfoo** | Developer tool, single-model evaluation | Enterprise platform, multi-tenant, multi-provider, continuous |
| **NVIDIA Garak** | Research probe scanner, single-target | Enterprise orchestration, policy-driven, compliance-mapped |
| **Azure PyRIT** | Research framework, manual scripting | Production platform, automated execution, lifecycle management |
| **OpenAI Evals** | Internal evaluation harness | External validation, adversarial testing, enterprise governance |
| **Wiz / CrowdStrike** | Cloud/endpoint security | AI-specific attack surface, LLM interaction security |
| **Protect AI / Lakera** | AI security point solutions | Full-lifecycle platform with execution engine, not just detection |

RedForge is not a wrapper around LLM APIs. It is not a prompt testing utility. It is not a vulnerability scanner with AI bolted on. It is a purpose-built enterprise security platform for the AI era.

---

## 2. Long-Term Mission

### 5–10 Year Vision

Become one of the world's leading AI Security Platforms — the enterprise standard for continuous AI security validation, analogous to what CrowdStrike became for endpoint security or Wiz became for cloud security.

### Strategic positioning

RedForge synthesizes architectural ideas from the best in each domain:

- **From OpenAI/Anthropic**: Deep understanding of model behavior, evaluation methodology, safety science
- **From Wiz/CrowdStrike**: Enterprise security product architecture, real-time posture management, executive reporting
- **From Palo Alto/Zscaler**: Platform thinking, integrated security ecosystem, policy-driven enforcement
- **From NVIDIA/Google**: Scale engineering, distributed execution, ML-driven intelligence

The goal is not to copy any of them. The goal is to build the AI security platform that all of them would need if they were building it today as an enterprise product.

### Evolution trajectory

```
Today: Automated AI red teaming
Year 2: Continuous AI security posture management
Year 3: AI security intelligence platform
Year 5: Autonomous AI security validation
Year 10: AI system governance and safety infrastructure
```

---

## 3. Engineering Philosophy

### Non-negotiable principles

| Principle | Meaning |
|-----------|---------|
| **Domain Driven Design** | Business concepts are modeled as rich domain objects with behavior, not anemic data structures |
| **Clean Architecture** | Dependencies point inward. Domain knows nothing about infrastructure. |
| **SOLID** | Single responsibility, open/closed, Liskov substitution, interface segregation, dependency inversion |
| **Repository Pattern** | Persistence is abstracted behind repository protocols. Domain never knows about SQL. |
| **UnitOfWork** | Transaction boundaries are owned by a single coordinator, never by repositories |
| **Protocol-first** | Every extension point is a Python Protocol. Implementations are injected. |
| **Dependency Inversion** | High-level modules define contracts. Low-level modules implement them. |
| **Plugin-first** | Every capability is designed to be replaceable by customers without modifying core |
| **Multi-provider** | No assumption about which AI provider is used. OpenAI, Anthropic, local models all equal. |
| **Multi-tenant** | Every data path is organization-scoped. No data leakage between tenants. |
| **Event-driven evolution** | Bounded contexts communicate via domain events. Eventual consistency is acceptable. |
| **Long-term maintainability** | Optimize for 10-year code lifespan, not today's velocity |

### Non-negotiable rules

1. Business logic MUST live in domain or application layer. Never in FastAPI routes, SQLAlchemy models, middleware, or infrastructure.
2. Domain entities MUST NOT import from infrastructure or API layers.
3. Every new capability MUST be behind a protocol. No concrete dependencies in business logic.
4. No switch statements for type dispatch. Use polymorphism or registry patterns.
5. Evidence is immutable once finalized. No exceptions.
6. All state changes emit domain events. Events are the integration mechanism.
7. Tests run without external dependencies (no real DB, no real AI APIs needed).

---

## 4. Architecture Principles

### Layer responsibilities

```
┌─────────────────────────────────────────────────────────┐
│ API Layer (src/redforge/api/)                            │
│ - HTTP endpoints (FastAPI routers)                       │
│ - Request/response serialization (Pydantic)              │
│ - Dependency injection wiring                            │
│ - Authentication middleware                              │
│ - NEVER contains business logic                          │
└─────────────────────────┬───────────────────────────────┘
                          │ calls
┌─────────────────────────▼───────────────────────────────┐
│ Application Layer (src/redforge/application/)             │
│ - Use case orchestration                                 │
│ - Coordination between domain objects                    │
│ - Transaction boundaries (UnitOfWork)                    │
│ - Application services (stateless)                       │
│ - Runtime engines (execution, evaluation, scenarios)     │
│ - Event publishing                                       │
└─────────────────────────┬───────────────────────────────┘
                          │ uses
┌─────────────────────────▼───────────────────────────────┐
│ Domain Layer (src/redforge/domain/)                       │
│ - Entities (aggregate roots with identity)               │
│ - Value objects (immutable, equality by value)           │
│ - Domain events                                          │
│ - Repository protocols (ports)                           │
│ - Domain services (stateless business rules)             │
│ - Exceptions                                             │
│ - ZERO infrastructure imports                            │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ Infrastructure Layer (src/redforge/infrastructure/)       │
│ - Repository implementations (SQLAlchemy)                │
│ - Provider adapters (OpenAI, Anthropic, etc.)           │
│ - Authentication (Argon2, JWT)                          │
│ - Middleware (correlation, metrics, security)            │
│ - Telemetry (OpenTelemetry, Prometheus)                 │
│ - Audit logging                                         │
│ - Rate limiting                                          │
│ - Database (engine, migrations, models)                  │
│ - External service adapters                              │
└─────────────────────────────────────────────────────────┘
```

### What must NEVER happen

- Business logic in FastAPI route handlers
- Domain entities importing SQLAlchemy
- Infrastructure deciding business rules
- Repositories calling commit() or rollback()
- Middleware containing domain logic
- Provider-specific behavior in the domain layer
- Direct instantiation of infrastructure classes in application services

---

## 5. Current Platform Architecture

### Bounded Context Map

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    BOUNDED CONTEXTS                                       │
├──────────────────────┬──────────────────────────────────────────────────┤
│ Organizations        │ Multi-tenant: orgs, membership, billing           │
│ Identity             │ Users, authentication, authorization              │
│ AI Targets           │ Systems under test, capabilities, lifecycle       │
│ Attack Library       │ Reusable attack definitions, versioning, taxonomy │
│ Payloads             │ Template rendering, variable substitution         │
│ Policies             │ Compose attacks, define strategy and triggers     │
│ Execution            │ Runtime plans, stages, steps, DAG ordering        │
│ Validations          │ Run lifecycle (scheduled → completed)             │
│ Evidence             │ Immutable interaction records                     │
│ Findings             │ Security assessments derived from evidence        │
│ Providers            │ Registered AI provider adapters                   │
│ Knowledge            │ Accumulated intelligence graph                    │
│ Risk                 │ Correlation, scoring, incidents                   │
└──────────────────────┴──────────────────────────────────────────────────┘
```

### Runtime Execution Pipeline

```
ValidationOrchestrator (thin coordination)
    ├── ExecutionDispatcher (traverse DAG, dispatch steps)
    │       └── StepExecutor (execute one attack → capture evidence)
    │               └── Provider Adapter (transport to AI target)
    └── ResponseClassifier / EvaluationPipeline (determine pass/fail)
```

### Attack Execution Engine

```
AttackPipelineRunner
    ├── AttackExecutionStrategy (determines flow: single-turn, multi-turn, agent)
    ├── PayloadGenerator (selects/creates payloads)
    ├── PromptRenderer (template → rendered content)
    └── ConversationBuilder (rendered content → message array)
```

### Evaluation Engine

```
EvaluationPipeline (implements ResponseClassifier protocol)
    ├── Evaluator[] (Keyword, Pattern, Rule — future: LLM Judge, ML)
    ├── ConfidenceAggregator (weighted average, majority vote)
    └── FindingCandidateGenerator (evaluation → finding candidate)
```

### Scenario Engine

```
ScenarioRunner
    ├── ScenarioDefinition (what to validate: objectives, criteria)
    ├── AttackResolver (resolve categories → executable steps)
    └── SuccessCriteria (evaluate: did the scenario pass?)
```

---

## 6. Product Capability Map

### Implemented

| Capability | Status | Location |
|-----------|--------|----------|
| Multi-tenant Organizations | Complete | `domain/organizations/` |
| User Authentication (Argon2id + JWT) | Complete | `infrastructure/auth/` |
| AI Target Management | Complete | `domain/ai_targets/` |
| Attack Library (versioned, lifecycle-managed) | Complete | `domain/attack_library/` |
| Validation Policies | Complete | `domain/policies/` |
| Payload Templates (rendering) | Complete | `domain/payloads/` |
| Execution DAG (parallel/sequential/conditional) | Complete | `application/execution_graph.py` |
| Execution Plans (stages, steps, retry, timeout) | Complete | `domain/execution/` |
| ValidationRun lifecycle | Complete | `domain/validations/` |
| Evidence (immutable, finalization) | Complete | `domain/evidence/` |
| Findings (lifecycle, compliance refs) | Complete | `domain/findings/` |
| Provider Framework (OpenAI adapter) | Complete | `infrastructure/providers/` |
| Runtime Orchestrator | Complete | `application/runtime/orchestrator.py` |
| In-Process Dispatcher | Complete | `application/runtime/dispatcher.py` |
| Chat Completion Executor | Complete | `application/runtime/executors.py` |
| Keyword Classifier | Complete | `application/runtime/classifiers.py` |
| Attack Execution Engine | Complete | `application/runtime/attacks/` |
| Evaluation Pipeline | Complete | `application/runtime/evaluation/` |
| Scenario Engine (5 profiles) | Complete | `application/scenarios/` |
| Risk Correlation Engine | Complete | `application/risk_engine.py` |
| Knowledge Graph | Complete | `application/knowledge_graph.py` |
| Structured Logging (JSON) | Complete | `core/logging.py` |
| Prometheus Metrics | Complete | `infrastructure/middleware/metrics.py` |
| OpenTelemetry (configurable) | Complete | `infrastructure/telemetry/` |
| Audit Logging | Complete | `infrastructure/audit/` |
| Rate Limiting | Complete | `infrastructure/rate_limiting/` |
| Security Headers | Complete | `infrastructure/middleware/security_headers.py` |
| CORS | Complete | `app.py` |
| Health/Readiness Endpoints | Complete | `api/v1/health.py` |
| CI/CD Pipeline (GitHub Actions) | Complete | `.github/workflows/ci.yml` |
| Alembic Migrations (10 tables) | Complete | `infrastructure/database/migrations/` |
| Docker (multi-stage, non-root) | Complete | `Dockerfile` |

### Planned (next sprints)

| Capability | Design Status |
|-----------|--------------|
| Security Objective Framework | ADR complete (ADR-002) |
| Threat Coverage Resolver | Designed |
| Compliance Mapping Engine | Designed |
| LLM-as-Judge Evaluator | Designed |
| Multi-Turn Attack Strategy | Protocol exists |
| Queue-based Distributed Dispatcher | Protocol exists |
| Campaign Engine | Conceptual |
| Continuous Validation Scheduler | Conceptual |
| Executive Reporting | Conceptual |
| Plugin SDK | Conceptual |

### Future Vision

| Capability | Timeline |
|-----------|----------|
| Autonomous AI Red Teaming (adaptive) | Year 2 |
| Agent-to-Agent attack validation | Year 2 |
| MCP Server security validation | Year 2 |
| AI Supply Chain Security | Year 2-3 |
| AI Security Intelligence (ML-driven) | Year 3 |
| Autonomous Governance Platform | Year 5+ |

---

## 7. AI Security Model

The platform's security model follows this hierarchy:

```
Security Domain (the broadest scope: "AI System Security")
    │
    ▼
Security Objectives (stable: what properties must hold)
    │  e.g., Prompt Integrity, Data Confidentiality, Tool Safety
    │
    ▼
Threat Coverage (which objectives are being tested)
    │  Maps objectives → attack categories dynamically
    │
    ▼
Attack Categories (volatile: taxonomy of techniques)
    │  e.g., prompt_injection, jailbreak, rag_poisoning
    │
    ▼
Attack Definitions (individual reusable techniques)
    │  Versioned, lifecycle-managed, provider-aware
    │
    ▼
Payload Templates (how to express attacks for a target)
    │  Rendered with context at execution time
    │
    ▼
Execution (runtime: dispatch, execute, capture)
    │
    ▼
Evidence (immutable record of what happened)
    │
    ▼
Evaluation (intelligence: what does the evidence mean)
    │
    ▼
Findings (security assessment: what vulnerabilities exist)
    │
    ▼
Risk Correlation (aggregate: how severe is the overall posture)
    │
    ▼
Compliance Mapping (governance: which controls are satisfied)
    │
    ▼
Executive Reporting (business: is the AI system safe to deploy)
```

**Why this model**: Security objectives are stable for decades (like CIA triad). Attack techniques evolve monthly. By placing a stable abstraction (objectives) above a volatile implementation (attacks), we ensure scenarios and compliance reporting don't break as the attack library grows.

---

## 8. Reference Architecture

### AI Platforms (execution targets)

| Platform | What RedForge learns |
|----------|---------------------|
| OpenAI | Chat completion API patterns, function calling, tool use protocols |
| Anthropic | Safety evaluation methodology, constitutional AI constraints |
| Google Vertex AI | Enterprise deployment patterns, model garden diversity |
| Azure OpenAI | Enterprise security controls, managed deployment |
| AWS Bedrock | Multi-model routing, enterprise IAM integration |

### Agent Frameworks (validation targets)

| Framework | What RedForge learns |
|-----------|---------------------|
| LangGraph | Stateful agent execution, graph-based orchestration patterns |
| CrewAI | Multi-agent collaboration, role-based agent design |
| AutoGen | Conversational agent patterns, code execution agents |
| MCP | Tool serving protocol, resource management, server security |
| Google ADK | Agent development kit patterns, tool integration |

### AI Security (competitive landscape + architectural inspiration)

| Tool | Architectural Pattern Learned |
|------|-------------------------------|
| Azure PyRIT | Orchestrator/target/scorer separation, memory-backed probing |
| NVIDIA Garak | Probe-based scanning, generator/detector pattern |
| Promptfoo | Assertion-based evaluation, dataset-driven testing |
| DeepTeam | Attack taxonomy structure, metric-based scoring |
| UK AISI Inspect | Task/solver/scorer architecture, structured evaluation |
| Protect AI | ML model security scanning, supply chain focus |
| Lakera | Real-time prompt injection detection, guard patterns |
| LangSmith/Langfuse | Trace-based observability, evaluation datasets |

### Enterprise Security (product architecture patterns)

| Platform | Pattern Learned |
|----------|-----------------|
| Wiz | Graph-based context, finding → risk → priority pipeline |
| CrowdStrike Falcon | Continuous monitoring, threat intelligence integration |
| Palo Alto Cortex | SOAR orchestration, playbook-driven response |
| Microsoft Defender | Multi-signal correlation, unified security posture |
| Zscaler | Zero-trust architecture, policy-driven enforcement |

### Standards (compliance and taxonomy)

| Standard | Usage in RedForge |
|----------|-------------------|
| OWASP GenAI Top 10 | Primary attack category mapping |
| OWASP Agentic AI | Agent-specific threat taxonomy |
| MITRE ATLAS | Technique IDs for findings, framework mapping |
| NIST AI RMF | Risk management vocabulary |
| OpenTelemetry GenAI | Trace semantics for AI interactions |

---

## 9. Architecture Decision Records

### ADR-001: Execution Architecture (Sprint 4-5)

**Decision**: The Validation Engine is NOT a new bounded context. It is thin application-layer orchestration coordinating existing domain objects.

**Reasoning**: The domain already models attacks (Attack Library), execution plans (Execution), evidence (Evidence), and findings (Findings). Adding a "Validation Engine" domain would duplicate all of these. The missing piece was runtime glue — orchestrator, dispatcher, executor, classifier — which belongs in the application layer.

**Consequence**: All runtime code lives in `application/runtime/`. No new domain entities were created. The Sprint 4 "validation_engine" module was deleted after the ADR showed it duplicated AttackDefinition, categories, and lifecycle concepts.

### ADR-002: Security Objective Framework (Sprint 8+)

**Decision**: Introduce Security Objectives as a Shared Kernel. Scenarios reference objectives (stable) instead of attack categories (volatile).

**Reasoning**: Enterprise customers think in security outcomes ("is my data safe?") not attack techniques ("did we run prompt_injection?"). Objectives are stable for decades; attack techniques change monthly. The mapping layer absorbs change.

**Consequence**: Scenarios gain `security_objectives` field. A ThreatCoverageResolver maps objectives → categories dynamically. New attacks auto-apply to scenarios via their objective tags. Zero breaking changes to existing architecture.

---

## 10. Roadmap

```
COMPLETED                              IN PROGRESS / NEXT
─────────────────────────────────────  ─────────────────────────────────────
Foundation (DDD, Clean Arch, DB)        Security Objective Framework
├── Organizations, Identity             Threat Coverage Resolver
├── AI Targets, Attack Library          LLM-as-Judge Evaluator
├── Policies, Payloads                  Multi-Turn Strategy
├── Execution, Evidence, Findings       Compliance Mapping
│                                       Queue-based Dispatcher
Production Hardening
├── Argon2id, JWT, Rate Limiting       FUTURE
├── Prometheus, OpenTelemetry          ─────────────────────────────────────
├── Audit Logging, CI/CD               Campaign Engine
├── Docker, Migrations                 Continuous Validation Scheduler
│                                       Executive Reporting
Runtime Engine                          Plugin SDK
├── Orchestrator, Dispatcher           Agent-to-Agent Validation
├── StepExecutor, Classifier           MCP Server Validation
│                                       Autonomous Red Teaming
Attack Execution Engine                AI Security Intelligence
├── Strategy, Generator, Renderer      Knowledge Graph Intelligence
├── ConversationBuilder, Adapter       Risk Prediction
│                                       Autonomous Governance
Evaluation Engine
├── Pipeline, Evaluators (3)
├── Aggregators (2), FindingGenerator

Scenario Engine
├── Profiles (5), SuccessCriteria
├── CapabilityResolution, Runner
```

**Why this order**: Foundation first (you can't execute attacks without a domain model). Then runtime (you can't evaluate without executing). Then evaluation (you can't report without classifying). Then scenarios (enterprise customers need business-level abstractions over technical internals). Security objectives next (compliance and reporting need stable abstractions over volatile attacks).

---

## 11. Coding Rules for AI Agents

Any AI coding assistant working on this repository MUST:

1. **Read this document first** before proposing any architectural change.
2. **Inspect existing code** before creating new modules. The concept you want to add may already exist.
3. **Never duplicate bounded contexts**. If `AttackDefinition` already models something, do not create `ValidationDefinition` with the same fields.
4. **Never introduce parallel models**. One source of truth for each concept.
5. **Never violate DDD layer boundaries**. Domain imports nothing from infrastructure or API.
6. **Prefer extension over modification**. Add a new protocol implementation; don't rewrite existing ones.
7. **Preserve protocol-first architecture**. Every new capability must be behind a protocol.
8. **Produce ADRs before major changes**. If a change affects bounded context boundaries, produce an ADR first. Then implement.
9. **Verify claims with executed evidence**. Run pytest, ruff, mypy. Never claim something works without running it.
10. **Use existing domain events**. Don't bypass the event system with direct calls between contexts.
11. **Keep orchestrators thin**. Application services coordinate; they do not contain business rules.
12. **Immutability by default**. Value objects are frozen dataclasses. Evidence is append-only. Context objects are read-only.

### Common mistakes to avoid

- Creating a "ValidationEngine" bounded context (the runtime IS the validation engine)
- Creating `ValidationDefinition` (use `AttackDefinition` from Attack Library)
- Creating `ValidationCategory` (use `AttackCategory`)
- Creating a "plugin registry" (the Attack Library repo IS the registry)
- Putting classification logic in the executor (classifier is a separate protocol)
- Putting business rules in middleware (middleware is infrastructure)
- Hardcoding provider behavior in domain logic (use provider adapters)

---

## 12. Quality Expectations

This platform is designed to be maintained and extended for 10+ years. Every change must meet:

| Dimension | Standard |
|-----------|----------|
| **Correctness** | All tests pass. mypy strict. ruff clean. |
| **Extensibility** | New capabilities via new protocol implementations, not modifications |
| **Maintainability** | Clear bounded contexts. Single responsibility. Readable code. |
| **Scalability** | Supports 10,000+ attacks, 1000+ scenarios, millions of executions |
| **Security** | Argon2id passwords, JWT with rotation, rate limiting, audit trails |
| **Observability** | Structured logging, Prometheus metrics, OpenTelemetry traces, correlation IDs |
| **Developer Experience** | Fast tests (<5s for unit), clear error messages, protocol-based mocking |

### Current verification baseline

```
pytest:  1132 tests passing, 5 skipped (Postgres-only)
ruff:    All checks passed
mypy:    Success (strict mode)
```

---

## 13. Current Status

### Completed (Sprints 1-8)

| Sprint | Delivered |
|--------|-----------|
| 1 | Risk Correlation Engine, Knowledge Graph |
| 2 | REST API (48 endpoints), Bounded-context service split |
| 3 | Infrastructure hardening (UnitOfWork, transaction ownership) |
| 4 | Production readiness (pytest fixed, mypy, migrations, Docker, metrics, security) |
| 5 | Enterprise auth (Argon2id, PyJWT, rate limiting, OpenTelemetry, audit, CI/CD) |
| 6 | Runtime vertical slice (orchestrator, dispatcher, executor, classifier) |
| 7 | Attack Execution Engine (strategy, generators, renderer, conversation builder) |
| 8 | Evaluation Engine (multi-evaluator pipeline, aggregation, finding candidates) |
| 8b | Scenario Engine (profiles, capability matching, success criteria, runner) |

### Architecture reviews completed

- ADR-001: Execution architecture (thin orchestrator, not new bounded context)
- ADR-002: Security Objective Framework (shared kernel, stable over volatile)

### Remaining major milestones

1. Security Objective Framework implementation
2. Threat Coverage Resolver
3. LLM-as-Judge Evaluator
4. Multi-turn attack strategies
5. Compliance mapping engine
6. Queue-based distributed execution
7. Campaign engine (multi-scenario orchestration)
8. Continuous validation scheduler
9. Executive reporting
10. Plugin SDK for customers

---

## 14. Anthropic Cybersecurity Program

AIVAR RedForge should leverage capabilities available through the organization's verified participation in the Anthropic Cybersecurity Program where appropriate and within Anthropic's policies and documentation.

### Guidelines

- When implementing provider-specific functionality for Anthropic models, prefer official Anthropic guidance, SDKs, APIs, and security capabilities before designing custom abstractions.
- Use Anthropic's recommended practices for model safety evaluation, red teaming methodology, and security assessment.
- Do not hardcode provider-specific behavior into the domain model. Keep Anthropic integrations behind provider interfaces (the existing `ProviderAdapter` protocol) so the platform remains multi-provider.
- When Anthropic publishes new security evaluation capabilities, assess them for integration as evaluator implementations behind the existing `Evaluator` protocol.
- Treat Anthropic's security research publications as input to RedForge's attack library and evaluation methodology — not as the sole source of truth.

---

## 15. Future AI Agent Instructions

### What this project IS

- An enterprise AI Security Platform designed to evolve over the next decade
- A product that should compete architecturally with platforms built by OpenAI, Anthropic, Microsoft, Google, CrowdStrike, and Wiz
- A system where correctness and extensibility matter more than velocity
- A living architecture that accumulates intelligence over time

### What this project is NOT

- A demo or prototype
- An MVP (it is past MVP — it is in architectural hardening phase)
- A CRUD application
- A wrapper around LLM APIs
- A single-use pentesting tool
- A research project without production constraints

### How to work on this codebase

1. **Start by reading this document.** Understand the vision, architecture, and constraints.
2. **Inspect existing code before proposing.** The repository has 200+ source files across 13 bounded contexts. What you want to build may already exist.
3. **Produce an ADR for major changes.** If your proposal affects bounded context boundaries, event flows, or the execution pipeline — write the architecture first, implement second.
4. **Run verification after every change.** `pytest`, `ruff check`, `mypy --strict`. No exceptions.
5. **Preserve backward compatibility.** Existing tests must continue to pass. Protocols must not gain breaking changes.
6. **Think in decades, not days.** Every protocol, every value object, every bounded context decision will be lived with for years. Make it right.

---

*This document is the single source of truth for AIVAR RedForge's architecture, philosophy, and engineering standards. All future implementation decisions must be consistent with this document. If a conflict is discovered, produce an ADR explaining the proposed deviation before implementing.*
