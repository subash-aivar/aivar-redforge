# AIVAR RedForge

Enterprise Continuous AI Security Validation and AI Red Teaming Platform — not a wrapper around LLM APIs, not a prompt-testing utility. AIVAR RedForge discovers, authorizes, validates, and continuously monitors the security posture of AI systems and their surrounding infrastructure, in the same spirit as CrowdStrike for endpoints or Wiz for cloud, but for AI.

## Current Status

**Milestones M1–M36 are COMPLETE** (migration head `0149`, single linear chain, verified `alembic heads`). The backend is organized as 34 bounded contexts under `backend/src/`. Full detail and per-milestone proof live in [`docs/PROJECT_CONTEXT.md`](docs/PROJECT_CONTEXT.md) and the milestone-specific reports/checkpoints under [`docs/`](docs/) — those documents currently describe the platform only through M22 and are due for a refresh; this README and the migration head above are the reliable source of truth for current state. This README is a high-level orientation, not a milestone log — do not add per-milestone history here.

Not every bounded context is production-hardened to the same degree yet. In particular: `incident` persists to PostgreSQL; twelve other M32–M36 contexts (`ml_pipeline`, `posture_forecasting`, `lessons_learned`, `automated_action`, `exposure_reporting`, `remediation_impact`, `analytics`, `threat_hunt`, `autonomous_intelligence`, `integration_hub`, `playbook`, `reporting`) currently run on in-memory repositories despite having real migrations — their data does not survive a process restart. This is being worked through context by context; see each container's `infrastructure/container.py` for its current wiring.

## Platform Capabilities (through M18)

- **Platform identity & governance** — super-admin bootstrap, privileged access security, real TOTP MFA with step-up assurance, platform RBAC, tenant/organization governance.
- **Asset, connector & Security Graph foundation** — a unified canonical asset model (`AIAsset`) and connector framework backed by real PostgreSQL persistence, projected into a versioned Security Graph ontology (node/edge kinds for assets, identities, services, conditions, correlations).
- **Identity, directory & multi-cloud security visibility** — read-only discovery and posture visibility across directory identities and multi-cloud resources.
- **Network, device & service discovery** — native asyncio TCP-connect discovery and protocol-aware service validation. No shell execution, no Nmap/NSE, no OS-level scanning tools.
- **Vulnerability & exposure management** — a canonical `SecurityCondition` model unifying findings across all bounded contexts.
- **Exposure correlation & attack surface intelligence** — a canonical `SecurityCorrelation` model and a bounded, cycle-safe **Exposure Relationship Path** view of how conditions and assets relate. This is explicitly *not* an "attack path": no exploitability scoring, no probability, no exploit chaining is computed or claimed anywhere in the product.
- **Authorized validation scope & execution policy control plane** — a `SecurityAuthorization` aggregate with an ALLOW/DENY/APPROVAL_REQUIRED policy engine gating every active validation action. No active validation of any kind occurs outside an explicit, time-bounded, tenant-scoped authorization.
- **Gated, safe active validation orchestration** — real (not simulated) active network and service validation, always behind the M10 authorization gate, always bounded (connect timeouts, concurrency limits, address-space limits).
- **Continuous validation, drift detection & revalidation** — a scheduler that re-validates authorized targets on a cadence and raises deterministic drift/security-condition events.
- **Advanced network security & continuous network monitoring** — network/IP-CIDR scoped continuous monitoring with mid-run cancellation, restart-durable cancellation state, and scheduler-dispatched execution, all gated by the same M10 authorization plane.
- **Enterprise identity, Super Admin & RBAC control plane** — organization-scoped custom roles and groups on top of the fixed platform RBAC table, a canonical effective-access explain view, and a centralized bounded-delegation grant policy that structurally prevents privilege self-escalation. Platform Super Admin authority (M1/M2) is a separate, non-forgeable authorization plane, never mixed with organization-scoped permissions.
- **Security Operations Command Center** — a premium, real-time, evidence-backed operational surface over every prior context: a deterministic and fully-explainable security-posture score, a live cross-domain activity feed (SSE), top open ports and validated-service exposure, deterministic UEBA/HBA/NBA behavior signals that link to their exact source records (no ML, no opaque scoring), explicit admin-authored network-zone/DMZ classification, an exposure-relationship network map (not an attack path), and provider-neutral boundaries for firewall/bandwidth/ISP/backup-DR/threat-intel/geolocation telemetry that honestly report **NOT CONFIGURED** until a real provider is wired — the platform never fabricates telemetry.
- **Customer-owned telemetry ingestion & geo-enrichment intelligence** — Suricata EVE JSON and Zeek JSON parsers, sensor management, idempotent batch ingest with source deduplication, canonical IP classification (`is_public_ip()`) gating all enrichment egress, keyless RDAP ASN/network-owner enrichment (IANA bootstrap + `_RIR_HOST_ALLOWLIST` SSRF defense), threat intelligence enrichment service with provider-neutral abstraction, and a real-time geo security activity map showing only genuine enriched public IPs — never fabricated coordinates or invented attack arcs.

## Platform Capabilities (M19–M36)

Added after the initial M1–M18 platform foundation above, in the same architectural style (bounded contexts, real persistence, explicit authorization gates, no fabricated telemetry):

- **DDoS defense center** (M19) — active DDoS detection and mitigation workflow bounded to the same authorization plane as all other active validation.
- **NDR, UEBA & behavioral threat detection** (M20) — deterministic behavioral signals (not ML-scored) over network and entity activity, linked to their exact source records.
- **Cross-domain correlation & unified investigation** (M21) — an `investigation` bounded context that correlates security conditions/behavior signals across contexts into a single investigative view.
- **Compliance foundation & evidence recommendation** (M24) — organization assessment domain, compliance operations console, and an evidence recommendation engine against a compliance catalog.
- **Cloud security foundation** (M26) — CSPM policy evaluation, Kubernetes security scanning of the *product's own* security-scanning domain (not deployment infrastructure), risk-weight scoring.
- **Credential vault** (M25) — encrypted credential storage with envelope encryption (DEK-per-credential, KMS-wrapped), rotation/expiration policies, break-glass access, and a full audit trail. See [Security](#security) for KMS configuration — this is the one context where getting production config right matters most.
- **Red team platform, campaign orchestration & AI posture/governance** (M29–M31) — authorized adversarial validation campaigns against AI systems, with AI agent governance and AI posture scoring as first-class bounded contexts.
- **Continuous threat exposure management (CTEM)** (M32) — ongoing exposure scoring and reporting layered on the Security Graph.
- **Security analytics, ML pipeline & reporting** (M33) — cross-domain analytics and an ML model pipeline for the platform's own scoring, separate from any AI-target-under-test.
- **Incident response, regulatory notification & lessons learned** (M34) — a full incident lifecycle (DECLARED → CLASSIFIED → CONTAINED → ERADICATED → RECOVERED → CLOSED) with two-role eradication attestation, an append-only hash-chained communication log, and regulatory notification/lessons-learned capture. PostgreSQL-backed as of this review.
- **Security playbook automation** (M35) — authorized automated response playbooks triggered from incident/detection events.
- **Autonomous AI intelligence & decision platform** (M36) — `autonomous_intelligence`, `posture_forecasting`, and `threat_hunt` contexts: LLM-driven suggestion generation with a domain-enforced autonomy boundary (no direct cross-context mutation without human review), tenant-isolated LLM inference, and posture forecasting with retrospective accuracy tracking.

**What this platform intentionally does not do**, by design, everywhere in the architecture: no arbitrary command execution, no shell/subprocess execution, no exploit or credential-attack tooling, no unrestricted or unbounded scanning, no DNS resolution or redirect-following inside the network validation path, and no "attack path"/exploitability scoring anywhere in the Security Graph or Attack Surface views.

## Architecture

Clean/hexagonal architecture with strict dependency rules, organized as bounded contexts (domain-driven design) rather than a single monolithic domain layer:

```
backend/src/redforge/
├── core/            # Configuration, exceptions, logging — depends on nothing
├── domain/          # Business logic per bounded context (identity, authorization,
│                    #   inventory, network_security, security_graph, ...) — depends on core/
├── application/     # Use-case orchestration, services, schedulers — depends on domain/
├── infrastructure/  # Database (SQLAlchemy/Alembic), middleware, external adapters
│                    #   — depends on core/, never on domain/ internals directly
├── api/             # HTTP transport layer (FastAPI routers) — orchestrates application/
└── app.py           # Application factory: FastAPI app, DI wiring, runtime lifecycle
```

- `core/` depends on nothing.
- `domain/` depends only on `core/`.
- `infrastructure/` depends on `core/`, never reaches into `domain/` internals.
- `api/` orchestrates `application/` services; it never talks to `infrastructure/` or `domain/` directly.

## Technology Stack

- **Backend:** Python (>=3.12), FastAPI, SQLAlchemy (async) + Alembic, PostgreSQL, asyncio-native networking (no external scanning tools).
- **Frontend:** Next.js 15 (App Router), React 19, TypeScript, Vitest — plain `fetch`-based API client, no react-query.

## Runtime Workers

On startup, the backend registers and health-checks the following runtime components (see `GET /api/v1/runtime/health`):

- `database` — connectivity probe
- `replay_worker` — durable event replay
- `dlq` — dead-letter queue processing
- `continuous_validation_scheduler` — M14 continuous validation scheduling
- `network_monitoring_scheduler` — M16 network monitoring scheduling

Many more per-context background workers exist outside this central registry — e.g. DDoS detection, behavior detection, correlation, threat-intel feed sync, credential vault rotation/expiration/DEK-rewrap, and the incident scheduler — each started from its own bounded context's `infrastructure/container.py` or `app.py`'s `_start_<context>()` functions. There is no Celery anywhere in this codebase; all background work is in-process asyncio, started and stopped via the app's lifecycle hooks.

## Local Development

### Prerequisites

- Python >= 3.12
- Node.js (for `npm`) and Next.js 15 compatible runtime
- PostgreSQL 16 (or Docker, for the bundled `postgres:16-alpine` service)

### Docker (recommended)

```bash
make dev
```

Starts backend (port 8000), frontend (port 3000), and PostgreSQL (port 5432) via `docker-compose.yml`/`docker-compose.override.yml`. There is no Redis or Celery service in either compose file, and no Celery anywhere in this codebase. `redis` is a declared backend dependency with real `RedisKillSwitchStore`/`RedisRateLimitStore` implementations under `execution/infrastructure/redis/`, but `execution/infrastructure/container.py` currently wires only their in-memory counterparts — Redis isn't actually connected to anything yet.

### Local Development (without Docker)

**PostgreSQL** — ensure a local PostgreSQL 16 instance is reachable with a `redforge`/`redforge` user and database (matching `.env.example`), or point `REDFORGE_DATABASE_URL` at your own instance.

**Backend:**

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env

# Apply migrations (current head: 0149 — verify with `alembic heads`)
alembic upgrade head

uvicorn redforge.app:create_app --factory --reload
```

**Frontend:**

```bash
cd frontend
npm install
cp .env.example .env.local
npm run dev
```

### Environment Configuration

- `backend/.env.example` → copy to `backend/.env`. Key variables: `REDFORGE_DATABASE_URL` (PostgreSQL DSN), `REDFORGE_HOST`/`REDFORGE_PORT`, `REDFORGE_ENVIRONMENT`, `REDFORGE_LOG_LEVEL`/`REDFORGE_LOG_FORMAT`. `REDFORGE_JWT_SECRET` and `REDFORGE_MFA_ENCRYPTION_KEY` ship with development-only placeholder defaults — the app **refuses to start** with those defaults once `REDFORGE_ENVIRONMENT=production` (see [Security](#security)).
- `frontend/.env.example` → copy to `frontend/.env.local`. **Leave `NEXT_PUBLIC_API_URL` unset for normal local development, including LAN access** (e.g. `http://<your-lan-ip>:3000`) — the frontend reaches the backend via a same-origin Next.js rewrite (`next.config.ts`), so it works on whatever host/port the browser loaded the page from with zero configuration. Only set `NEXT_PUBLIC_API_URL` as an explicit override when the backend is not reachable via that same-origin proxy (e.g. a separately-deployed backend). `BACKEND_INTERNAL_URL` (server-side only, no `NEXT_PUBLIC_` prefix) is the escape hatch for when the Next.js server process itself can't reach the backend at `http://localhost:8000` — e.g. Docker Compose service networking.

AI provider credentials (for validating third-party AI targets) are **not** environment variables — they're tenant-scoped and stored per-organization through the credential vault / connector configuration, consistent with this being a multi-tenant platform rather than a single-provider tool.

### Migrations

```bash
cd backend
alembic heads               # confirm single head (currently 0149)
alembic upgrade head        # apply all migrations
alembic current              # show applied head
alembic downgrade -1         # roll back one migration
```

The entire platform shares one linear Alembic chain — there is no per-bounded-context migration history. Running `alembic upgrade head` migrates every bounded context's schema together.

### Verify

```bash
curl http://localhost:8000/api/v1/health
curl http://localhost:8000/api/v1/runtime/health
```

- App: http://localhost:3000
- API: http://localhost:8000
- Interactive API docs (Swagger UI, enabled only when `REDFORGE_DEBUG=true`): http://localhost:8000/docs

## Security

- **Authentication** — JWT (`REDFORGE_JWT_SECRET`, `REDFORGE_JWT_ALGORITHM`). Ships with a placeholder secret that is rejected outright at startup once `REDFORGE_ENVIRONMENT=production` (`redforge/core/config.py::_validate_production_secrets`) — generate a real one with `python -c "import secrets; print(secrets.token_urlsafe(64))"`.
- **Authorization** — two structurally separate planes: platform `SUPER_ADMIN` (bootstrap via `REDFORGE_PLATFORM_BOOTSTRAP_*`) and per-organization `MembershipRole` (OWNER/ADMIN/SECURITY_MANAGER/ANALYST/MEMBER/VIEWER). An organization Owner/Admin role never grants platform authority — that's enforced structurally, not just at the UI layer, with a "last super-admin can't be removed" invariant.
- **Multi-tenancy** — tenant isolation is enforced at the repository/query layer (not just the API edge) across bounded contexts, and is covered by explicit cross-tenant tests (e.g. `tests/incident/test_lifecycle.py::test_tenant_isolation`).
- **Credential vault KMS** — `CredentialVaultContainer` selects its key-management adapter via `CREDENTIAL_VAULT_KMS_PROVIDER`:
  - `local` (default) — `LocalAesKwKmsAdapter`, an AES-KW-256 local key-wrap adapter for development. The app **refuses to start** with this adapter when `REDFORGE_ENVIRONMENT=production`, unless `CREDENTIAL_VAULT_ALLOW_LOCAL_KMS_IN_PRODUCTION=true` is set explicitly.
  - `aws` — `AwsKmsAdapter`, backed by real AWS KMS. Requires `CREDENTIAL_VAULT_AWS_KMS_KEY_ARN`; optionally `CREDENTIAL_VAULT_AWS_REGION`.
- **AI provider credentials** are stored per-tenant through the credential vault, not as global environment variables — see Environment Configuration above.

## Run Tests & Quality Gates

**Backend:**

```bash
cd backend
ruff check .                 # lint
mypy src/                    # strict type check
pytest                       # full test suite
```

Or via Make from the repo root: `make backend-lint`, `make backend-typecheck`, `make backend-test`.

**Frontend:**

```bash
cd frontend
npm run typecheck            # tsc --noEmit
npm run test                 # vitest run
npm run build                # production build
npm audit
```

Or via Make: `make frontend-lint`, `make frontend-typecheck`.

Run `make help` for the full list of available commands.

## Project Structure

```
.
├── backend/          # FastAPI application (see Architecture above)
│   ├── src/redforge/
│   ├── tests/
│   └── scripts/       # Live HTTP acceptance scripts (real running app, real Postgres)
├── frontend/          # Next.js application
│   └── src/app/        # (app)/(auth)/(platform) route groups
├── docs/              # Milestone reports, checkpoints, architecture context
└── docker-compose.yml
```

## Known Limitations

- One pre-existing backend integration test (`tests/integration/test_security_operations_postgres_proof.py`) is excluded from routine full-suite runs due to a reproducible, evidenced deadlock unrelated to any production code path.
- `npm audit` reports pre-existing moderate advisories in a transitive dependency of `next`, fixable only via a breaking upgrade; not new, not yet remediated.
- No frontend CI stage exists yet (`.github/workflows/ci.yml` covers backend lint/typecheck/test/migration-check/Docker/security-scan only) — run `make frontend-lint`/`make frontend-typecheck`/`cd frontend && npm run test` locally before pushing frontend changes.
- Running the full backend `pytest tests/` locally without a live database (`REDFORGE_DATABASE_URL`/`TEST_DATABASE_URL` pointed at a migrated PostgreSQL instance) produces several hundred fixture-setup errors in `tests/api/` and elsewhere — those tests need a real database and pass in CI, where a `postgres:16-alpine` service is provisioned. Point `REDFORGE_DATABASE_URL` at a local Postgres migrated to head (`alembic upgrade head`) to run them locally.
- No production deployment path exists in this repo yet: `docker-compose.yml`/`.override.yml` are dev-only (bind mounts, `--reload`), and there is no Kubernetes/Helm/Terraform or CD pipeline here.

A prior version of this section incorrectly described the authenticated app shell's permanent "Loading..." behavior as a harmless preview-tooling artifact. It was a real, browser-reproducible defect — `next dev`'s webpack/HMR runtime requires `'unsafe-eval'`, which the app's Content-Security-Policy did not grant, so the client bundle silently never hydrated in development (production builds were unaffected). Fixed: the CSP now allows `'unsafe-eval'` in development only, and the frontend talks to the backend via a same-origin Next.js rewrite by default (see Environment Configuration above) instead of a hardcoded `localhost` origin, so both `http://localhost:3000` and `http://<lan-ip>:3000` work identically. Verified end-to-end in a real browser: register → organization bootstrap → dashboard, logout → login → dashboard, and all primary navigation pages (Dashboard, Assets, Connectors, Attack Surface, Network Security, Findings, Risk, Health) render without a stuck loading state or redirect loop.

See `docs/PROJECT_CONTEXT.md` and the per-milestone checkpoint documents for the complete, evidenced status of every milestone.
