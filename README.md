# AIVAR RedForge

Enterprise Continuous AI Security Validation and AI Red Teaming Platform — not a wrapper around LLM APIs, not a prompt-testing utility. AIVAR RedForge discovers, authorizes, validates, and continuously monitors the security posture of AI systems and their surrounding infrastructure, in the same spirit as CrowdStrike for endpoints or Wiz for cloud, but for AI.

## Current Status

**Milestones M1–M16 are COMPLETE** (verified baseline at commit `0682c23`, migration head `0025`). Full detail and per-milestone proof live in [`docs/PROJECT_CONTEXT.md`](docs/PROJECT_CONTEXT.md) and the milestone-specific reports/checkpoints under [`docs/`](docs/). This README is a high-level orientation, not a milestone log — do not add per-milestone history here.

## Platform Capabilities (through M16)

- **Platform identity & governance** — super-admin bootstrap, privileged access security, real TOTP MFA with step-up assurance, platform RBAC, tenant/organization governance.
- **Asset, connector & Security Graph foundation** — a unified canonical asset model (`AIAsset`) and connector framework backed by real PostgreSQL persistence, projected into a versioned Security Graph ontology (node/edge kinds for assets, identities, services, conditions, correlations).
- **Identity, directory & multi-cloud security visibility** — read-only discovery and posture visibility across directory identities and multi-cloud resources.
- **Network, device & service discovery** — native asyncio TCP-connect discovery and protocol-aware service validation. No shell execution, no Nmap/NSE, no OS-level scanning tools.
- **Vulnerability & exposure management** — a canonical `SecurityCondition` model unifying findings across all bounded contexts.
- **Exposure correlation & attack surface intelligence** — a canonical `SecurityCorrelation` model and a bounded, cycle-safe **Exposure Relationship Path** view of how conditions and assets relate. This is explicitly *not* an "attack path": no exploitability scoring, no probability, no exploit chaining is computed or claimed anywhere in the product.
- **Authorized validation scope & execution policy control plane** — a `SecurityAuthorization` aggregate with an ALLOW/DENY/APPROVAL_REQUIRED policy engine gating every active validation action. No active validation of any kind occurs outside an explicit, time-bounded, tenant-scoped authorization.
- **Gated, safe active validation orchestration** — real (not simulated) active network and service validation, always behind the M10 authorization gate, always bounded (connect timeouts, concurrency limits, address-space limits).
- **Continuous validation, drift detection & revalidation** — a scheduler that re-validates authorized targets on a cadence and raises deterministic drift/security-condition events.
- **Security Operations Command Center** — a unified, read-only, real-time execution telemetry feed across every validation-producing bounded context.
- **Advanced network security & continuous network monitoring** — network/IP-CIDR scoped continuous monitoring with mid-run cancellation, restart-durable cancellation state, and scheduler-dispatched execution, all gated by the same M10 authorization plane.

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

## Local Development

### Prerequisites

- Python >= 3.12
- Node.js (for `npm`) and Next.js 15 compatible runtime
- PostgreSQL 16 (or Docker, for the bundled `postgres:16-alpine` service)

### Docker (recommended)

```bash
make dev
```

Starts backend (port 8000), frontend (port 3000), and PostgreSQL (port 5432) via `docker-compose.yml`/`docker-compose.override.yml`.

### Local Development (without Docker)

**PostgreSQL** — ensure a local PostgreSQL 16 instance is reachable with a `redforge`/`redforge` user and database (matching `.env.example`), or point `REDFORGE_DATABASE_URL` at your own instance.

**Backend:**

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env

# Apply migrations (current head: 0025)
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

- `backend/.env.example` → copy to `backend/.env`. Key variables: `REDFORGE_DATABASE_URL` (PostgreSQL DSN), `REDFORGE_HOST`/`REDFORGE_PORT`, `REDFORGE_ENVIRONMENT`, `REDFORGE_LOG_LEVEL`/`REDFORGE_LOG_FORMAT`.
- `frontend/.env.example` → copy to `frontend/.env.local`. **Leave `NEXT_PUBLIC_API_URL` unset for normal local development, including LAN access** (e.g. `http://<your-lan-ip>:3000`) — the frontend reaches the backend via a same-origin Next.js rewrite (`next.config.ts`), so it works on whatever host/port the browser loaded the page from with zero configuration. Only set `NEXT_PUBLIC_API_URL` as an explicit override when the backend is not reachable via that same-origin proxy (e.g. a separately-deployed backend). `BACKEND_INTERNAL_URL` (server-side only, no `NEXT_PUBLIC_` prefix) is the escape hatch for when the Next.js server process itself can't reach the backend at `http://localhost:8000` — e.g. Docker Compose service networking.

### Migrations

```bash
cd backend
alembic upgrade head       # apply all migrations — current head: 0025
alembic current            # show applied head
alembic downgrade -1       # roll back one migration
```

### Verify

```bash
curl http://localhost:8000/api/v1/health
curl http://localhost:8000/api/v1/runtime/health
```

- App: http://localhost:3000
- API: http://localhost:8000
- Interactive API docs (Swagger UI, enabled only when `REDFORGE_DEBUG=true`): http://localhost:8000/docs

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

A prior version of this section incorrectly described the authenticated app shell's permanent "Loading..." behavior as a harmless preview-tooling artifact. It was a real, browser-reproducible defect — `next dev`'s webpack/HMR runtime requires `'unsafe-eval'`, which the app's Content-Security-Policy did not grant, so the client bundle silently never hydrated in development (production builds were unaffected). Fixed: the CSP now allows `'unsafe-eval'` in development only, and the frontend talks to the backend via a same-origin Next.js rewrite by default (see Environment Configuration above) instead of a hardcoded `localhost` origin, so both `http://localhost:3000` and `http://<lan-ip>:3000` work identically. Verified end-to-end in a real browser: register → organization bootstrap → dashboard, logout → login → dashboard, and all primary navigation pages (Dashboard, Assets, Connectors, Attack Surface, Network Security, Findings, Risk, Health) render without a stuck loading state or redirect loop.

See `docs/PROJECT_CONTEXT.md` and the per-milestone checkpoint documents for the complete, evidenced status of every milestone.
