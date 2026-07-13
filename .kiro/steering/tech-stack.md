---
inclusion: auto
---

# AIVAR RedForge — Technology Stack

Locked decisions. Do not deviate without explicit approval.

## Backend

| Technology | Version | Purpose |
|------------|---------|---------|
| Python | 3.12+ | Runtime |
| FastAPI | Latest | HTTP framework (outer ring only) |
| Pydantic | v2 | Validation, settings, schemas |
| SQLAlchemy | 2.x | ORM / persistence adapter (outer ring only) |
| Alembic | Latest | Database migrations |
| PostgreSQL | 16+ | Primary data store |
| structlog | Latest | Structured logging |
| asyncpg | Latest | Async PostgreSQL driver |
| python-ulid | Latest | Sortable unique identifiers |
| httpx | Latest | Async HTTP client |
| ruff | Latest | Linting + formatting |
| mypy | Latest | Static type checking (strict) |
| pytest | Latest | Test runner |
| pytest-asyncio | Latest | Async test support |

## Frontend

| Technology | Purpose |
|------------|---------|
| Next.js (App Router) | React framework |
| TypeScript | Language (strict mode) |
| TailwindCSS | Styling |
| TanStack Query | Server state management |
| pnpm | Package manager |

## Infrastructure

| Technology | Purpose |
|------------|---------|
| Docker | Containerization |
| Docker Compose | Local development |
| GitHub Actions | CI/CD |

## Authentication (Future Milestone)

| Technology | Purpose |
|------------|---------|
| JWT | Token-based auth |
| RBAC | Role-based access control |

## Background Processing (Future)

| Technology | Purpose |
|------------|---------|
| FastAPI BackgroundTasks | MVP async work |
| Redis + Celery/ARQ | Production distributed workers |

## Decisions Log

- **ULID over UUIDv4:** Sortable, timestamp-embedded, better B-tree index locality.
- **structlog over stdlib logging:** Structured processors, bound loggers, JSON output.
- **Manual DI over framework:** Explicit, debuggable, no magic.
- **pnpm over npm/yarn:** Faster, stricter, disk-efficient.
- **src/ layout:** Prevents accidental root imports, proper packaging.
- **Next.js over Vite+React:** SSR for data-heavy dashboards, built-in BFF, file routing.
