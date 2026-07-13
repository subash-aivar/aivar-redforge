# AIVAR RedForge

Continuous AI Security Validation Platform.

## Quick Start

### Docker (recommended)

```bash
make dev
```

This starts the backend (port 8000), frontend (port 3000), and PostgreSQL.

### Local Development

**Backend:**

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
uvicorn redforge.app:create_app --factory --reload
```

**Frontend:**

```bash
cd frontend
corepack enable pnpm
pnpm install
cp .env.example .env.local
pnpm dev
```

## Verify

```bash
curl http://localhost:8000/api/v1/health
```

## Run Tests

```bash
make backend-test
```

## Project Structure

```
backend/src/redforge/
├── core/            # Configuration, exceptions, logging
├── domain/          # Business logic (future)
├── shared/          # Cross-domain primitives (future)
├── infrastructure/  # Database, middleware, external adapters
├── api/             # HTTP transport layer
└── app.py           # Application factory
```

## Architecture

Clean Architecture with strict dependency rules:

- `core/` depends on nothing
- `domain/` depends on `core/`
- `infrastructure/` depends on `core/` (never on `domain/` internals)
- `api/` orchestrates `domain/` services

## Available Commands

Run `make help` to see all available commands.
