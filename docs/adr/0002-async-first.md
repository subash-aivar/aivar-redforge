# ADR-0002: Async-First Backend Architecture

## Status

Accepted

## Date

2025-01-01

## Context

RedForge's primary workload is validating AI systems by calling external AI APIs. These operations are I/O-bound with high latency (100ms-30s per call). The platform must handle millions of validations per day.

## Decision

The backend is fully async:

- FastAPI as the async HTTP framework.
- SQLAlchemy 2.x with asyncpg for non-blocking database access.
- httpx for async HTTP client operations.
- asyncio as the event loop.

The domain layer remains sync-agnostic — it contains pure Python logic that does not depend on async primitives. Only infrastructure adapters (database, HTTP clients) use async/await.

## Consequences

- High throughput for I/O-bound validation workloads.
- Connection pooling with async yields better resource utilization.
- Domain logic remains testable without async test infrastructure.
- All infrastructure code must be async-aware.
- Background tasks that are CPU-bound will need to be offloaded to worker processes.

## Alternatives Considered

- **Sync with thread pool** — Lower throughput for the same hardware cost.
- **Go/Rust service** — Higher performance ceiling but loses Python AI ecosystem access.
