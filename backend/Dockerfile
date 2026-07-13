# ─── Stage 1: Dependencies ─────────────────────────────────────────────────
FROM python:3.12-slim AS dependencies

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Install build dependencies for asyncpg (libpq-dev for pg_config)
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --prefix=/install .

# ─── Stage 2: Runtime ──────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app

# Runtime system dependencies only (no compiler)
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpq5 curl && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r redforge && \
    useradd -r -g redforge -d /app -s /sbin/nologin redforge

# Copy installed packages from build stage
COPY --from=dependencies /install/lib /usr/local/lib
COPY --from=dependencies /install/bin /usr/local/bin

# Copy application source
COPY src/ src/
COPY alembic.ini .

# Set ownership
RUN chown -R redforge:redforge /app

# Switch to non-root user
USER redforge

EXPOSE 8000

# Production environment defaults
ENV REDFORGE_ENVIRONMENT=production \
    REDFORGE_LOG_FORMAT=json \
    REDFORGE_LOG_LEVEL=INFO \
    REDFORGE_DEBUG=false

# Healthcheck using curl (fast, no Python interpreter overhead)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["curl", "-f", "http://localhost:8000/api/v1/health/live"]

# Production entrypoint with multiple workers
CMD ["uvicorn", "redforge.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--workers", "4", "--access-log"]
