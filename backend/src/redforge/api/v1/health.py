"""Health check endpoints for container orchestration and monitoring.

- /health — Liveness probe. Returns 200 if the process is running.
- /health/ready — Readiness probe. Returns 200 if all dependencies are reachable.
"""

from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import text

from redforge import __version__
from redforge.core.logging import get_logger
from redforge.infrastructure.database.engine import get_engine

router = APIRouter(prefix="/health")
logger = get_logger(__name__)


class HealthResponse(BaseModel):
    """Response body for the liveness probe."""

    status: str
    version: str
    timestamp: str


class ReadinessResponse(BaseModel):
    """Response body for the readiness probe."""

    status: str
    checks: dict[str, str]


@router.get("", response_model=HealthResponse)
async def liveness() -> HealthResponse:
    """Liveness probe — confirms the application process is running."""
    return HealthResponse(
        status="healthy",
        version=__version__,
        timestamp=datetime.now(UTC).isoformat(),
    )


@router.get("/ready", response_model=ReadinessResponse)
async def readiness() -> ReadinessResponse:
    """Readiness probe — confirms all dependencies are available.

    Checks database connectivity by executing a simple query.
    Returns degraded status if any dependency is unreachable.
    """
    checks: dict[str, str] = {
        "application": "ok",
    }

    try:
        engine = get_engine()
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except RuntimeError:
        checks["database"] = "not_configured"
    except Exception as exc:
        logger.warning("health_check_failed", component="database", error=str(exc))
        checks["database"] = "unavailable"

    all_ok = all(v == "ok" for v in checks.values())
    status = "ready" if all_ok else "degraded"

    return ReadinessResponse(status=status, checks=checks)


class LivenessMinimalResponse(BaseModel):
    """Minimal liveness response for load balancer probes."""

    status: str


@router.get("/live", response_model=LivenessMinimalResponse)
async def live() -> LivenessMinimalResponse:
    """Minimal liveness probe — responds immediately with no dependency checks.

    Designed for load balancer health checks that need sub-millisecond response.
    """
    return LivenessMinimalResponse(status="alive")
