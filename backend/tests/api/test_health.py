"""Tests for health check endpoints.

Verifies that liveness and readiness probes return expected responses
and include proper headers (request ID, correlation ID).
"""

from unittest.mock import AsyncMock, MagicMock, patch

from httpx import AsyncClient


async def test_liveness_returns_healthy(client: AsyncClient) -> None:
    response = await client.get("/api/v1/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "healthy"
    assert body["version"] == "0.1.0"
    assert "timestamp" in body


async def test_readiness_without_database_returns_degraded(client: AsyncClient) -> None:
    """When no database engine is configured, readiness reports degraded."""
    response = await client.get("/api/v1/health/ready")

    assert response.status_code == 200
    body = response.json()
    assert body["checks"]["application"] == "ok"
    assert body["checks"]["database"] == "not_configured"
    assert body["status"] == "degraded"


async def test_readiness_with_healthy_database(client: AsyncClient) -> None:
    """When database is reachable, readiness reports ready."""
    mock_conn = AsyncMock()
    mock_conn.execute = AsyncMock()

    mock_engine = MagicMock()
    mock_engine.connect = MagicMock(return_value=AsyncMock(
        __aenter__=AsyncMock(return_value=mock_conn),
        __aexit__=AsyncMock(return_value=None),
    ))

    with patch("redforge.api.v1.health.get_engine", return_value=mock_engine):
        response = await client.get("/api/v1/health/ready")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["checks"]["database"] == "ok"
    assert body["checks"]["application"] == "ok"


async def test_readiness_with_unavailable_database(client: AsyncClient) -> None:
    """When database connection fails, readiness reports degraded."""
    mock_engine = MagicMock()
    mock_engine.connect = MagicMock(return_value=AsyncMock(
        __aenter__=AsyncMock(side_effect=ConnectionRefusedError("connection refused")),
        __aexit__=AsyncMock(return_value=None),
    ))

    with patch("redforge.api.v1.health.get_engine", return_value=mock_engine):
        response = await client.get("/api/v1/health/ready")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["checks"]["database"] == "unavailable"


async def test_request_id_generated_when_not_provided(client: AsyncClient) -> None:
    response = await client.get("/api/v1/health")

    assert response.status_code == 200
    assert "x-request-id" in response.headers
    assert "x-correlation-id" in response.headers


async def test_request_id_echoed_when_provided(client: AsyncClient) -> None:
    custom_id = "test-request-123"
    response = await client.get(
        "/api/v1/health",
        headers={"X-Request-ID": custom_id},
    )

    assert response.status_code == 200
    assert response.headers["x-request-id"] == custom_id


async def test_correlation_id_propagated(client: AsyncClient) -> None:
    correlation = "trace-abc-456"
    response = await client.get(
        "/api/v1/health",
        headers={"X-Correlation-ID": correlation},
    )

    assert response.status_code == 200
    assert response.headers["x-correlation-id"] == correlation
