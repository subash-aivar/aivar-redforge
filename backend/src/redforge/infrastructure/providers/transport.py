"""Generic LLM Transport Layer.

Provides reusable HTTP transport with retry, timeout, error normalization,
telemetry hooks, and correlation ID propagation. Every AI provider adapter
composes this transport rather than implementing its own HTTP handling.

Usage:
    transport = LLMTransport(config)
    response = await transport.post("/chat/completions", body={...})
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

import httpx

from redforge.core.logging import get_logger, request_id_ctx
from redforge.domain.providers.value_objects import ProviderError

logger = get_logger(__name__)


# ─── Configuration ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TransportConfig:
    """Configuration for the LLM transport layer."""

    base_url: str
    auth_header: str = ""
    timeout_seconds: int = 60
    max_retries: int = 3
    retry_backoff_seconds: float = 1.0
    retryable_status_codes: frozenset[int] = frozenset({429, 500, 502, 503, 504})
    extra_headers: dict[str, str] = field(default_factory=dict)


# ─── Hooks ────────────────────────────────────────────────────────────────────


@runtime_checkable
class TelemetryHook(Protocol):
    """Hook for observability — called on every request/response cycle."""

    async def on_request(self, method: str, path: str, body: dict[str, Any]) -> None:
        """Called before sending a request."""
        ...

    async def on_response(
        self, method: str, path: str, status: int, duration_ms: float
    ) -> None:
        """Called after receiving a response."""
        ...

    async def on_error(self, method: str, path: str, error: str) -> None:
        """Called when a request fails."""
        ...


class NullTelemetryHook:
    """No-op telemetry hook for when observability is not configured."""

    async def on_request(self, method: str, path: str, body: dict[str, Any]) -> None:
        pass

    async def on_response(
        self, method: str, path: str, status: int, duration_ms: float
    ) -> None:
        pass

    async def on_error(self, method: str, path: str, error: str) -> None:
        pass


# ─── Response ─────────────────────────────────────────────────────────────────


@dataclass
class TransportResponse:
    """Normalized response from the transport layer."""

    status_code: int
    body: dict[str, Any]
    headers: dict[str, str]
    duration_ms: float
    retries_used: int = 0


# ─── Errors ───────────────────────────────────────────────────────────────────


class TransportError(Exception):
    """Raised when the transport layer exhausts retries or encounters a fatal error."""

    def __init__(
        self, message: str, retryable: bool, retries_used: int = 0,
        provider_error: ProviderError | None = None,
    ) -> None:
        self.message = message
        self.retryable = retryable
        self.retries_used = retries_used
        self.provider_error = provider_error
        super().__init__(message)


# ─── Transport ────────────────────────────────────────────────────────────────


class LLMTransport:
    """Generic HTTP transport for LLM providers.

    Handles retry with exponential backoff, timeout, error normalization,
    correlation ID propagation, and telemetry hooks. Provider adapters
    compose this transport and focus only on request/response mapping.
    """

    def __init__(
        self,
        config: TransportConfig,
        http_client: httpx.AsyncClient | None = None,
        telemetry: TelemetryHook | None = None,
    ) -> None:
        self._config = config
        self._telemetry = telemetry or NullTelemetryHook()

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if config.auth_header:
            headers["Authorization"] = config.auth_header
        headers.update(config.extra_headers)

        self._client = http_client or httpx.AsyncClient(
            base_url=config.base_url,
            headers=headers,
            timeout=httpx.Timeout(config.timeout_seconds),
        )

    async def post(self, path: str, body: dict[str, Any]) -> TransportResponse:
        """Send a POST request with retry and telemetry."""
        return await self._request("POST", path, body)

    async def get(self, path: str) -> TransportResponse:
        """Send a GET request with retry and telemetry."""
        return await self._request("GET", path, {})

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    # ─── Private ──────────────────────────────────────────────────────────

    async def _request(
        self, method: str, path: str, body: dict[str, Any]
    ) -> TransportResponse:
        """Execute request with retry loop."""
        import time

        last_error: TransportError | None = None

        for attempt in range(self._config.max_retries + 1):
            await self._telemetry.on_request(method, path, body)
            start = time.perf_counter()

            try:
                resp = await self._send(method, path, body)
                duration_ms = (time.perf_counter() - start) * 1000

                await self._telemetry.on_response(
                    method, path, resp.status_code, duration_ms
                )

                if resp.status_code in self._config.retryable_status_codes:
                    error = self._build_error(resp, attempt)
                    last_error = error
                    if attempt >= self._config.max_retries:
                        raise error
                    await self._backoff(attempt)
                    continue

                if resp.status_code >= 400:
                    raise self._build_error(resp, attempt)

                resp_body = resp.json() if resp.content else {}
                return TransportResponse(
                    status_code=resp.status_code,
                    body=resp_body,
                    headers=dict(resp.headers),
                    duration_ms=duration_ms,
                    retries_used=attempt,
                )

            except httpx.TimeoutException as exc:
                duration_ms = (time.perf_counter() - start) * 1000
                await self._telemetry.on_error(method, path, "timeout")
                last_error = TransportError(
                    message="Request timed out",
                    retryable=True,
                    retries_used=attempt,
                    provider_error=ProviderError(
                        code="TIMEOUT", message=str(exc), retryable=True
                    ),
                )
                if attempt >= self._config.max_retries:
                    raise last_error from exc
                await self._backoff(attempt)

            except httpx.HTTPError as exc:
                duration_ms = (time.perf_counter() - start) * 1000
                await self._telemetry.on_error(method, path, str(exc))
                last_error = TransportError(
                    message=f"HTTP error: {exc}",
                    retryable=True,
                    retries_used=attempt,
                    provider_error=ProviderError(
                        code="HTTP_ERROR", message=str(exc), retryable=True
                    ),
                )
                if attempt >= self._config.max_retries:
                    raise last_error from exc
                await self._backoff(attempt)

        raise last_error  # type: ignore[misc]

    async def _send(self, method: str, path: str, body: dict[str, Any]) -> httpx.Response:
        """Send a single HTTP request with correlation ID."""
        headers: dict[str, str] = {}
        correlation_id = request_id_ctx.get()
        if correlation_id:
            headers["X-Request-ID"] = correlation_id

        if method == "POST":
            return await self._client.post(path, json=body, headers=headers)
        return await self._client.get(path, headers=headers)

    def _build_error(self, resp: httpx.Response, attempt: int) -> TransportError:
        """Build a TransportError from an HTTP response."""
        error_body = resp.json() if resp.content else {}
        error_field = error_body.get("error", {})
        if isinstance(error_field, dict):
            error_msg = error_field.get("message", f"Status {resp.status_code}")
        else:
            error_msg = str(error_field) or f"Status {resp.status_code}"
        retryable = resp.status_code in self._config.retryable_status_codes

        return TransportError(
            message=error_msg,
            retryable=retryable,
            retries_used=attempt,
            provider_error=ProviderError(
                code=f"HTTP_{resp.status_code}",
                message=error_msg,
                retryable=retryable,
                provider_code=str(resp.status_code),
            ),
        )

    async def _backoff(self, attempt: int) -> None:
        """Exponential backoff between retries."""
        delay = self._config.retry_backoff_seconds * (2**attempt)
        logger.info("transport_retry", attempt=attempt + 1, delay_s=delay)
        await asyncio.sleep(delay)
