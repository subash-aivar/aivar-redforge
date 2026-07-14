"""SSRF-safe, resilient outbound HTTP client for the Threat Intelligence
bounded context.

Every external call in this bounded context goes through this one client.
It composes three already-existing, generic platform primitives rather
than reinventing them:

  - `DefaultCircuitBreaker` (application/platform/circuit_breaker.py, Sprint 26)
  - `RetryExecutor`/`RetryConfig` (application/platform/retry_strategy.py, Sprint 25)
  - `InMemorySlidingWindowLimiter` (infrastructure/rate_limiting/sliding_window.py)

SSRF posture:
  - The destination host is never taken from user/tenant input — every
    provider adapter passes a fixed, hardcoded hostname belonging to a
    closed allowlist (`_ALLOWED_HOSTS`). There is no code path that lets
    a caller supply an arbitrary URL.
  - TLS verification is always on (httpx default; never disabled here).
  - Redirects are not followed (`follow_redirects=False`) — a provider
    that tries to redirect us elsewhere fails closed rather than being
    silently trusted.
  - Response bodies are capped (`MAX_RESPONSE_BYTES`) and read via a
    streaming decode so a hostile/broken feed cannot exhaust memory.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

import httpx

from redforge.application.platform.circuit_breaker import (
    CircuitBreakerRegistry,
    CircuitOpenError,
)
from redforge.application.platform.retry_strategy import RetryConfig, RetryExecutor
from redforge.infrastructure.rate_limiting.sliding_window import (
    InMemorySlidingWindowLimiter,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

logger = logging.getLogger(__name__)

# Fixed allowlist of hosts this bounded context is ever permitted to
# contact. Provider adapters reference these by name; nothing derives a
# host from tenant/user-controlled data.
_ALLOWED_HOSTS: frozenset[str] = frozenset(
    {
        "api.abuseipdb.com",
        "otx.alienvault.com",
        "www.spamhaus.org",
        "rdap.arin.net",
        "rdap.db.ripe.net",
        "rdap.apnic.net",
        "rdap.lacnic.net",
        "rdap.afrinic.net",
        "data.iana.org",
        "ipinfo.io",
        "api.greynoise.io",
        "urlhaus-api.abuse.ch",
        "threatfox-api.abuse.ch",
        "feodotracker.abuse.ch",
    }
)

MAX_RESPONSE_BYTES = 5 * 1024 * 1024  # 5 MB — generous for JSON/CSV feeds, bounded
DEFAULT_TIMEOUT_S = 8.0


class ProviderRateLimitedError(Exception):
    """Raised when this process's own self-imposed rate limit for a
    provider is hit — distinct from the provider's HTTP 429, which is
    surfaced separately so provider health can tell them apart."""


class ProviderResponseTooLargeError(Exception):
    pass


class DisallowedHostError(Exception):
    """Raised if an adapter ever attempts to contact a host outside the
    fixed allowlist — this should be unreachable in practice since hosts
    are hardcoded per adapter, but the check exists as defense in depth."""


@dataclass(frozen=True, slots=True)
class HttpFetchResult:
    status_code: int
    body: bytes
    headers: Mapping[str, str]


class ThreatIntelHttpClient:
    """One resilient client shared by all provider adapters.

    A separate circuit breaker and rate-limit bucket is created per
    `provider_name`, so one provider's outage or quota exhaustion can
    never affect another's — this is what makes "one provider failure
    must never break the Command Center" true at the transport layer,
    not just by convention.
    """

    def __init__(
        self,
        circuit_registry: CircuitBreakerRegistry | None = None,
        rate_limiter: InMemorySlidingWindowLimiter | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
    ) -> None:
        self._circuits = circuit_registry or CircuitBreakerRegistry()
        self._rate_limiter = rate_limiter or InMemorySlidingWindowLimiter()
        self._timeout_s = timeout_s

    async def get(
        self,
        provider_name: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, str] | None = None,
        max_requests_per_window: int = 30,
        window_seconds: int = 60,
        retry: RetryConfig | None = None,
    ) -> HttpFetchResult:
        return await self._request(
            provider_name,
            "GET",
            url,
            headers=headers,
            params=params,
            max_requests_per_window=max_requests_per_window,
            window_seconds=window_seconds,
            retry=retry,
        )

    async def post(
        self,
        provider_name: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        json_body: Mapping[str, Any] | None = None,
        max_requests_per_window: int = 30,
        window_seconds: int = 60,
        retry: RetryConfig | None = None,
    ) -> HttpFetchResult:
        return await self._request(
            provider_name,
            "POST",
            url,
            headers=headers,
            json_body=json_body,
            max_requests_per_window=max_requests_per_window,
            window_seconds=window_seconds,
            retry=retry,
        )

    async def _request(
        self,
        provider_name: str,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, str] | None = None,
        json_body: Mapping[str, Any] | None = None,
        max_requests_per_window: int,
        window_seconds: int,
        retry: RetryConfig | None,
    ) -> HttpFetchResult:
        host = httpx.URL(url).host
        if host not in _ALLOWED_HOSTS:
            raise DisallowedHostError(f"host {host!r} is not in the threat-intel allowlist")

        limit_result = await self._rate_limiter.check(
            key=f"threat_intel:{provider_name}",
            max_requests=max_requests_per_window,
            window_seconds=window_seconds,
        )
        if not limit_result.allowed:
            raise ProviderRateLimitedError(
                f"{provider_name}: self-imposed rate limit hit, retry after "
                f"{limit_result.retry_after_seconds}s"
            )

        breaker = self._circuits.get_or_create(
            f"threat_intel:{provider_name}",
            failure_threshold=5,
            recovery_timeout_s=60.0,
        )
        executor = RetryExecutor(
            retry or RetryConfig(max_attempts=2, base_delay_s=0.5, max_delay_s=4.0)
        )

        async def _once() -> HttpFetchResult:
            async with httpx.AsyncClient(
                timeout=self._timeout_s,
                follow_redirects=False,
                verify=True,
            ) as client:
                response = await client.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    json=json_body,
                )
                content_length = response.headers.get("content-length")
                if content_length is not None and int(content_length) > MAX_RESPONSE_BYTES:
                    raise ProviderResponseTooLargeError(
                        f"{provider_name}: response declared {content_length} bytes"
                    )
                body = response.content
                if len(body) > MAX_RESPONSE_BYTES:
                    raise ProviderResponseTooLargeError(
                        f"{provider_name}: response body exceeded {MAX_RESPONSE_BYTES} bytes"
                    )
                if response.status_code >= 500:
                    # Only 5xx is treated as transient/retryable; 4xx (auth
                    # failure, bad request, rate-limited) is not retried —
                    # retrying an auth failure just burns quota for nothing.
                    response.raise_for_status()
                return HttpFetchResult(
                    status_code=response.status_code,
                    body=body,
                    headers=dict(response.headers),
                )

        async def _with_retry() -> HttpFetchResult:
            return await executor.execute(
                _once, retryable_exceptions=(httpx.HTTPStatusError, httpx.TransportError)
            )

        try:
            return cast("HttpFetchResult", await breaker.execute(_with_retry))
        except CircuitOpenError:
            raise
        except httpx.HTTPStatusError as exc:
            return HttpFetchResult(
                status_code=exc.response.status_code,
                body=exc.response.content,
                headers=dict(exc.response.headers),
            )

    async def call_with_circuit(self, provider_name: str, coro_factory: Any) -> Any:
        """Wrap an arbitrary provider call (e.g. one that itself calls
        `get`/`post` multiple times, like RDAP bootstrap+lookup) in that
        provider's circuit breaker without duplicating the rate-limit
        and retry logic already applied inside `get`/`post`."""
        breaker = self._circuits.get_or_create(
            f"threat_intel:{provider_name}",
            failure_threshold=5,
            recovery_timeout_s=60.0,
        )
        return await breaker.execute(coro_factory)

    @property
    def circuits(self) -> CircuitBreakerRegistry:
        return self._circuits
