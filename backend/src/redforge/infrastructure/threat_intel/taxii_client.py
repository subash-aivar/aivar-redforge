"""TAXII 2.1 client — M22 Phase 3 (STIX/TAXII Integration).

Unlike every other adapter in `infrastructure/threat_intel/providers/`,
a TAXII endpoint is *admin-configured per feed* (`Feed.connector_config`),
not a fixed, hardcoded hostname from a closed allowlist — so the
`_ALLOWED_HOSTS` pattern `ThreatIntelHttpClient` uses does not apply
here at all. This is exactly the SSRF vector the Hardening Review
flags as P0 ("TAXII endpoint URL is admin-configurable — classic SSRF
vector"). Every request this client issues therefore goes through
`_validate_ssrf_safe` immediately beforehand:

  (a) scheme must be `https://` — no plaintext, no `file://`/`gopher://`/etc.
  (b) the hostname is resolved and EVERY resolved address must be a
      genuinely public, routable address (`ip_classification.is_public_ip`
      — the same private/loopback/link-local/multicast/reserved/
      documentation-range gate the rest of this bounded context's
      egress already uses for indicator lookups); a hostname that
      resolves to an internal address (RFC-1918, `169.254.169.254`
      cloud metadata, `127.0.0.1`, ...) is refused before any
      connection is attempted.
  (c) `follow_redirects=False` — a 3xx response is treated as a
      request failure, never silently followed. This closes the
      "redirect to an internal host" bypass without needing to
      re-validate every hop.

DNS resolution is injectable (`resolver` constructor parameter) so
tests can exercise the SSRF gate deterministically without depending
on real DNS or a real network — production code always uses the
default `socket.getaddrinfo`-backed resolver.

STIX external_references URLs (arbitrary URLs embedded IN STIX object
content, not TAXII endpoint URLs) are a distinct, second SSRF vector
the Hardening Review names separately (Part 4, "STIX external
references contain arbitrary URLs — secondary SSRF via reference
resolution") — this client never resolves those; they are stored as
inert text metadata by the ACL mapper, never fetched. See
`stix_reference_data_mapper.py`.
"""

from __future__ import annotations

import asyncio
import json
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx

from redforge.infrastructure.threat_intel.ip_classification import is_public_ip

TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"
STIX_MEDIA_TYPE = "application/stix+json;version=2.1"

DEFAULT_TIMEOUT_S = 15.0
DEFAULT_DNS_TIMEOUT_S = 5.0
#: Matches `stix_parser.MAX_CONTAINER_BYTES` — the same hard cap on
#: how much of a TAXII response this client (and, downstream, the
#: STIX parser) will ever hold in memory at once.
MAX_RESPONSE_BYTES = 24 * 1024 * 1024
DEFAULT_PAGE_LIMIT = 500

#: Resolves a hostname to the tuple of IP address strings it maps to.
#: Injectable purely for deterministic testing of the SSRF gate — see
#: module docstring.
Resolver = Callable[[str], Awaitable[tuple[str, ...]]]


class TaxiiDisallowedUrlError(Exception):
    """SSRF defense: raised when a configured/discovered TAXII URL
    fails the scheme/host safety gate. No network call is ever made
    once this is raised — the check runs strictly before the request."""


class TaxiiRequestError(Exception):
    """Raised for a TAXII HTTP transport failure: a non-2xx status (a
    3xx is deliberately treated as a failure too, since redirects are
    never followed), a timeout, or a connection failure."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class TaxiiAuthenticationError(TaxiiRequestError):
    """Raised when the TAXII server responds 401 or 403."""


class TaxiiResponseTooLargeError(Exception):
    """Raised when a response's declared or actual body size exceeds
    `MAX_RESPONSE_BYTES` — never buffered past that point."""


class TaxiiResponseFormatError(Exception):
    """Raised when a 2xx response is not valid JSON, or is valid JSON
    that does not have the shape the TAXII 2.1 resource in question is
    required to have."""


async def _default_resolve(
    hostname: str, *, timeout: float = DEFAULT_DNS_TIMEOUT_S
) -> tuple[str, ...]:
    loop = asyncio.get_event_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM), timeout=timeout
        )
    except (TimeoutError, socket.gaierror) as exc:
        raise TaxiiDisallowedUrlError(
            f"DNS resolution failed for host {hostname!r}: {exc}"
        ) from exc
    addresses: list[str] = []
    for _family, _type, _proto, _canonname, sockaddr in infos:
        addr = str(sockaddr[0])
        if addr not in addresses:
            addresses.append(addr)
    return tuple(addresses)


def _validate_scheme_and_host(url: str) -> str:
    parsed = httpx.URL(url)
    if parsed.scheme != "https":
        raise TaxiiDisallowedUrlError(
            f"TAXII URL must use the https:// scheme, got {parsed.scheme!r} for {url!r}"
        )
    if not parsed.host:
        raise TaxiiDisallowedUrlError(f"TAXII URL has no host: {url!r}")
    return parsed.host


async def validate_ssrf_safe(url: str, *, resolver: Resolver = _default_resolve) -> None:
    """Public so `StixTaxiiFeedConnector` can pre-validate admin-supplied
    configuration URLs eagerly (e.g. at feed registration/config-update
    preview time) using the exact same gate this client enforces on
    every request."""
    host = _validate_scheme_and_host(url)
    addresses = await resolver(host)
    if not addresses:
        raise TaxiiDisallowedUrlError(f"host {host!r} did not resolve to any address")
    for addr in addresses:
        if not is_public_ip(addr):
            raise TaxiiDisallowedUrlError(
                f"host {host!r} resolves to non-public address {addr!r} — refused"
            )


@dataclass(frozen=True, slots=True)
class TaxiiAuth:
    """TAXII 2.1 authentication material.

    Resolved from `Feed.credential_ref` (an opaque env-var-name
    reference — never a secret value) by the *connector*, using the
    exact same `EnvironmentCredentialResolver`/`CredentialResolverPort`
    pattern the rest of the platform uses. This dataclass itself never
    reads an environment variable or touches a credential store — it
    only carries an already-resolved value for exactly the duration of
    one HTTP call, and is never logged (its `secret` field is excluded
    from any structured log)."""

    scheme: Literal["none", "basic", "bearer"] = "none"
    username: str | None = None  # non-secret; only meaningful for scheme="basic"
    secret: str | None = None  # password (basic) or bearer token — never logged

    def headers(self) -> dict[str, str]:
        if self.scheme == "bearer" and self.secret:
            return {"Authorization": f"Bearer {self.secret}"}
        return {}

    def httpx_auth(self) -> httpx.BasicAuth | None:
        if self.scheme == "basic" and self.username and self.secret:
            return httpx.BasicAuth(self.username, self.secret)
        return None

    @classmethod
    def none(cls) -> TaxiiAuth:
        return cls(scheme="none")


@dataclass(frozen=True, slots=True)
class TaxiiDiscovery:
    title: str
    description: str | None
    api_roots: tuple[str, ...] = field(default_factory=tuple)
    default: str | None = None


@dataclass(frozen=True, slots=True)
class TaxiiCollection:
    id: str
    title: str
    description: str | None
    can_read: bool
    can_write: bool
    media_types: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class TaxiiEnvelope:
    """One page of a TAXII collection's `/objects/` response."""

    objects: tuple[dict[str, Any], ...]
    more: bool
    next: str | None = None


class TaxiiClient:
    """SSRF-safe TAXII 2.1 consumer client — discovery, collection
    listing, and paginated object polling. Read-only: this client
    never writes to a TAXII server (RedForge is a TAXII consumer only,
    per the Architecture Freeze — "TAXII server (hosting) is out of
    scope for M22")."""

    def __init__(
        self,
        *,
        http_client: httpx.AsyncClient | None = None,
        resolver: Resolver = _default_resolve,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
    ) -> None:
        self._http_client = http_client
        self._resolver = resolver
        self._timeout_s = timeout_s
        self._max_response_bytes = max_response_bytes

    async def get_discovery(self, discovery_url: str, *, auth: TaxiiAuth) -> TaxiiDiscovery:
        body = await self._get_json(discovery_url, auth=auth)
        if not isinstance(body, dict):
            raise TaxiiResponseFormatError("TAXII discovery response is not a JSON object")
        api_roots = tuple(r for r in (body.get("api_roots") or []) if isinstance(r, str))
        return TaxiiDiscovery(
            title=str(body.get("title") or ""),
            description=body.get("description"),
            api_roots=api_roots,
            default=body.get("default") if isinstance(body.get("default"), str) else None,
        )

    async def get_collections(
        self, api_root_url: str, *, auth: TaxiiAuth
    ) -> tuple[TaxiiCollection, ...]:
        url = f"{api_root_url.rstrip('/')}/collections/"
        body = await self._get_json(url, auth=auth)
        if not isinstance(body, dict):
            raise TaxiiResponseFormatError("TAXII collections response is not a JSON object")
        raw_collections = body.get("collections")
        if not isinstance(raw_collections, list):
            raise TaxiiResponseFormatError("TAXII collections response missing 'collections'")
        return tuple(
            self._parse_collection(c) for c in raw_collections if isinstance(c, dict)
        )

    async def get_collection(
        self, api_root_url: str, collection_id: str, *, auth: TaxiiAuth
    ) -> TaxiiCollection:
        url = f"{api_root_url.rstrip('/')}/collections/{collection_id}/"
        body = await self._get_json(url, auth=auth)
        if not isinstance(body, dict):
            raise TaxiiResponseFormatError("TAXII collection response is not a JSON object")
        return self._parse_collection(body)

    async def get_objects(
        self,
        api_root_url: str,
        collection_id: str,
        *,
        auth: TaxiiAuth,
        added_after: str | None = None,
        limit: int = DEFAULT_PAGE_LIMIT,
        next_cursor: str | None = None,
    ) -> TaxiiEnvelope:
        url = f"{api_root_url.rstrip('/')}/collections/{collection_id}/objects/"
        params: dict[str, str] = {"limit": str(limit)}
        if added_after:
            params["added_after"] = added_after
        if next_cursor:
            params["next"] = next_cursor
        body = await self._get_json(url, auth=auth, params=params)
        if not isinstance(body, dict):
            raise TaxiiResponseFormatError("TAXII objects response is not a JSON object")
        raw_objects = body.get("objects", [])
        if not isinstance(raw_objects, list):
            raise TaxiiResponseFormatError("TAXII objects response 'objects' is not an array")
        return TaxiiEnvelope(
            objects=tuple(o for o in raw_objects if isinstance(o, dict)),
            more=bool(body.get("more", False)),
            next=body.get("next") if isinstance(body.get("next"), str) else None,
        )

    # ── internal ──────────────────────────────────────────────────────

    @staticmethod
    def _parse_collection(body: dict[str, Any]) -> TaxiiCollection:
        collection_id = body.get("id")
        if not isinstance(collection_id, str) or not collection_id:
            raise TaxiiResponseFormatError("TAXII collection resource missing 'id'")
        title = body.get("title")
        if not isinstance(title, str) or not title:
            title = collection_id
        media_types = tuple(m for m in (body.get("media_types") or []) if isinstance(m, str))
        return TaxiiCollection(
            id=collection_id,
            title=title,
            description=body.get("description"),
            can_read=bool(body.get("can_read", False)),
            can_write=bool(body.get("can_write", False)),
            media_types=media_types,
        )

    async def _get_json(
        self,
        url: str,
        *,
        auth: TaxiiAuth,
        params: dict[str, str] | None = None,
    ) -> Any:
        await validate_ssrf_safe(url, resolver=self._resolver)

        headers = {"Accept": TAXII_MEDIA_TYPE, **auth.headers()}
        client = self._http_client
        owns_client = client is None
        if client is None:
            client = httpx.AsyncClient(timeout=self._timeout_s, follow_redirects=False, verify=True)
        try:
            try:
                response = await client.get(
                    url, headers=headers, params=params, auth=auth.httpx_auth()
                )
            except httpx.TimeoutException as exc:
                raise TaxiiRequestError(f"TAXII request to {url} timed out") from exc
            except httpx.TransportError as exc:
                raise TaxiiRequestError(f"TAXII request to {url} failed: {exc}") from exc

            content_length = response.headers.get("content-length")
            if (
                content_length is not None
                and content_length.isdigit()
                and int(content_length) > self._max_response_bytes
            ):
                raise TaxiiResponseTooLargeError(
                    f"TAXII response from {url} declared {content_length} bytes, "
                    f"exceeding the {self._max_response_bytes}-byte cap"
                )
            body = response.content
            if len(body) > self._max_response_bytes:
                raise TaxiiResponseTooLargeError(
                    f"TAXII response from {url} was {len(body)} bytes, "
                    f"exceeding the {self._max_response_bytes}-byte cap"
                )

            if response.status_code in (401, 403):
                raise TaxiiAuthenticationError(
                    f"TAXII server rejected credentials for {url} "
                    f"(HTTP {response.status_code})",
                    status_code=response.status_code,
                )
            if response.status_code >= 300:
                raise TaxiiRequestError(
                    f"TAXII request to {url} failed with HTTP {response.status_code}",
                    status_code=response.status_code,
                )

            try:
                return json.loads(body)
            except json.JSONDecodeError as exc:
                raise TaxiiResponseFormatError(f"non-JSON response from {url}: {exc}") from exc
        finally:
            if owns_client:
                await client.aclose()
