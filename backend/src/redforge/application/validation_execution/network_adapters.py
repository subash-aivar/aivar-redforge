"""Real, bounded, non-destructive network adapters for M11 active
validation: DNS resolution, TCP connectivity, TLS handshake + cert
metadata, HTTP metadata (with per-hop-revalidated redirects), and
deterministic security-header rule checks.

Every adapter here is a pure async function taking explicit bounds
(timeout, limits) — no adapter reads global config, and none of them
ever executes a client-supplied command, path, or expression. All
network destinations are derived entirely from a canonical
`AITarget.endpoint` via `target_normalizer.normalize_target()` and
`network_boundary.classify_address()`.

Never persisted: Authorization headers, cookies, Set-Cookie values,
bearer tokens, response bodies (only metadata is read), private key
material.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx

from redforge.application.validation_execution.network_boundary import classify_address
from redforge.application.validation_execution.target_normalizer import (
    NormalizedTarget,
    normalize_target,
)
from redforge.domain.validation_execution.exceptions import TargetNormalizationError
from redforge.domain.validation_execution.value_objects import (
    ALLOWED_ADDRESS_CLASSES,
    DiscoveryPortOutcome,
    ErrorCategory,
)

_REDACTED_HEADER_NAMES = frozenset({
    "authorization", "cookie", "set-cookie", "proxy-authorization", "www-authenticate",
})


# ─── DNS ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class DnsResult:
    hostname: str
    resolved_addresses: tuple[str, ...]
    denied_address: str | None = None
    denied_class: str | None = None
    error_category: ErrorCategory | None = None

    @property
    def ok(self) -> bool:
        return self.error_category is None and self.denied_address is None


async def resolve_dns(
    hostname: str, timeout: float, max_addresses: int, retry_attempts: int,
) -> DnsResult:
    """Bounded async DNS resolution with bounded retry on transient
    failure — no unlimited retry, no retry storm. Every resolved
    address is classified; the first non-PUBLIC address found denies
    the whole resolution (fail closed) rather than silently dropping it."""
    loop = asyncio.get_event_loop()
    attempts = max(1, retry_attempts + 1)

    for attempt in range(attempts):
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM), timeout=timeout,
            )
        except TimeoutError:
            if attempt == attempts - 1:
                return DnsResult(hostname, (), error_category=ErrorCategory.TIMEOUT)
            continue
        except socket.gaierror:
            if attempt == attempts - 1:
                return DnsResult(hostname, (), error_category=ErrorCategory.DNS_FAILURE)
            continue

        addresses: list[str] = []
        for _family, _type, _proto, _canonname, sockaddr in infos:
            addr = str(sockaddr[0])
            if addr not in addresses:
                addresses.append(addr)
            if len(addresses) >= max_addresses:
                break

        for addr in addresses:
            addr_class = classify_address(addr)
            if addr_class not in ALLOWED_ADDRESS_CLASSES:
                return DnsResult(
                    hostname, tuple(addresses),
                    denied_address=addr, denied_class=addr_class.value,
                )
        return DnsResult(hostname, tuple(addresses))

    return DnsResult(hostname, (), error_category=ErrorCategory.DNS_FAILURE)  # pragma: no cover


# ─── TCP connectivity ───────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class TcpResult:
    address: str
    port: int
    reachable: bool
    latency_ms: float | None = None
    error_category: ErrorCategory | None = None


async def check_tcp_connectivity(address: str, port: int, timeout: float) -> TcpResult:
    start = time.perf_counter()
    writer: asyncio.StreamWriter | None = None
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port), timeout=timeout,
        )
        latency_ms = (time.perf_counter() - start) * 1000
        return TcpResult(address, port, reachable=True, latency_ms=round(latency_ms, 2))
    except TimeoutError:
        return TcpResult(address, port, reachable=False, error_category=ErrorCategory.TIMEOUT)
    except (ConnectionRefusedError, OSError):
        return TcpResult(
            address, port, reachable=False, error_category=ErrorCategory.CONNECTION_REFUSED,
        )
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()


# ─── TLS handshake ──────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class TlsResult:
    success: bool
    protocol_version: str | None = None
    cipher_name: str | None = None
    subject_common_name: str | None = None
    issuer_common_name: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    san_count: int = 0
    fingerprint_sha256: str | None = None
    hostname_verified: bool = False
    error_category: ErrorCategory | None = None


def _extract_common_name(name_tuples: tuple[tuple[tuple[str, str], ...], ...]) -> str | None:
    for rdn in name_tuples:
        for key, value in rdn:
            if key == "commonName":
                return str(value)
    return None


async def perform_tls_handshake(
    address: str, hostname: str, port: int, timeout: float,
) -> TlsResult:
    """Real TLS handshake via the standard library's ssl module —
    verifies the certificate chain and hostname using the platform's
    default trust store (same as any well-behaved HTTPS client). Never
    stores private key material (there is none to store — this is the
    client side of the handshake) and never stores the raw certificate
    bytes, only bounded derived metadata."""
    context = ssl.create_default_context()
    writer: asyncio.StreamWriter | None = None
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port, ssl=context, server_hostname=hostname),
            timeout=timeout,
        )
        assert writer is not None
        ssl_object = writer.get_extra_info("ssl_object")
        if ssl_object is None:
            return TlsResult(success=False, error_category=ErrorCategory.TLS_FAILURE)

        cert = ssl_object.getpeercert()
        der_cert = ssl_object.getpeercert(binary_form=True)
        fingerprint = hashlib.sha256(der_cert).hexdigest() if der_cert else None
        cipher_info = ssl_object.cipher()  # (name, tls_version, secret_bits)

        return TlsResult(
            success=True,
            protocol_version=ssl_object.version(),
            cipher_name=cipher_info[0] if cipher_info else None,
            subject_common_name=_extract_common_name(cert.get("subject", ())) if cert else None,
            issuer_common_name=_extract_common_name(cert.get("issuer", ())) if cert else None,
            not_before=cert.get("notBefore") if cert else None,
            not_after=cert.get("notAfter") if cert else None,
            san_count=len(cert.get("subjectAltName", ())) if cert else 0,
            fingerprint_sha256=fingerprint,
            hostname_verified=True,  # ssl.create_default_context() enforces this or raises
        )
    except ssl.SSLCertVerificationError:
        return TlsResult(
            success=False, hostname_verified=False, error_category=ErrorCategory.TLS_FAILURE,
        )
    except TimeoutError:
        return TlsResult(success=False, error_category=ErrorCategory.TIMEOUT)
    except (ssl.SSLError, OSError):
        return TlsResult(success=False, error_category=ErrorCategory.TLS_FAILURE)
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()


# ─── HTTP metadata (with per-hop-revalidated redirects) ────────────────────


@dataclass(frozen=True, slots=True)
class HttpHop:
    url: str
    status_code: int


@dataclass(frozen=True, slots=True)
class HttpResult:
    success: bool
    final_url: str | None = None
    status_code: int | None = None
    content_type: str | None = None
    content_length: int | None = None
    server_header: str | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    redirect_chain: tuple[HttpHop, ...] = ()
    error_category: ErrorCategory | None = None


async def fetch_http_metadata(
    target: NormalizedTarget,
    resolved_addresses: tuple[str, ...],
    timeout: float,
    redirect_limit: int,
    dns_timeout: float,
    dns_retry_attempts: int,
) -> HttpResult:
    """Fetch response metadata only — never reads/returns the response
    body. Redirects are followed manually (never httpx's automatic
    `follow_redirects`) so every hop can be independently revalidated:
    scheme/userinfo/host-syntax normalized, DNS re-resolved, and every
    resolved address re-checked against the network boundary. A hop is
    additionally only followed if the resolved address set stays within
    the ORIGINAL target's own validated resolution set — the DNS
    rebinding / "redirect to a foreign target" defense: a genuinely
    different target resolves to different addresses and is refused."""
    current = target
    allowed_address_set = set(resolved_addresses)
    chain: list[HttpHop] = []
    redacted_response_headers: dict[str, str] = {}

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout), follow_redirects=False, verify=True,
    ) as client:
        for _hop in range(redirect_limit + 1):
            query_suffix = f"?{current.query}" if current.query else ""
            url = f"{current.base_url}{current.path}{query_suffix}"
            try:
                response = await client.get(url)
            except httpx.TimeoutException:
                return HttpResult(success=False, error_category=ErrorCategory.TIMEOUT)
            except httpx.TransportError:
                return HttpResult(success=False, error_category=ErrorCategory.CONNECTION_REFUSED)

            redacted_response_headers = {
                k: v for k, v in response.headers.items() if k.lower() not in _REDACTED_HEADER_NAMES
            }

            if response.status_code in (301, 302, 303, 307, 308) and "location" in response.headers:
                chain.append(HttpHop(url=url, status_code=response.status_code))
                location = response.headers["location"]
                try:
                    next_target = normalize_target(location)
                except TargetNormalizationError:
                    return HttpResult(
                        success=False, error_category=ErrorCategory.NETWORK_BOUNDARY_DENIED,
                        redirect_chain=tuple(chain),
                    )

                hop_dns = await resolve_dns(
                    next_target.hostname, dns_timeout, len(allowed_address_set) or 4,
                    dns_retry_attempts,
                )
                if not hop_dns.ok:
                    return HttpResult(
                        success=False, error_category=ErrorCategory.NETWORK_BOUNDARY_DENIED,
                        redirect_chain=tuple(chain),
                    )
                if not allowed_address_set.intersection(hop_dns.resolved_addresses):
                    # Redirect resolves to addresses outside the
                    # original target's validated set — refuse as a
                    # foreign-target/rebinding pivot, regardless of
                    # whether those addresses are individually public.
                    return HttpResult(
                        success=False, error_category=ErrorCategory.NETWORK_BOUNDARY_DENIED,
                        redirect_chain=tuple(chain),
                    )
                current = next_target
                continue

            content_length_raw = response.headers.get("content-length")
            return HttpResult(
                success=True,
                final_url=url,
                status_code=response.status_code,
                content_type=response.headers.get("content-type"),
                content_length=(
                    int(content_length_raw)
                    if content_length_raw and content_length_raw.isdigit()
                    else None
                ),
                server_header=response.headers.get("server"),
                response_headers=redacted_response_headers,
                redirect_chain=tuple(chain),
            )

    return HttpResult(
        success=False, error_category=ErrorCategory.REDIRECT_LIMIT_EXCEEDED,
        redirect_chain=tuple(chain),
    )


# ─── Security headers (pure, no I/O) ───────────────────────────────────────


STABLE_RULE_MISSING_HSTS = "MISSING_HSTS_HEADER"
STABLE_RULE_MISSING_CSP = "MISSING_CSP_HEADER"
STABLE_RULE_MISSING_X_CONTENT_TYPE_OPTIONS = "MISSING_X_CONTENT_TYPE_OPTIONS_HEADER"


@dataclass(frozen=True, slots=True)
class SecurityHeaderFinding:
    stable_rule_id: str
    title: str
    summary: str
    remediation: str


def evaluate_security_headers(
    response_headers: dict[str, str], is_https: bool,
) -> tuple[SecurityHeaderFinding, ...]:
    """Deterministic, exact-response-driven header checks only — never
    an inference, never a claim of exploitability. Headers are matched
    case-insensitively (HTTP header names are case-insensitive)."""
    lower_headers = {k.lower() for k in response_headers}
    findings: list[SecurityHeaderFinding] = []

    if is_https and "strict-transport-security" not in lower_headers:
        findings.append(SecurityHeaderFinding(
            stable_rule_id=STABLE_RULE_MISSING_HSTS,
            title="Missing Strict-Transport-Security header",
            summary="The HTTPS response did not include a Strict-Transport-Security header.",
            remediation=(
                "Enable Strict-Transport-Security after confirming HTTPS-only operation."
            ),
        ))
    if "content-security-policy" not in lower_headers:
        findings.append(SecurityHeaderFinding(
            stable_rule_id=STABLE_RULE_MISSING_CSP,
            title="Missing Content-Security-Policy header",
            summary="The response did not include a Content-Security-Policy header.",
            remediation="Add a restrictive Content-Security-Policy.",
        ))
    if "x-content-type-options" not in lower_headers:
        findings.append(SecurityHeaderFinding(
            stable_rule_id=STABLE_RULE_MISSING_X_CONTENT_TYPE_OPTIONS,
            title="Missing X-Content-Type-Options header",
            summary="The response did not include an X-Content-Type-Options header.",
            remediation="Add 'X-Content-Type-Options: nosniff' to all responses.",
        ))
    return tuple(findings)


# ─── TLS findings (pure, no I/O) — M13 ─────────────────────────────────────


STABLE_RULE_TLS_CERTIFICATE_EXPIRED = "TLS_CERTIFICATE_EXPIRED"
STABLE_RULE_TLS_SELF_SIGNED_CERTIFICATE_OBSERVED = "TLS_SELF_SIGNED_CERTIFICATE_OBSERVED"
STABLE_RULE_DEPRECATED_TLS_PROTOCOL_OBSERVED = "DEPRECATED_TLS_PROTOCOL_OBSERVED"

# ssl.SSLObject.version() returns one of these literal strings — never a
# free-form guess. Anything not in this set (TLSv1.2, TLSv1.3) is
# current and never flagged.
_DEPRECATED_TLS_VERSIONS = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"})


def evaluate_tls_findings(tls: TlsResult, now_utc: str) -> tuple[SecurityHeaderFinding, ...]:
    """Deterministic, exact-evidence-driven TLS checks only — reuses the
    same `TlsResult` fields M11's own TLS_HANDSHAKE step already
    captures (protocol_version/subject_common_name/issuer_common_name/
    not_after); no new adapter or network round-trip is required. Never
    infers a CVE or exploitability claim from a protocol version or
    certificate field — only the deterministic facts below.

    `now_utc` is an ISO-8601 UTC timestamp string supplied by the caller
    (never `datetime.now()` computed inside this pure function) so the
    comparison is explicit and testable."""
    if not tls.success:
        return ()

    findings: list[SecurityHeaderFinding] = []

    if tls.protocol_version in _DEPRECATED_TLS_VERSIONS:
        findings.append(SecurityHeaderFinding(
            stable_rule_id=STABLE_RULE_DEPRECATED_TLS_PROTOCOL_OBSERVED,
            title="Deprecated TLS protocol version observed",
            summary=f"The server negotiated {tls.protocol_version}, a deprecated TLS version.",
            remediation="Disable TLS versions older than TLS 1.2 on this endpoint.",
        ))

    if (
        tls.subject_common_name
        and tls.issuer_common_name
        and tls.subject_common_name == tls.issuer_common_name
    ):
        findings.append(SecurityHeaderFinding(
            stable_rule_id=STABLE_RULE_TLS_SELF_SIGNED_CERTIFICATE_OBSERVED,
            title="Self-signed TLS certificate observed",
            summary=(
                f"The certificate's subject and issuer common name are both "
                f"'{tls.subject_common_name}' — a self-signed certificate."
            ),
            remediation="Replace with a certificate issued by a trusted certificate authority.",
        ))

    if tls.not_after:
        try:
            # Python's ssl module's own fixed notAfter/notBefore format.
            expiry = datetime.strptime(tls.not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
            now = datetime.fromisoformat(now_utc)
            if now.tzinfo is None:
                now = now.replace(tzinfo=UTC)
            if expiry <= now:
                findings.append(SecurityHeaderFinding(
                    stable_rule_id=STABLE_RULE_TLS_CERTIFICATE_EXPIRED,
                    title="TLS certificate has expired",
                    summary=f"The certificate expired {tls.not_after}.",
                    remediation="Renew the TLS certificate immediately.",
                ))
        except ValueError:
            pass  # unparseable date format — never crash, never guess

    return tuple(findings)


# ─── Service reachability (explicit semantics) ─────────────────────────────


@dataclass(frozen=True, slots=True)
class ServiceReachabilityResult:
    """Deliberately distinct from TcpResult: PORT CONNECTIVITY OBSERVED
    (a TCP connect succeeded) is never conflated with SERVICE
    REACHABILITY VALIDATED (an application-layer response was actually
    observed on that port — e.g. an HTTP response, or a completed TLS
    handshake). A bare open TCP port proves only that something
    accepted the connection, not what it is or that it is healthy."""

    tcp_reachable: bool
    application_layer_validated: bool
    validation_basis: str | None = None


# ─── Bounded port discovery (M12) ──────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class PortDiscoveryEntry:
    address: str
    port: int
    outcome: DiscoveryPortOutcome
    latency_ms: float | None = None


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    entries: tuple[PortDiscoveryEntry, ...]

    @property
    def reachable_ports(self) -> tuple[int, ...]:
        return tuple(
            sorted({e.port for e in self.entries if e.outcome == DiscoveryPortOutcome.REACHABLE})
        )

    def best_outcome_for_port(self, port: int) -> DiscoveryPortOutcome:
        """One representative outcome for a port across every resolved
        address checked — REACHABLE wins if any address showed it
        (a bounded discovery run typically resolves to very few
        addresses, so this is a simple, deterministic aggregate, never
        a majority vote or heuristic)."""
        port_entries = [e for e in self.entries if e.port == port]
        if not port_entries:
            return DiscoveryPortOutcome.UNREACHABLE
        for entry in port_entries:
            if entry.outcome == DiscoveryPortOutcome.REACHABLE:
                return DiscoveryPortOutcome.REACHABLE
        return port_entries[0].outcome


def _classify_tcp_result(result: TcpResult) -> DiscoveryPortOutcome:
    if result.reachable:
        return DiscoveryPortOutcome.REACHABLE
    if result.error_category == ErrorCategory.TIMEOUT:
        return DiscoveryPortOutcome.TIMEOUT
    if result.error_category == ErrorCategory.CONNECTION_REFUSED:
        return DiscoveryPortOutcome.UNREACHABLE
    return DiscoveryPortOutcome.NETWORK_ERROR


async def discover_ports(
    addresses: tuple[str, ...],
    ports: tuple[int, ...],
    timeout: float,
    max_concurrency: int,
) -> DiscoveryResult:
    """Bounded TCP-connect discovery against the target's OWN already-
    resolved, already-boundary-checked address set — never an arbitrary
    CIDR/network range (that is a different product surface; see M6's
    connector-scoped `BoundedNetworkScanAdapter`, deliberately not reused
    here since it has no concept of M10/M11's authorization boundary).

    Reuses `check_tcp_connectivity()` unchanged — this is the exact same
    real `asyncio.open_connection()` primitive every other M11 step uses,
    just invoked over a small, closed, versioned port list instead of
    once for the target's own endpoint port. No new socket-level
    capability is introduced."""
    semaphore = asyncio.Semaphore(max(1, max_concurrency))

    async def _check(address: str, port: int) -> PortDiscoveryEntry:
        async with semaphore:
            result = await check_tcp_connectivity(address, port, timeout)
        return PortDiscoveryEntry(
            address=address, port=port, outcome=_classify_tcp_result(result),
            latency_ms=result.latency_ms,
        )

    entries = await asyncio.gather(*(_check(a, p) for a in addresses for p in ports))
    return DiscoveryResult(entries=tuple(entries))
