"""Bounded, non-authenticating, non-mutating protocol-identification
reads for M13 — Protocol-Aware Service Validation.

Every function here does ONE thing: open a TCP connection to an already
policy-gated (address, port) pair, read (or, where the wire protocol
genuinely requires the client to speak first, send a single fixed,
well-documented, non-destructive probe) a small bounded number of
bytes, and deterministically classify the result. None of these
functions:

  - authenticate (no username, password, key, or token is ever sent)
  - execute a query/command against the service
  - enumerate databases, users, roles, keys, or accounts
  - mutate any server-side state
  - read an unbounded amount of data (every read has both an explicit
    byte cap and a timeout)

This module is the M13 analogue of `network_adapters.py`'s TCP/TLS/HTTP
adapters — pure I/O, no policy/business logic, no persistence. Only
`protocol_validators.py` (the closed, versioned registry) may call
these; there is no path from an HTTP request to this module.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import struct
from dataclasses import dataclass

from redforge.domain.validation_execution.value_objects import ErrorCategory

# Hard per-read byte caps — generous enough for any real server's
# identification banner/handshake greeting, nowhere near enough to
# accept an attacker-controlled amplification payload.
_SSH_BANNER_MAX_BYTES = 256
_MYSQL_HANDSHAKE_MAX_BYTES = 1024
_POSTGRES_RESPONSE_MAX_BYTES = 8
_REDIS_RESPONSE_MAX_BYTES = 256


async def _bounded_read(
    address: str, port: int, timeout: float, max_bytes: int, send: bytes | None = None,
) -> tuple[bytes | None, ErrorCategory | None]:
    """Shared connect-(optionally send)-bounded-read primitive. Returns
    `(data, None)` on any successful read (including an empty read on a
    clean EOF — the caller decides what an empty/short read means for
    its own protocol), or `(None, error_category)` on a network-level
    failure. Never raises past this function — every protocol validator
    built on top of it only ever has to reason about bytes-or-error."""
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port), timeout=timeout,
        )
        assert writer is not None
        if send is not None:
            writer.write(send)
            await asyncio.wait_for(writer.drain(), timeout=timeout)
        data = await asyncio.wait_for(reader.read(max_bytes), timeout=timeout)
        return data, None
    except TimeoutError:
        return None, ErrorCategory.TIMEOUT
    except (ConnectionRefusedError, OSError):
        return None, ErrorCategory.CONNECTION_REFUSED
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()


# ─── SSH ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class SshBannerResult:
    matched: bool
    banner: str | None = None
    software_hint: str | None = None
    error_category: ErrorCategory | None = None


_SSH_BANNER_RE = re.compile(r"^SSH-(1\.99|1\.5|2\.0)-(\S+)")


async def read_ssh_banner(address: str, port: int, timeout: float) -> SshBannerResult:
    """SSH servers speak FIRST (RFC 4253 §4.2) — the client never sends
    anything before receiving the server's own identification string.
    This is a purely passive read: no key exchange, no authentication,
    no data ever sent to the server."""
    data, error = await _bounded_read(address, port, timeout, _SSH_BANNER_MAX_BYTES)
    if error is not None:
        return SshBannerResult(matched=False, error_category=error)
    if not data:
        return SshBannerResult(matched=False)

    line = data.split(b"\r\n", 1)[0].split(b"\n", 1)[0].decode("ascii", errors="replace")
    match = _SSH_BANNER_RE.match(line)
    if match is None:
        return SshBannerResult(matched=False, banner=line[:100])
    return SshBannerResult(matched=True, banner=line[:100], software_hint=match.group(2)[:60])


# ─── MySQL ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class MySqlHandshakeResult:
    matched: bool
    protocol_version: int | None = None
    server_version: str | None = None
    supports_ssl: bool | None = None
    error_category: ErrorCategory | None = None


# capability_flags bit 11 (0x0800) is CLIENT_SSL in the MySQL/MariaDB
# wire protocol's initial handshake packet.
_MYSQL_CLIENT_SSL_FLAG = 0x0800


async def read_mysql_handshake(address: str, port: int, timeout: float) -> MySqlHandshakeResult:
    """MySQL/MariaDB servers send their initial handshake (greeting)
    packet immediately upon connection, before any authentication byte
    is exchanged (MySQL Client/Server Protocol, "Connection Phase").
    This function only PASSIVELY reads that one greeting packet and
    parses its fixed-position fields — it never replies, never sends
    credentials, never completes the handshake."""
    data, error = await _bounded_read(address, port, timeout, _MYSQL_HANDSHAKE_MAX_BYTES)
    if error is not None:
        return MySqlHandshakeResult(matched=False, error_category=error)
    # Smallest plausible greeting: 4-byte header + protocol_version(1) +
    # at least a 1-byte-terminated server_version + the fixed tail
    # fields up to capability_flags_lower — well under this floor and
    # we cannot reliably read anything.
    if not data or len(data) < 8:
        return MySqlHandshakeResult(matched=False)

    payload = data[4:]  # skip the 3-byte length + 1-byte sequence header
    protocol_version = payload[0]
    if protocol_version != 0x0A:
        return MySqlHandshakeResult(matched=False, protocol_version=protocol_version)

    null_index = payload.find(b"\x00", 1)
    if null_index == -1:
        return MySqlHandshakeResult(matched=True, protocol_version=protocol_version)
    server_version = payload[1:null_index].decode("ascii", errors="replace")[:80]

    # Fixed tail after the NUL-terminated server_version: thread_id(4) +
    # auth-plugin-data-part-1(8) + filler(1) + capability_flags_lower(2).
    caps_offset = null_index + 1 + 4 + 8 + 1
    supports_ssl: bool | None = None
    if len(payload) >= caps_offset + 2:
        caps_lower = int.from_bytes(payload[caps_offset : caps_offset + 2], "little")
        supports_ssl = bool(caps_lower & _MYSQL_CLIENT_SSL_FLAG)

    return MySqlHandshakeResult(
        matched=True, protocol_version=protocol_version,
        server_version=server_version, supports_ssl=supports_ssl,
    )


# ─── PostgreSQL ─────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class PostgreSqlProbeResult:
    matched: bool
    ssl_supported: bool | None = None
    error_category: ErrorCategory | None = None


# The SSLRequest message (PostgreSQL Frontend/Backend Protocol §55.2.2):
# a fixed 8-byte message — length(4)=8, then the reserved "SSL request
# code" 1234 in the high 16 bits / 5679 in the low 16 bits
# (80877103 as a big-endian 32-bit int). Every real PostgreSQL server
# replies with EXACTLY one byte: 'S' (will proceed with SSL) or 'N'
# (will continue in cleartext) — this is the documented, standard first
# message every PostgreSQL client driver sends before authentication;
# no credentials are included, no session is authenticated, nothing is
# mutated, and the TCP connection is closed immediately after.
_SSL_REQUEST_MESSAGE = struct.pack("!ii", 8, 80877103)


async def probe_postgresql(address: str, port: int, timeout: float) -> PostgreSqlProbeResult:
    data, error = await _bounded_read(
        address, port, timeout, _POSTGRES_RESPONSE_MAX_BYTES, send=_SSL_REQUEST_MESSAGE,
    )
    if error is not None:
        return PostgreSqlProbeResult(matched=False, error_category=error)
    if not data:
        return PostgreSqlProbeResult(matched=False)
    first_byte = data[:1]
    if first_byte == b"S":
        return PostgreSqlProbeResult(matched=True, ssl_supported=True)
    if first_byte == b"N":
        return PostgreSqlProbeResult(matched=True, ssl_supported=False)
    return PostgreSqlProbeResult(matched=False)


# ─── Redis ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class RedisPingResult:
    matched: bool
    replied_pong: bool = False
    error_category: ErrorCategory | None = None


# PING is Redis's own documented liveness/identity command — read-only,
# idempotent, requires no prior state, and is the exact command every
# standard health-check/monitoring integration uses. No other command
# is ever sent by this validator.
_REDIS_PING_COMMAND = b"PING\r\n"


async def ping_redis(address: str, port: int, timeout: float) -> RedisPingResult:
    data, error = await _bounded_read(
        address, port, timeout, _REDIS_RESPONSE_MAX_BYTES, send=_REDIS_PING_COMMAND,
    )
    if error is not None:
        return RedisPingResult(matched=False, error_category=error)
    if not data:
        return RedisPingResult(matched=False)
    if data.startswith(b"+PONG"):
        return RedisPingResult(matched=True, replied_pong=True)
    if data.startswith(b"-"):
        # A RESP error reply (e.g. "-NOAUTH Authentication required.")
        # is still unambiguous proof of the RESP wire protocol — only a
        # Redis/RESP-compatible server replies in this exact shape.
        # This recognizes protocol identity; it never bypasses auth.
        return RedisPingResult(matched=True, replied_pong=False)
    return RedisPingResult(matched=False)
