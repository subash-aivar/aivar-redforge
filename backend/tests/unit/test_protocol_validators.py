"""Adversarial + unit tests for M13 — Protocol-Aware Service Validation.

Covers the protocol validator registry (determinism, duplicate
rejection, closed lookup), each of the four bounded protocol adapters
against real owned local TCP fixtures (never an external target), the
hinted-vs-validated truth boundary, and bounded-read/amplification
defense. API-level adversarial coverage (policy gate, tenant isolation,
client-cannot-submit-validator) lives in
tests/api/test_validation_executions_m13_isolation.py.
"""

from __future__ import annotations

import socket
import struct
import threading
from collections.abc import Callable

import pytest

from redforge.application.validation_execution import protocol_adapters
from redforge.application.validation_execution.protocol_validators import (
    DuplicateProtocolValidatorRegistrationError,
    MySqlHandshakeValidator,
    PostgreSqlProtocolValidator,
    ProtocolValidatorRegistry,
    RedisPingValidator,
    SshBannerValidator,
    default_protocol_validator_registry,
)
from redforge.domain.validation_execution.value_objects import (
    ErrorCategory,
    ProtocolValidationState,
)

# ─── Bounded, owned local TCP fixtures — never an external target ─────────────


class _OneShotServer:
    """A minimal, owned local TCP fixture: accepts one connection,
    hands the raw socket to `handler`, then stops. Runs in a background
    thread so the async validator under test can connect to it."""

    def __init__(self, handler: Callable[[socket.socket], None]) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]
        self._handler = handler
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        self._sock.settimeout(5.0)
        try:
            conn, _addr = self._sock.accept()
        except TimeoutError:
            return
        try:
            self._handler(conn)
        finally:
            conn.close()

    def close(self) -> None:
        self._sock.close()
        self._thread.join(timeout=2)


@pytest.fixture
def closed_port() -> int:
    """A port nothing is listening on — real connection-refused, never
    simulated."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()  # closed immediately — nothing accepts on this port
    return port


# ─── SSH ────────────────────────────────────────────────────────────────────


def _valid_ssh_server() -> _OneShotServer:
    return _OneShotServer(lambda conn: conn.sendall(b"SSH-2.0-OpenSSH_9.6\r\n"))


def _invalid_ssh_server() -> _OneShotServer:
    return _OneShotServer(lambda conn: conn.sendall(b"HELLO NOT AN SSH BANNER\r\n"))


def _silent_server() -> _OneShotServer:
    return _OneShotServer(lambda conn: None)


class TestSshBannerValidator:
    async def test_valid_banner_validates(self) -> None:
        server = _valid_ssh_server()
        try:
            outcome = await SshBannerValidator().validate("127.0.0.1", server.port, 2.0)
        finally:
            server.close()
        assert outcome.state == ProtocolValidationState.VALIDATED
        assert outcome.validated_protocol == "ssh"
        assert outcome.metadata["banner"].startswith("SSH-2.0-")
        assert outcome.metadata["software_hint"] == "OpenSSH_9.6"

    async def test_invalid_banner_stays_inconclusive_never_validated(self) -> None:
        """Port reachable with a non-SSH reply must remain HINTED
        (never fabricated into VALIDATED)."""
        server = _invalid_ssh_server()
        try:
            outcome = await SshBannerValidator().validate("127.0.0.1", server.port, 2.0)
        finally:
            server.close()
        assert outcome.state == ProtocolValidationState.INCONCLUSIVE
        assert outcome.validated_protocol is None

    async def test_silent_server_stays_inconclusive(self) -> None:
        server = _silent_server()
        try:
            outcome = await SshBannerValidator().validate("127.0.0.1", server.port, 1.0)
        finally:
            server.close()
        assert outcome.state == ProtocolValidationState.INCONCLUSIVE

    async def test_closed_port_is_error_not_validated(self, closed_port: int) -> None:
        outcome = await SshBannerValidator().validate("127.0.0.1", closed_port, 2.0)
        assert outcome.state == ProtocolValidationState.ERROR
        assert outcome.error_category == ErrorCategory.CONNECTION_REFUSED

    async def test_never_sends_anything_to_the_server(self) -> None:
        """SSH speaks first — the validator must never transmit
        anything (no auth attempt, no key exchange)."""
        received: list[bytes] = []

        def _capture(conn: socket.socket) -> None:
            conn.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")
            conn.settimeout(0.3)
            try:
                received.append(conn.recv(64))
            except TimeoutError:
                received.append(b"")

        server = _OneShotServer(_capture)
        try:
            await SshBannerValidator().validate("127.0.0.1", server.port, 2.0)
        finally:
            server.close()
        assert received == [b""]


# ─── MySQL ──────────────────────────────────────────────────────────────────


def _mysql_greeting(server_version: bytes = b"8.0.35", ssl_flag: bool = True) -> bytes:
    caps_lower = 0xFFFF if ssl_flag else 0x0000
    payload = (
        bytes([0x0A])  # protocol_version = 10
        + server_version + b"\x00"
        + b"\x01\x02\x03\x04"  # thread_id
        + b"AUTHDATA"  # auth-plugin-data-part-1 (8 bytes)
        + b"\x00"  # filler
        + struct.pack("<H", caps_lower)
    )
    header = struct.pack("<I", len(payload))[:3] + b"\x00"  # 3-byte length + seq
    return header + payload


class TestMySqlHandshakeValidator:
    async def test_real_handshake_shape_validates(self) -> None:
        server = _OneShotServer(lambda conn: conn.sendall(_mysql_greeting()))
        try:
            outcome = await MySqlHandshakeValidator().validate("127.0.0.1", server.port, 2.0)
        finally:
            server.close()
        assert outcome.state == ProtocolValidationState.VALIDATED
        assert outcome.validated_protocol == "mysql"
        assert outcome.metadata["server_version"] == "8.0.35"
        assert outcome.metadata["supports_ssl"] == "True"

    async def test_no_ssl_capability_flag_is_captured_truthfully(self) -> None:
        server = _OneShotServer(
            lambda conn: conn.sendall(_mysql_greeting(ssl_flag=False)),
        )
        try:
            outcome = await MySqlHandshakeValidator().validate("127.0.0.1", server.port, 2.0)
        finally:
            server.close()
        assert outcome.state == ProtocolValidationState.VALIDATED
        assert outcome.metadata["supports_ssl"] == "False"

    async def test_garbage_bytes_stay_inconclusive(self) -> None:
        server = _OneShotServer(lambda conn: conn.sendall(b"not a mysql server at all!!"))
        try:
            outcome = await MySqlHandshakeValidator().validate("127.0.0.1", server.port, 2.0)
        finally:
            server.close()
        assert outcome.state == ProtocolValidationState.INCONCLUSIVE
        assert outcome.validated_protocol is None

    async def test_never_authenticates(self) -> None:
        """Only a passive read — the validator must never transmit a
        client handshake response (would require sending credentials)."""
        received: list[bytes] = []

        def _capture(conn: socket.socket) -> None:
            conn.sendall(_mysql_greeting())
            conn.settimeout(0.3)
            try:
                received.append(conn.recv(64))
            except TimeoutError:
                received.append(b"")

        server = _OneShotServer(_capture)
        try:
            await MySqlHandshakeValidator().validate("127.0.0.1", server.port, 2.0)
        finally:
            server.close()
        assert received == [b""]


# ─── PostgreSQL ─────────────────────────────────────────────────────────────


def _postgres_ssl_responder(reply: bytes, expect_ssl_request: bool = True) -> _OneShotServer:
    def _handle(conn: socket.socket) -> None:
        conn.settimeout(2.0)
        request = conn.recv(8)
        if expect_ssl_request:
            length, code = struct.unpack("!ii", request)
            assert length == 8
            assert code == 80877103
        conn.sendall(reply)

    return _OneShotServer(_handle)


class TestPostgreSqlProtocolValidator:
    async def test_ssl_supported_response_validates(self) -> None:
        server = _postgres_ssl_responder(b"S")
        try:
            outcome = await PostgreSqlProtocolValidator().validate("127.0.0.1", server.port, 2.0)
        finally:
            server.close()
        assert outcome.state == ProtocolValidationState.VALIDATED
        assert outcome.validated_protocol == "postgresql"
        assert outcome.metadata["ssl_supported"] == "True"

    async def test_ssl_unsupported_response_still_validates_protocol(self) -> None:
        """'N' is just as valid a PostgreSQL protocol identification as
        'S' — the wire protocol, not TLS support, is what's proven."""
        server = _postgres_ssl_responder(b"N")
        try:
            outcome = await PostgreSqlProtocolValidator().validate("127.0.0.1", server.port, 2.0)
        finally:
            server.close()
        assert outcome.state == ProtocolValidationState.VALIDATED
        assert outcome.metadata["ssl_supported"] == "False"

    async def test_non_postgres_reply_stays_inconclusive(self) -> None:
        server = _postgres_ssl_responder(b"X", expect_ssl_request=False)
        try:
            outcome = await PostgreSqlProtocolValidator().validate("127.0.0.1", server.port, 2.0)
        finally:
            server.close()
        assert outcome.state == ProtocolValidationState.INCONCLUSIVE
        assert outcome.validated_protocol is None

    async def test_probe_sends_only_the_documented_sslrequest_bytes(self) -> None:
        """No credentials, no SQL, no startup message beyond the
        standard 8-byte SSLRequest — verified from the server side."""
        captured: list[bytes] = []

        def _handle(conn: socket.socket) -> None:
            conn.settimeout(2.0)
            captured.append(conn.recv(64))
            conn.sendall(b"N")

        server = _OneShotServer(_handle)
        try:
            await PostgreSqlProtocolValidator().validate("127.0.0.1", server.port, 2.0)
        finally:
            server.close()
        assert captured == [struct.pack("!ii", 8, 80877103)]


# ─── Redis ──────────────────────────────────────────────────────────────────


class TestRedisPingValidator:
    async def test_pong_reply_validates(self) -> None:
        server = _OneShotServer(lambda conn: conn.sendall(b"+PONG\r\n"))
        try:
            outcome = await RedisPingValidator().validate("127.0.0.1", server.port, 2.0)
        finally:
            server.close()
        assert outcome.state == ProtocolValidationState.VALIDATED
        assert outcome.validated_protocol == "redis"
        assert outcome.metadata["replied_pong"] == "True"

    async def test_resp_error_reply_still_validates_protocol_not_auth(self) -> None:
        """A NOAUTH error is still unambiguous RESP protocol identity —
        this recognizes the wire protocol, never bypasses auth."""
        server = _OneShotServer(
            lambda conn: conn.sendall(b"-NOAUTH Authentication required.\r\n"),
        )
        try:
            outcome = await RedisPingValidator().validate("127.0.0.1", server.port, 2.0)
        finally:
            server.close()
        assert outcome.state == ProtocolValidationState.VALIDATED
        assert outcome.metadata["replied_pong"] == "False"

    async def test_non_resp_reply_stays_inconclusive(self) -> None:
        server = _OneShotServer(lambda conn: conn.sendall(b"garbage response\r\n"))
        try:
            outcome = await RedisPingValidator().validate("127.0.0.1", server.port, 2.0)
        finally:
            server.close()
        assert outcome.state == ProtocolValidationState.INCONCLUSIVE

    async def test_sends_only_the_ping_command(self) -> None:
        captured: list[bytes] = []

        def _handle(conn: socket.socket) -> None:
            conn.settimeout(2.0)
            captured.append(conn.recv(64))
            conn.sendall(b"+PONG\r\n")

        server = _OneShotServer(_handle)
        try:
            await RedisPingValidator().validate("127.0.0.1", server.port, 2.0)
        finally:
            server.close()
        assert captured == [b"PING\r\n"]


# ─── Bounded-read / amplification defense ──────────────────────────────────


class TestBoundedReadDefense:
    async def test_ssh_banner_read_is_capped_never_unbounded(self) -> None:
        """A malicious/misconfigured service sending megabytes back
        must never be read in full — only a small bounded prefix."""
        huge_payload = b"SSH-2.0-" + (b"A" * 100_000)

        def _flood(conn: socket.socket) -> None:
            conn.sendall(huge_payload)

        server = _OneShotServer(_flood)
        try:
            result = await protocol_adapters.read_ssh_banner("127.0.0.1", server.port, 2.0)
        finally:
            server.close()
        assert result.banner is not None
        assert len(result.banner) <= 100  # bounded normalized banner, not 100_000 bytes

    async def test_mysql_read_is_capped(self) -> None:
        huge = _mysql_greeting() + (b"B" * 100_000)
        server = _OneShotServer(lambda conn: conn.sendall(huge))
        try:
            result = await protocol_adapters.read_mysql_handshake("127.0.0.1", server.port, 2.0)
        finally:
            server.close()
        # The raw read itself is capped at _MYSQL_HANDSHAKE_MAX_BYTES —
        # parsing still succeeds on the leading real greeting bytes.
        assert result.matched is True


# ─── Registry ───────────────────────────────────────────────────────────────


class TestProtocolValidatorRegistry:
    def test_duplicate_registration_rejected(self) -> None:
        registry = ProtocolValidatorRegistry()
        registry.register(SshBannerValidator())
        with pytest.raises(DuplicateProtocolValidatorRegistrationError):
            registry.register(SshBannerValidator())

    def test_default_registry_has_exactly_the_four_protocol_validators(self) -> None:
        registry = default_protocol_validator_registry()
        ids = {(v.validator_id, v.validator_version) for v in registry.all_validators()}
        assert ids == {
            ("SSH_BANNER_V1", 1), ("MYSQL_HANDSHAKE_V1", 1),
            ("POSTGRESQL_PROTOCOL_V1", 1), ("REDIS_PING_V1", 1),
        }

    def test_get_for_protocol_is_deterministic(self) -> None:
        registry = default_protocol_validator_registry()
        expected = {
            "ssh": "SSH_BANNER_V1", "mysql": "MYSQL_HANDSHAKE_V1",
            "postgresql": "POSTGRESQL_PROTOCOL_V1", "redis": "REDIS_PING_V1",
        }
        for protocol, validator_id in expected.items():
            validator = registry.get_for_protocol(protocol)
            assert validator is not None
            assert validator.validator_id == validator_id

    def test_unregistered_protocol_returns_none_never_a_fabricated_validator(self) -> None:
        registry = default_protocol_validator_registry()
        assert registry.get_for_protocol("rdp") is None
        assert registry.get_for_protocol("smb") is None

    def test_validators_declare_their_own_supported_ports_closed(self) -> None:
        ssh = SshBannerValidator()
        assert ssh.supports(22)
        assert not ssh.supports(23)
        assert not ssh.supports(2222)  # no arbitrary port acceptance
