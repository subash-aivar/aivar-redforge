"""Adversarial tests for M11's network boundary / SSRF / DNS-rebinding /
redirect protections — items 15-24, 30 of the M11 adversarial checklist.

Uses only owned local test HTTP servers (started in-process) — never an
external/unrelated internet target.
"""

from __future__ import annotations

import http.server
import threading

import pytest

from redforge.application.validation_execution import network_adapters
from redforge.application.validation_execution.network_adapters import (
    evaluate_security_headers,
    fetch_http_metadata,
)
from redforge.application.validation_execution.network_boundary import (
    classify_address,
    is_address_allowed,
)
from redforge.application.validation_execution.target_normalizer import (
    normalize_target,
)
from redforge.domain.validation_execution.exceptions import TargetNormalizationError
from redforge.domain.validation_execution.value_objects import AddressClass, ErrorCategory

# asyncio_mode = "auto" (pyproject.toml) auto-detects async tests — no
# pytestmark needed, and this module mixes sync and async test methods.


# ─── 15-19: address classification (SSRF categorical denial) ─────────────────


class TestAddressClassification:
    def test_loopback_denied(self) -> None:
        assert classify_address("127.0.0.1") == AddressClass.LOOPBACK
        assert classify_address("::1") == AddressClass.LOOPBACK
        assert not is_address_allowed("127.0.0.1")

    def test_link_local_denied(self) -> None:
        assert classify_address("169.254.1.1") == AddressClass.LINK_LOCAL
        assert not is_address_allowed("169.254.1.1")

    def test_metadata_endpoint_denied(self) -> None:
        assert classify_address("169.254.169.254") == AddressClass.METADATA
        assert not is_address_allowed("169.254.169.254")
        assert classify_address("fd00:ec2::254") == AddressClass.METADATA

    def test_multicast_denied(self) -> None:
        assert classify_address("224.0.0.1") == AddressClass.MULTICAST
        assert not is_address_allowed("224.0.0.1")

    def test_uncontrolled_private_pivot_denied(self) -> None:
        assert classify_address("10.0.0.5") == AddressClass.PRIVATE
        assert classify_address("192.168.1.1") == AddressClass.PRIVATE
        assert not is_address_allowed("10.0.0.5")

    def test_public_address_allowed(self) -> None:
        assert classify_address("8.8.8.8") == AddressClass.PUBLIC
        assert is_address_allowed("8.8.8.8")

    def test_malformed_address_denied_fail_safe(self) -> None:
        assert classify_address("not-an-ip") == AddressClass.RESERVED
        assert not is_address_allowed("not-an-ip")


# ─── Target normalization adversarial cases ───────────────────────────────────


class TestTargetNormalization:
    def test_malformed_url_rejected(self) -> None:
        with pytest.raises(TargetNormalizationError):
            normalize_target("not a url at all ::::")

    def test_unsupported_scheme_rejected(self) -> None:
        with pytest.raises(TargetNormalizationError):
            normalize_target("ftp://example.com/")
        with pytest.raises(TargetNormalizationError):
            normalize_target("file:///etc/passwd")
        with pytest.raises(TargetNormalizationError):
            normalize_target("gopher://example.com/")

    def test_url_userinfo_rejected(self) -> None:
        with pytest.raises(TargetNormalizationError):
            normalize_target("http://user:pass@example.com/")

    def test_ambiguous_host_syntax_rejected(self) -> None:
        with pytest.raises(TargetNormalizationError):
            normalize_target("http://")
        with pytest.raises(TargetNormalizationError):
            normalize_target("http:///path-no-host")


# ─── Local HTTP test server for redirect/header adversarial proof ────────────


_PORT = 18099


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/redirect-same-target":
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{_PORT}/landed")
            self.end_headers()
        elif self.path == "/redirect-forbidden":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()
        elif self.path == "/redirect-foreign":
            # Resolves to a genuinely different public address than the
            # original target's own validated resolution set.
            self.send_response(302)
            self.send_header("Location", "http://93.184.216.34/")
            self.end_headers()
        elif self.path == "/redirect-loop-a":
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{_PORT}/redirect-loop-b")
            self.end_headers()
        elif self.path == "/redirect-loop-b":
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{_PORT}/redirect-loop-a")
            self.end_headers()
        elif self.path == "/full-headers":
            self.send_response(200)
            self.send_header("Strict-Transport-Security", "max-age=31536000")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html>ok</html>")
        elif self.path == "/leaky-headers":
            self.send_response(200)
            self.send_header("Set-Cookie", "session=leaked-secret-value")
            self.send_header("Authorization", "Bearer leaked-token-value")
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html>ok</html>")
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html>ok</html>")

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture(scope="module", autouse=True)
def _local_server():
    server = http.server.HTTPServer(("127.0.0.1", _PORT), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def _target(path: str = "/"):
    return normalize_target(f"http://127.0.0.1:{_PORT}{path}")


class TestRedirectAndHeaderProtections:
    """Test-only relaxation: production denies LOOPBACK (proven above in
    TestAddressClassification and by the unpatched deny tests below,
    which stay denied regardless of this patch since they are denied
    for an unrelated reason — foreign/metadata address). This local
    HTTP server is necessarily loopback-bound, so LOOPBACK is added to
    the allowed set for the duration of this class only, to exercise
    the redirect/DNS-rebinding/header pipeline end-to-end. Never a
    production code path."""

    @pytest.fixture(autouse=True)
    def _allow_loopback_for_local_test_server(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            network_adapters, "ALLOWED_ADDRESS_CLASSES",
            frozenset({AddressClass.PUBLIC, AddressClass.LOOPBACK}),
        )

    async def test_redirect_within_original_resolution_set_followed(self) -> None:
        target = _target("/redirect-same-target")
        result = await fetch_http_metadata(
            target, resolved_addresses=("127.0.0.1",), timeout=3.0, redirect_limit=3,
            dns_timeout=2.0, dns_retry_attempts=1,
        )
        assert result.success is True
        assert result.final_url == f"http://127.0.0.1:{_PORT}/landed"
        assert len(result.redirect_chain) == 1

    async def test_redirect_to_forbidden_metadata_address_blocked(self) -> None:
        target = _target("/redirect-forbidden")
        result = await fetch_http_metadata(
            target, resolved_addresses=("127.0.0.1",), timeout=3.0, redirect_limit=3,
            dns_timeout=2.0, dns_retry_attempts=1,
        )
        assert result.success is False
        assert result.error_category == ErrorCategory.NETWORK_BOUNDARY_DENIED

    async def test_redirect_to_foreign_unauthorized_target_blocked(self) -> None:
        """DNS-rebinding / foreign-target defense: a redirect resolving
        to addresses outside the ORIGINAL target's own validated
        resolution set is refused, even though 93.184.216.34 is itself
        a public address."""
        target = _target("/redirect-foreign")
        result = await fetch_http_metadata(
            target, resolved_addresses=("127.0.0.1",), timeout=3.0, redirect_limit=3,
            dns_timeout=2.0, dns_retry_attempts=1,
        )
        assert result.success is False
        assert result.error_category == ErrorCategory.NETWORK_BOUNDARY_DENIED

    async def test_redirect_limit_enforced(self) -> None:
        target = _target("/redirect-loop-a")
        result = await fetch_http_metadata(
            target, resolved_addresses=("127.0.0.1",), timeout=3.0, redirect_limit=3,
            dns_timeout=2.0, dns_retry_attempts=1,
        )
        assert result.success is False
        assert result.error_category == ErrorCategory.REDIRECT_LIMIT_EXCEEDED
        assert len(result.redirect_chain) == 4  # redirect_limit + 1 attempts

    async def test_authorization_header_absent_from_response_metadata(self) -> None:
        target = _target("/leaky-headers")
        result = await fetch_http_metadata(
            target, resolved_addresses=("127.0.0.1",), timeout=3.0, redirect_limit=3,
            dns_timeout=2.0, dns_retry_attempts=1,
        )
        assert result.success is True
        assert "authorization" not in {k.lower() for k in result.response_headers}
        assert "set-cookie" not in {k.lower() for k in result.response_headers}
        serialized = str(result.response_headers).lower()
        assert "leaked-secret-value" not in serialized
        assert "leaked-token-value" not in serialized

    async def test_full_headers_produce_no_findings(self) -> None:
        target = _target("/full-headers")
        result = await fetch_http_metadata(
            target, resolved_addresses=("127.0.0.1",), timeout=3.0, redirect_limit=3,
            dns_timeout=2.0, dns_retry_attempts=1,
        )
        assert result.success is True
        findings = evaluate_security_headers(result.response_headers, target.is_https)
        assert findings == ()

    async def test_missing_headers_produce_exactly_expected_findings(self) -> None:
        target = _target("/")
        result = await fetch_http_metadata(
            target, resolved_addresses=("127.0.0.1",), timeout=3.0, redirect_limit=3,
            dns_timeout=2.0, dns_retry_attempts=1,
        )
        findings = evaluate_security_headers(result.response_headers, target.is_https)
        rule_ids = {f.stable_rule_id for f in findings}
        assert rule_ids == {"MISSING_CSP_HEADER", "MISSING_X_CONTENT_TYPE_OPTIONS_HEADER"}
        # HTTP (not HTTPS) target — HSTS is meaningless over plain HTTP,
        # so it must NOT be flagged.
        assert "MISSING_HSTS_HEADER" not in rule_ids
