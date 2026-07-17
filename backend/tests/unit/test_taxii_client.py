"""Unit tests for the TAXII 2.1 client — M22 Phase 3 (STIX/TAXII
Integration).

DNS resolution and the outbound HTTP transport are both injected
(`resolver`, `http_client=httpx.AsyncClient(transport=...)`), so every
test here runs with zero real network access, per the client's own
design (see `taxii_client.py` module docstring).

Covers:
  - The SSRF gate (`validate_ssrf_safe` / `_validate_scheme_and_host`)
    in isolation.
  - `TaxiiAuth`'s header/httpx_auth construction for each scheme.
  - `TaxiiClient.get_discovery` / `get_collections` / `get_collection`
    / `get_objects` (including pagination) against a mock transport.
  - Transport-level failure handling: auth rejection (401/403),
    other non-2xx (including 3xx, since redirects are never
    followed), oversized response, and malformed JSON.
"""

from __future__ import annotations

import httpx
import pytest

from redforge.infrastructure.threat_intel.taxii_client import (
    DEFAULT_PAGE_LIMIT,
    TaxiiAuth,
    TaxiiAuthenticationError,
    TaxiiClient,
    TaxiiDisallowedUrlError,
    TaxiiRequestError,
    TaxiiResponseFormatError,
    TaxiiResponseTooLargeError,
    validate_ssrf_safe,
)

_PUBLIC_IP = "93.184.216.34"  # example.com — a real, public, non-reserved address
_PRIVATE_IP = "10.0.0.5"
_DISCOVERY_URL = "https://taxii.example.com/taxii2/"
_API_ROOT_URL = "https://taxii.example.com/api1/"


async def _public_resolver(hostname: str) -> tuple[str, ...]:
    return (_PUBLIC_IP,)


async def _private_resolver(hostname: str) -> tuple[str, ...]:
    return (_PRIVATE_IP,)


async def _empty_resolver(hostname: str) -> tuple[str, ...]:
    return ()


def _json_response(status: int, body: dict | list) -> httpx.Response:
    return httpx.Response(status, json=body)


class _RecordingHandler:
    """Mock transport handler that records every request it sees and
    replays canned responses in order (or repeats the last one)."""

    def __init__(self, responses: list[httpx.Response]) -> None:
        self._responses = list(responses)
        self.requests: list[httpx.Request] = []

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        index = min(len(self.requests) - 1, len(self._responses) - 1)
        return self._responses[index]


def _client_with(
    responses: list[httpx.Response], *, resolver=_public_resolver
) -> tuple[TaxiiClient, _RecordingHandler]:
    handler = _RecordingHandler(responses)
    transport = httpx.MockTransport(handler)
    http_client = httpx.AsyncClient(transport=transport, follow_redirects=False)
    return TaxiiClient(http_client=http_client, resolver=resolver), handler


# ─────────────────────────────────────────────────────────────────────────────
# SSRF gate
# ─────────────────────────────────────────────────────────────────────────────


class TestSsrfGate:
    async def test_non_https_scheme_is_rejected(self) -> None:
        with pytest.raises(TaxiiDisallowedUrlError):
            await validate_ssrf_safe("http://taxii.example.com/", resolver=_public_resolver)

    async def test_url_with_no_host_is_rejected(self) -> None:
        with pytest.raises(TaxiiDisallowedUrlError):
            await validate_ssrf_safe("https:///no-host", resolver=_public_resolver)

    async def test_hostname_resolving_to_a_public_ip_is_allowed(self) -> None:
        await validate_ssrf_safe("https://taxii.example.com/", resolver=_public_resolver)

    async def test_hostname_resolving_to_a_private_ip_is_rejected(self) -> None:
        with pytest.raises(TaxiiDisallowedUrlError):
            await validate_ssrf_safe("https://internal.example.com/", resolver=_private_resolver)

    async def test_hostname_resolving_to_no_addresses_is_rejected(self) -> None:
        with pytest.raises(TaxiiDisallowedUrlError):
            await validate_ssrf_safe("https://nowhere.example.com/", resolver=_empty_resolver)

    async def test_a_dns_resolution_failure_propagates(self) -> None:
        async def _failing_resolver(hostname: str) -> tuple[str, ...]:
            raise TaxiiDisallowedUrlError(f"DNS resolution failed for host {hostname!r}")

        with pytest.raises(TaxiiDisallowedUrlError):
            await validate_ssrf_safe("https://broken.example.com/", resolver=_failing_resolver)


# ─────────────────────────────────────────────────────────────────────────────
# TaxiiAuth
# ─────────────────────────────────────────────────────────────────────────────


class TestTaxiiAuth:
    def test_none_scheme_has_no_headers_or_httpx_auth(self) -> None:
        auth = TaxiiAuth.none()
        assert auth.headers() == {}
        assert auth.httpx_auth() is None

    def test_bearer_scheme_sets_authorization_header(self) -> None:
        auth = TaxiiAuth(scheme="bearer", secret="my-token")
        assert auth.headers() == {"Authorization": "Bearer my-token"}
        assert auth.httpx_auth() is None

    def test_basic_scheme_produces_httpx_basic_auth(self) -> None:
        auth = TaxiiAuth(scheme="basic", username="alice", secret="p@ss")
        assert auth.headers() == {}
        basic_auth = auth.httpx_auth()
        assert isinstance(basic_auth, httpx.BasicAuth)

    def test_basic_scheme_missing_username_yields_no_auth(self) -> None:
        auth = TaxiiAuth(scheme="basic", username=None, secret="p@ss")
        assert auth.httpx_auth() is None


# ─────────────────────────────────────────────────────────────────────────────
# TaxiiClient.get_discovery
# ─────────────────────────────────────────────────────────────────────────────


class TestGetDiscovery:
    async def test_parses_a_valid_discovery_response(self) -> None:
        client, handler = _client_with(
            [
                _json_response(
                    200,
                    {
                        "title": "Example TAXII Server",
                        "description": "A test server",
                        "api_roots": [_API_ROOT_URL, "https://taxii.example.com/api2/"],
                        "default": _API_ROOT_URL,
                    },
                )
            ]
        )
        discovery = await client.get_discovery(_DISCOVERY_URL, auth=TaxiiAuth.none())
        assert discovery.title == "Example TAXII Server"
        assert discovery.default == _API_ROOT_URL
        assert discovery.api_roots == (_API_ROOT_URL, "https://taxii.example.com/api2/")
        assert len(handler.requests) == 1

    async def test_ssrf_gate_runs_before_any_request_is_sent(self) -> None:
        handler = _RecordingHandler([_json_response(200, {"title": "unreachable"})])
        transport = httpx.MockTransport(handler)
        http_client = httpx.AsyncClient(transport=transport, follow_redirects=False)
        client = TaxiiClient(http_client=http_client, resolver=_private_resolver)

        with pytest.raises(TaxiiDisallowedUrlError):
            await client.get_discovery(_DISCOVERY_URL, auth=TaxiiAuth.none())
        assert len(handler.requests) == 0

    async def test_non_object_response_raises_format_error(self) -> None:
        client, _handler = _client_with([_json_response(200, ["not", "an", "object"])])
        with pytest.raises(TaxiiResponseFormatError):
            await client.get_discovery(_DISCOVERY_URL, auth=TaxiiAuth.none())

    async def test_bearer_auth_header_is_sent(self) -> None:
        client, handler = _client_with([_json_response(200, {"title": "t"})])
        await client.get_discovery(
            _DISCOVERY_URL, auth=TaxiiAuth(scheme="bearer", secret="secret-token")
        )
        assert handler.requests[0].headers["authorization"] == "Bearer secret-token"


# ─────────────────────────────────────────────────────────────────────────────
# TaxiiClient.get_collections / get_collection
# ─────────────────────────────────────────────────────────────────────────────


class TestGetCollections:
    async def test_parses_a_list_of_collections(self) -> None:
        client, _handler = _client_with(
            [
                _json_response(
                    200,
                    {
                        "collections": [
                            {
                                "id": "col-1",
                                "title": "Enterprise ATT&CK",
                                "can_read": True,
                                "can_write": False,
                                "media_types": ["application/stix+json;version=2.1"],
                            },
                            {"id": "col-2", "title": "Other", "can_read": False, "can_write": False},
                        ]
                    },
                )
            ]
        )
        collections = await client.get_collections(_API_ROOT_URL, auth=TaxiiAuth.none())
        assert len(collections) == 2
        assert collections[0].id == "col-1"
        assert collections[0].can_read is True

    async def test_missing_collections_key_raises_format_error(self) -> None:
        client, _handler = _client_with([_json_response(200, {})])
        with pytest.raises(TaxiiResponseFormatError):
            await client.get_collections(_API_ROOT_URL, auth=TaxiiAuth.none())


class TestGetCollection:
    async def test_parses_a_single_collection(self) -> None:
        client, handler = _client_with(
            [_json_response(200, {"id": "col-1", "title": "Enterprise ATT&CK", "can_read": True, "can_write": False})]
        )
        collection = await client.get_collection(_API_ROOT_URL, "col-1", auth=TaxiiAuth.none())
        assert collection.id == "col-1"
        assert collection.can_read is True
        assert str(handler.requests[0].url).endswith("/api1/collections/col-1/")

    async def test_missing_id_raises_format_error(self) -> None:
        client, _handler = _client_with([_json_response(200, {"title": "No Id"})])
        with pytest.raises(TaxiiResponseFormatError):
            await client.get_collection(_API_ROOT_URL, "col-1", auth=TaxiiAuth.none())

    async def test_missing_title_falls_back_to_id(self) -> None:
        client, _handler = _client_with([_json_response(200, {"id": "col-1", "can_read": True})])
        collection = await client.get_collection(_API_ROOT_URL, "col-1", auth=TaxiiAuth.none())
        assert collection.title == "col-1"


# ─────────────────────────────────────────────────────────────────────────────
# TaxiiClient.get_objects — pagination and query params
# ─────────────────────────────────────────────────────────────────────────────


class TestGetObjects:
    async def test_single_page_with_more_false(self) -> None:
        client, handler = _client_with(
            [_json_response(200, {"objects": [{"id": "a", "type": "vulnerability"}], "more": False})]
        )
        envelope = await client.get_objects(_API_ROOT_URL, "col-1", auth=TaxiiAuth.none())
        assert len(envelope.objects) == 1
        assert envelope.more is False
        assert envelope.next is None
        query = dict(handler.requests[0].url.params)
        assert query["limit"] == str(DEFAULT_PAGE_LIMIT)
        assert "added_after" not in query

    async def test_added_after_and_limit_are_sent_as_query_params(self) -> None:
        client, handler = _client_with(
            [_json_response(200, {"objects": [], "more": False})]
        )
        await client.get_objects(
            _API_ROOT_URL,
            "col-1",
            auth=TaxiiAuth.none(),
            added_after="2026-01-01T00:00:00+00:00",
            limit=250,
        )
        query = dict(handler.requests[0].url.params)
        assert query["added_after"] == "2026-01-01T00:00:00+00:00"
        assert query["limit"] == "250"

    async def test_pagination_cursor_is_forwarded_on_the_next_call(self) -> None:
        client, handler = _client_with(
            [_json_response(200, {"objects": [{"id": "a"}], "more": True, "next": "cursor-2"})]
        )
        first = await client.get_objects(_API_ROOT_URL, "col-1", auth=TaxiiAuth.none())
        assert first.more is True
        assert first.next == "cursor-2"

        await client.get_objects(
            _API_ROOT_URL, "col-1", auth=TaxiiAuth.none(), next_cursor=first.next
        )
        second_query = dict(handler.requests[1].url.params)
        assert second_query["next"] == "cursor-2"

    async def test_non_dict_objects_entries_are_dropped(self) -> None:
        client, _handler = _client_with(
            [_json_response(200, {"objects": [{"id": "a"}, "garbage", 42], "more": False})]
        )
        envelope = await client.get_objects(_API_ROOT_URL, "col-1", auth=TaxiiAuth.none())
        assert envelope.objects == ({"id": "a"},)

    async def test_missing_objects_key_defaults_to_empty(self) -> None:
        client, _handler = _client_with([_json_response(200, {"more": False})])
        envelope = await client.get_objects(_API_ROOT_URL, "col-1", auth=TaxiiAuth.none())
        assert envelope.objects == ()

    async def test_non_array_objects_field_raises_format_error(self) -> None:
        client, _handler = _client_with([_json_response(200, {"objects": "not-a-list"})])
        with pytest.raises(TaxiiResponseFormatError):
            await client.get_objects(_API_ROOT_URL, "col-1", auth=TaxiiAuth.none())


# ─────────────────────────────────────────────────────────────────────────────
# Transport-level failure handling
# ─────────────────────────────────────────────────────────────────────────────


class TestTransportFailures:
    @pytest.mark.parametrize("status", [401, 403])
    async def test_401_and_403_raise_authentication_error(self, status: int) -> None:
        client, _handler = _client_with([httpx.Response(status)])
        with pytest.raises(TaxiiAuthenticationError) as exc_info:
            await client.get_discovery(_DISCOVERY_URL, auth=TaxiiAuth.none())
        assert exc_info.value.status_code == status

    async def test_500_raises_generic_request_error(self) -> None:
        client, _handler = _client_with([httpx.Response(500)])
        with pytest.raises(TaxiiRequestError) as exc_info:
            await client.get_discovery(_DISCOVERY_URL, auth=TaxiiAuth.none())
        assert exc_info.value.status_code == 500

    async def test_a_redirect_response_is_treated_as_a_failure_never_followed(self) -> None:
        client, handler = _client_with(
            [httpx.Response(302, headers={"Location": "https://internal.example.com/"})]
        )
        with pytest.raises(TaxiiRequestError):
            await client.get_discovery(_DISCOVERY_URL, auth=TaxiiAuth.none())
        # Only the ORIGINAL request was made — the 302 was never followed.
        assert len(handler.requests) == 1

    async def test_response_larger_than_declared_content_length_cap_is_rejected(self) -> None:
        client, _handler = _client_with(
            [httpx.Response(200, headers={"content-length": str(50 * 1024 * 1024)}, json={"title": "big"})]
        )
        with pytest.raises(TaxiiResponseTooLargeError):
            await client.get_discovery(_DISCOVERY_URL, auth=TaxiiAuth.none())

    async def test_actual_body_larger_than_cap_is_rejected(self) -> None:
        handler = _RecordingHandler([httpx.Response(200, json={"title": "x" * 200})])
        transport = httpx.MockTransport(handler)
        http_client = httpx.AsyncClient(transport=transport, follow_redirects=False)
        client = TaxiiClient(
            http_client=http_client, resolver=_public_resolver, max_response_bytes=10
        )
        with pytest.raises(TaxiiResponseTooLargeError):
            await client.get_discovery(_DISCOVERY_URL, auth=TaxiiAuth.none())

    async def test_non_json_body_raises_format_error(self) -> None:
        client, _handler = _client_with(
            [httpx.Response(200, content=b"not json at all", headers={"content-type": "text/plain"})]
        )
        with pytest.raises(TaxiiResponseFormatError):
            await client.get_discovery(_DISCOVERY_URL, auth=TaxiiAuth.none())

    async def test_client_never_created_by_this_module_owns_and_does_not_close_injected_client(
        self,
    ) -> None:
        """An injected `http_client` is the caller's responsibility to
        close — the client must not close it out from under a caller
        reusing it across multiple TAXII calls."""
        handler = _RecordingHandler([_json_response(200, {"title": "t"})])
        transport = httpx.MockTransport(handler)
        http_client = httpx.AsyncClient(transport=transport, follow_redirects=False)
        client = TaxiiClient(http_client=http_client, resolver=_public_resolver)

        await client.get_discovery(_DISCOVERY_URL, auth=TaxiiAuth.none())
        assert http_client.is_closed is False
        await client.get_discovery(_DISCOVERY_URL, auth=TaxiiAuth.none())
        assert len(handler.requests) == 2
