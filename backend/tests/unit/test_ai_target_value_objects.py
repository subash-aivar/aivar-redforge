"""Unit tests for AI Target value objects."""

import pytest

from redforge.domain.ai_targets.value_objects import (
    EndpointUrl,
    Provider,
    Tag,
    TargetMetadata,
    TargetName,
    TargetStatus,
    TargetType,
    ValidationPolicyReference,
)


class TestTargetName:
    def test_valid(self) -> None:
        name = TargetName("My LLM App")
        assert name.value == "My LLM App"

    def test_strips_whitespace(self) -> None:
        assert TargetName("  App  ").value == "App"

    def test_too_short_raises(self) -> None:
        with pytest.raises(ValueError, match="at least 2"):
            TargetName("A")

    def test_too_long_raises(self) -> None:
        with pytest.raises(ValueError, match="at most 150"):
            TargetName("A" * 151)

    def test_equality(self) -> None:
        assert TargetName("App") == TargetName("App")
        assert TargetName("App") != TargetName("Other")

    def test_hashable(self) -> None:
        assert len({TargetName("App"), TargetName("App")}) == 1


class TestEndpointUrl:
    def test_valid_https(self) -> None:
        url = EndpointUrl("https://api.openai.com/v1/chat")
        assert url.value == "https://api.openai.com/v1/chat"

    def test_valid_http(self) -> None:
        url = EndpointUrl("http://localhost:8080/api")
        assert url.value == "http://localhost:8080/api"

    def test_no_scheme_raises(self) -> None:
        with pytest.raises(ValueError, match="valid HTTP/HTTPS"):
            EndpointUrl("api.openai.com/v1")

    def test_ftp_raises(self) -> None:
        with pytest.raises(ValueError, match="valid HTTP/HTTPS"):
            EndpointUrl("ftp://files.example.com")

    def test_whitespace_raises(self) -> None:
        with pytest.raises(ValueError, match="valid HTTP/HTTPS"):
            EndpointUrl("https://api.com/path with spaces")

    def test_too_long_raises(self) -> None:
        with pytest.raises(ValueError, match="at most 2048"):
            EndpointUrl("https://x.com/" + "a" * 2040)

    def test_equality(self) -> None:
        assert EndpointUrl("https://a.com") == EndpointUrl("https://a.com")
        assert EndpointUrl("https://a.com") != EndpointUrl("https://b.com")


class TestTag:
    def test_valid_simple(self) -> None:
        assert Tag("production").value == "production"

    def test_valid_namespaced(self) -> None:
        assert Tag("env:production").value == "env:production"

    def test_valid_with_hyphens(self) -> None:
        assert Tag("team-security").value == "team-security"

    def test_normalizes_to_lowercase(self) -> None:
        assert Tag("Production").value == "production"

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="not be empty"):
            Tag("")

    def test_too_long_raises(self) -> None:
        with pytest.raises(ValueError, match="at most 50"):
            Tag("a" * 51)

    def test_invalid_chars_raises(self) -> None:
        with pytest.raises(ValueError, match="lowercase alphanumeric"):
            Tag("has spaces")

    def test_equality(self) -> None:
        assert Tag("env:prod") == Tag("env:prod")
        assert Tag("env:prod") != Tag("env:dev")

    def test_hashable(self) -> None:
        assert len({Tag("a"), Tag("a"), Tag("b")}) == 2


class TestValidationPolicyReference:
    def test_valid(self) -> None:
        ref = ValidationPolicyReference("policy-123")
        assert ref.policy_id == "policy-123"

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="valid identifier"):
            ValidationPolicyReference("")

    def test_too_short_raises(self) -> None:
        with pytest.raises(ValueError, match="valid identifier"):
            ValidationPolicyReference("x")

    def test_equality(self) -> None:
        r1 = ValidationPolicyReference("abc")
        r2 = ValidationPolicyReference("abc")
        assert r1 == r2

    def test_hashable(self) -> None:
        r = ValidationPolicyReference("abc")
        assert len({r, ValidationPolicyReference("abc")}) == 1


class TestTargetMetadata:
    def test_empty(self) -> None:
        m = TargetMetadata()
        assert len(m) == 0

    def test_with_data(self) -> None:
        m = TargetMetadata({"key": "value"})
        assert m.get("key") == "value"

    def test_with_entry_returns_new(self) -> None:
        m = TargetMetadata()
        m2 = m.with_entry("k", "v")
        assert m2.get("k") == "v"
        assert m.get("k") is None

    def test_without_entry(self) -> None:
        m = TargetMetadata({"a": "1", "b": "2"})
        m2 = m.without_entry("a")
        assert m2.get("a") is None
        assert m2.get("b") == "2"

    def test_too_many_entries_raises(self) -> None:
        data = {f"key{i}": "v" for i in range(51)}
        with pytest.raises(ValueError, match="cannot exceed 50"):
            TargetMetadata(data)

    def test_key_too_long_raises(self) -> None:
        with pytest.raises(ValueError, match="1-100 characters"):
            TargetMetadata({"k" * 101: "v"})

    def test_empty_key_raises(self) -> None:
        with pytest.raises(ValueError, match="1-100 characters"):
            TargetMetadata({"": "v"})

    def test_value_too_long_raises(self) -> None:
        with pytest.raises(ValueError, match="exceeds 1000"):
            TargetMetadata({"k": "v" * 1001})

    def test_equality(self) -> None:
        assert TargetMetadata({"a": "1"}) == TargetMetadata({"a": "1"})
        assert TargetMetadata({"a": "1"}) != TargetMetadata({"a": "2"})

    def test_data_returns_copy(self) -> None:
        m = TargetMetadata({"a": "1"})
        d = m.data
        d["b"] = "2"
        assert m.get("b") is None


class TestEnums:
    def test_target_type_values(self) -> None:
        assert TargetType.LLM_APPLICATION == "llm_application"
        assert TargetType.MCP_SERVER == "mcp_server"

    def test_target_status_values(self) -> None:
        assert TargetStatus.ACTIVE == "active"
        assert TargetStatus.ARCHIVED == "archived"

    def test_provider_values(self) -> None:
        assert Provider.OPENAI == "openai"
        assert Provider.ANTHROPIC == "anthropic"
        assert Provider.CUSTOM == "custom"
