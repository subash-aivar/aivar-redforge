"""Asset identity normalization tests — M3."""

from __future__ import annotations

import pytest

from redforge.domain.inventory.identity import (
    IdentityNormalizationError,
    IdentityScheme,
    build_external_id,
)


def test_redforge_target_id_deterministic() -> None:
    assert build_external_id(
        IdentityScheme.REDFORGE_TARGET_ID, "01ABCDEF"
    ) == "redforge_target_id:01ABCDEF"


def test_redforge_target_id_rejects_empty() -> None:
    with pytest.raises(IdentityNormalizationError):
        build_external_id(IdentityScheme.REDFORGE_TARGET_ID, "  ")


def test_url_origin_strips_path_query_fragment() -> None:
    a = build_external_id(IdentityScheme.URL_ORIGIN, "https://api.example.com/v1/chat?x=1#frag")
    b = build_external_id(IdentityScheme.URL_ORIGIN, "https://api.example.com/v2/completions")
    assert a == b == "url_origin:https://api.example.com"


def test_url_origin_is_case_insensitive_for_host() -> None:
    a = build_external_id(IdentityScheme.URL_ORIGIN, "https://API.Example.COM/x")
    assert a == "url_origin:https://api.example.com"


def test_url_origin_keeps_non_default_port() -> None:
    a = build_external_id(IdentityScheme.URL_ORIGIN, "https://api.example.com:8443/x")
    assert a == "url_origin:https://api.example.com:8443"


def test_url_origin_drops_default_https_port() -> None:
    a = build_external_id(IdentityScheme.URL_ORIGIN, "https://api.example.com:443/x")
    assert a == "url_origin:https://api.example.com"


def test_url_origin_rejects_relative_url() -> None:
    with pytest.raises(IdentityNormalizationError):
        build_external_id(IdentityScheme.URL_ORIGIN, "/just/a/path")


def test_ip_address_normalizes_canonical_form() -> None:
    assert build_external_id(IdentityScheme.IP_ADDRESS, " 10.0.0.1 ") == "ip_address:10.0.0.1"


def test_ip_address_rejects_invalid() -> None:
    with pytest.raises(IdentityNormalizationError):
        build_external_id(IdentityScheme.IP_ADDRESS, "not-an-ip")


def test_cloud_resource_id_preserves_case() -> None:
    arn = "arn:aws:s3:::My-Bucket-Name"
    assert build_external_id(IdentityScheme.CLOUD_RESOURCE_ID, arn) == f"cloud_resource_id:{arn}"


def test_different_schemes_never_collide_even_with_same_raw_value() -> None:
    """The scheme prefix guarantees two different schemes normalizing an
    identical raw string never produce the same external_id — a strict
    requirement for tenant-scoped uniqueness to mean what it claims."""
    raw = "10.0.0.1"
    ip_id = build_external_id(IdentityScheme.IP_ADDRESS, raw)
    target_id = build_external_id(IdentityScheme.REDFORGE_TARGET_ID, raw)
    assert ip_id != target_id
