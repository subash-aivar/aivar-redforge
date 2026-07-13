"""Canonical asset identity/fingerprint strategy — M3.

An asset's deduplication identity is:

    ORGANIZATION_ID + IDENTITY_SCHEME + NORMALIZED_EXTERNAL_ID

The `organization_id` half of this is enforced structurally — every
query/repository method requires it explicitly (never inferred). The
`IdentityScheme + NORMALIZED_EXTERNAL_ID` half is encoded into
`AIAsset.external_id` as a single deterministic string
(`"{scheme}:{normalized_value}"`), which is what the tenant-scoped
partial unique index (migration 0013, `ux_ai_assets_org_external_id`)
actually enforces at the database level.

Display name, mutable endpoint text, and free-form metadata are
NEVER used for deduplication — only the fields explicitly normalized
here.
"""

from __future__ import annotations

from enum import StrEnum, unique
from urllib.parse import urlsplit


@unique
class IdentityScheme(StrEnum):
    """Supported external-identity schemes for M3.

    Each scheme has an explicit, deterministic normalization rule below.
    Do not add a scheme without also adding its normalization function
    and a normalization test — an unnormalized scheme silently breaks
    deduplication (two representations of the same resource would be
    treated as different assets).
    """

    REDFORGE_TARGET_ID = "redforge_target_id"
    URL_ORIGIN = "url_origin"
    IP_ADDRESS = "ip_address"
    CLOUD_RESOURCE_ID = "cloud_resource_id"

    # M6 network discovery schemes.
    NETWORK_CIDR = "network_cidr"
    DISCOVERY_HOST = "discovery_host"
    SERVICE_ENDPOINT = "service_endpoint"

    # M7 cloud discovery scheme.
    CLOUD_ACCOUNT_ID = "cloud_account_id"


class IdentityNormalizationError(ValueError):
    """Raised when a value cannot be normalized for its declared scheme."""


def normalize_redforge_target_id(raw: str) -> str:
    """RedForge's own target IDs are already canonical ULIDs — no
    transformation needed beyond trimming and validating non-empty."""
    value = raw.strip()
    if not value:
        raise IdentityNormalizationError("redforge_target_id must not be empty")
    return value


def normalize_url_origin(raw: str) -> str:
    """Normalizes a URL down to its origin (scheme://host:port), the
    only part of a URL that is a safe, mutable-text-free identity —
    path/query/fragment are excluded since they can change without the
    underlying resource changing identity.
    """
    parsed = urlsplit(raw.strip())
    if not parsed.scheme or not parsed.netloc:
        raise IdentityNormalizationError(f"'{raw}' is not a valid absolute URL")
    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower() if parsed.hostname else ""
    if not host:
        raise IdentityNormalizationError(f"'{raw}' has no host")
    port = parsed.port
    default_ports = {"http": 80, "https": 443}
    if port is not None and default_ports.get(scheme) != port:
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


def normalize_ip_address(raw: str) -> str:
    """Normalizes an IP address to its canonical string form."""
    import ipaddress

    value = raw.strip()
    try:
        addr = ipaddress.ip_address(value)
    except ValueError as exc:
        raise IdentityNormalizationError(f"'{raw}' is not a valid IP address") from exc
    return str(addr)


def normalize_cloud_resource_id(raw: str) -> str:
    """Cloud resource identifiers (ARNs, Azure resource IDs, GCP full
    resource names) are already globally unique and case-sensitive by
    the cloud provider's own convention — normalization here is limited
    to trimming whitespace, not lower-casing (case IS significant for
    these identifiers, unlike a hostname).
    """
    value = raw.strip()
    if not value:
        raise IdentityNormalizationError("cloud_resource_id must not be empty")
    return value


_SUPPORTED_CLOUD_PROVIDERS = {"aws", "azure", "gcp"}


def normalize_cloud_account_id(raw: str) -> str:
    """Cloud account identity is PROVIDER-AWARE: the raw value must
    already be composed as `"{provider}:{account_identifier}"` by the
    caller — an AWS account ID, an Azure subscription ID, and a GCP
    project ID occupy entirely different namespaces with different
    semantics (M7 report §3), so the provider must be part of the
    identity, never inferred. Provider is normalized to lowercase and
    restricted to the explicitly implemented set; the account
    identifier portion is preserved as-is (case may be significant,
    e.g. some GCP project IDs)."""
    value = raw.strip()
    if ":" not in value:
        raise IdentityNormalizationError(
            f"'{raw}' must be composed as 'provider:account_identifier'"
        )
    provider, _, account_id = value.partition(":")
    provider = provider.strip().lower()
    account_id = account_id.strip()
    if provider not in _SUPPORTED_CLOUD_PROVIDERS:
        raise IdentityNormalizationError(f"Unsupported cloud provider: {provider!r}")
    if not account_id:
        raise IdentityNormalizationError(f"'{raw}' has an empty account identifier")
    return f"{provider}:{account_id}"


def normalize_network_cidr(raw: str) -> str:
    """Normalizes a network/CIDR to its canonical network address +
    prefix length — host bits are masked off per `ipaddress`'s own
    `strict=False` semantics, so `10.0.0.1/24` and `10.0.0.0/24`
    normalize identically (never accidentally treated as two networks).
    """
    import ipaddress

    value = raw.strip()
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise IdentityNormalizationError(f"'{raw}' is not a valid network/CIDR") from exc
    return str(network)


def normalize_discovery_host(raw: str) -> str:
    """A hostname alone is not a safe identity (mutable, can collide
    across environments) — the raw value here MUST already be composed
    as `"{connector_id}:{hostname}"` by the caller, scoping host
    identity to the discovery source that observed it. The hostname
    portion is lowercased (DNS names are case-insensitive); the
    connector_id portion is preserved as-is (a case-sensitive ULID).
    """
    value = raw.strip()
    if ":" not in value:
        raise IdentityNormalizationError(
            f"'{raw}' must be composed as 'connector_id:hostname'"
        )
    connector_id, _, hostname = value.partition(":")
    connector_id = connector_id.strip()
    hostname = hostname.strip().lower()
    if not connector_id or not hostname:
        raise IdentityNormalizationError(f"'{raw}' has an empty connector_id or hostname")
    return f"{connector_id}:{hostname}"


def normalize_service_endpoint(raw: str) -> str:
    """Canonical service identity: `"{host_asset_id}:{protocol}:{port}"`
    — never the service banner or product/version guess, which are
    mutable and unreliable. Protocol is restricted to tcp/udp; port
    must be a valid 1-65535 integer."""
    value = raw.strip()
    parts = value.split(":")
    if len(parts) != 3:
        raise IdentityNormalizationError(
            f"'{raw}' must be composed as 'host_asset_id:protocol:port'"
        )
    host_asset_id, protocol, port_str = (p.strip() for p in parts)
    protocol = protocol.lower()
    if not host_asset_id:
        raise IdentityNormalizationError(f"'{raw}' has an empty host_asset_id")
    if protocol not in ("tcp", "udp"):
        raise IdentityNormalizationError(f"'{raw}' has an unsupported protocol: {protocol!r}")
    try:
        port = int(port_str)
    except ValueError as exc:
        raise IdentityNormalizationError(f"'{raw}' has a non-integer port") from exc
    if not (1 <= port <= 65535):
        raise IdentityNormalizationError(f"'{raw}' has an out-of-range port: {port}")
    return f"{host_asset_id}:{protocol}:{port}"


_NORMALIZERS = {
    IdentityScheme.REDFORGE_TARGET_ID: normalize_redforge_target_id,
    IdentityScheme.URL_ORIGIN: normalize_url_origin,
    IdentityScheme.IP_ADDRESS: normalize_ip_address,
    IdentityScheme.CLOUD_RESOURCE_ID: normalize_cloud_resource_id,
    IdentityScheme.NETWORK_CIDR: normalize_network_cidr,
    IdentityScheme.DISCOVERY_HOST: normalize_discovery_host,
    IdentityScheme.SERVICE_ENDPOINT: normalize_service_endpoint,
    IdentityScheme.CLOUD_ACCOUNT_ID: normalize_cloud_account_id,
}


def build_external_id(scheme: IdentityScheme, raw_value: str) -> str:
    """Deterministically normalizes `raw_value` per `scheme` and encodes
    it as the single string stored in `AIAsset.external_id` — the value
    the tenant-scoped unique index is built on.
    """
    normalized = _NORMALIZERS[scheme](raw_value)
    return f"{scheme.value}:{normalized}"
