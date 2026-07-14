"""Standards-based RDAP (RFC 9224) ASN/network-ownership enrichment.

Bootstraps from IANA's own published registry (data.iana.org/rdap/*.json)
to find which Regional Internet Registry is authoritative for a given
IP, then queries that RIR's RDAP server directly — never the shared
rdap.org proxy, and never more than once per bootstrap-cache lifetime.
Callers are expected to cache both the bootstrap file (~24h) and each
per-IP result (~24h) themselves; this module only performs the parsing
and lookup, it holds no cache state of its own.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from datetime import UTC, datetime

from redforge.domain.threat_intel.results import AsnEnrichment, ProviderCallOutcome
from redforge.infrastructure.threat_intel.http_client import ThreatIntelHttpClient
from redforge.infrastructure.threat_intel.providers._shared import outcome_for_exception

logger = logging.getLogger(__name__)

_PROVIDER = "rdap"
_IANA_IPV4_BOOTSTRAP = "https://data.iana.org/rdap/ipv4.json"
_IANA_IPV6_BOOTSTRAP = "https://data.iana.org/rdap/ipv6.json"

# The bootstrap file maps CIDR prefixes to RIR RDAP base URLs; we only
# ever contact the 5 canonical RIR RDAP servers already on our fixed
# allowlist, keyed here by hostname substring found in the bootstrap data.
_RIR_HOST_ALLOWLIST = (
    "rdap.arin.net",
    "rdap.db.ripe.net",
    "rdap.apnic.net",
    "rdap.lacnic.net",
    "rdap.afrinic.net",
)


async def fetch_bootstrap(
    client: ThreatIntelHttpClient,
    ip_version: int,
) -> tuple[list[tuple[str, list[str]]] | None, ProviderCallOutcome]:
    """Returns a list of (cidr, [rdap_base_urls]) entries from IANA's
    bootstrap file. Cache this for ~24h per RFC 9224's own intent."""
    now = datetime.now(UTC).isoformat()
    url = _IANA_IPV4_BOOTSTRAP if ip_version == 4 else _IANA_IPV6_BOOTSTRAP
    try:
        result = await client.get(_PROVIDER, url, max_requests_per_window=6, window_seconds=3600)
    except Exception as exc:
        return None, outcome_for_exception(_PROVIDER, exc, now)
    if result.status_code != 200:
        return None, ProviderCallOutcome(
            _PROVIDER, False, "provider_error", now, f"HTTP {result.status_code}"
        )
    try:
        payload = json.loads(result.body)
        services = payload["services"]
    except (json.JSONDecodeError, KeyError, TypeError):
        return None, ProviderCallOutcome(
            _PROVIDER, False, "malformed_response", now, "unexpected bootstrap shape"
        )

    entries: list[tuple[str, list[str]]] = []
    for service in services:
        if len(service) < 2:
            continue
        prefixes, urls = service[0], service[1]
        for prefix in prefixes:
            entries.append((prefix, [u for u in urls if any(h in u for h in _RIR_HOST_ALLOWLIST)]))
    return entries, ProviderCallOutcome(_PROVIDER, True, None, now, f"{len(entries)} prefixes")


def find_rdap_base(
    ip: str,
    bootstrap_entries: list[tuple[str, list[str]]],
) -> str | None:
    """Pure, offline lookup against an already-fetched bootstrap table."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    best: tuple[int, str] | None = None
    for prefix, urls in bootstrap_entries:
        if not urls:
            continue
        try:
            network = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            continue
        if addr in network and (best is None or network.prefixlen > best[0]):
            best = (network.prefixlen, urls[0].rstrip("/"))
    return best[1] if best else None


async def lookup_ip(
    client: ThreatIntelHttpClient,
    rdap_base_url: str,
    ip: str,
) -> tuple[AsnEnrichment | None, ProviderCallOutcome]:
    """Query the RIR's own RDAP server for one IP. `rdap_base_url` must
    come from `find_rdap_base` (i.e. already validated against our
    fixed RIR allowlist) — never accept an arbitrary caller-supplied URL."""
    now = datetime.now(UTC).isoformat()
    url = f"{rdap_base_url}/ip/{ip}"
    try:
        result = await client.get(
            _PROVIDER,
            url,
            headers={"Accept": "application/rdap+json"},
            max_requests_per_window=20,
            window_seconds=60,
        )
    except Exception as exc:
        return None, outcome_for_exception(_PROVIDER, exc, now)
    if result.status_code == 404:
        return None, ProviderCallOutcome(_PROVIDER, True, None, now, "no RDAP record")
    if result.status_code == 429:
        return None, ProviderCallOutcome(
            _PROVIDER, False, "rate_limited", now, "RIR RDAP server throttled us"
        )
    if result.status_code != 200:
        return None, ProviderCallOutcome(
            _PROVIDER, False, "provider_error", now, f"HTTP {result.status_code}"
        )

    try:
        payload = json.loads(result.body)
    except json.JSONDecodeError:
        return None, ProviderCallOutcome(
            _PROVIDER, False, "malformed_response", now, "invalid JSON"
        )

    org_name = None
    country = None
    for entity in payload.get("entities", []) or []:
        vcard = entity.get("vcardArray")
        if vcard and len(vcard) > 1:
            for field_entry in vcard[1]:
                if field_entry[0] == "fn":
                    org_name = field_entry[3]
        if not org_name and "roles" in entity and "registrant" in entity.get("roles", []):
            org_name = entity.get("handle")

    country = payload.get("country")

    enrichment = AsnEnrichment(
        provider=_PROVIDER,
        indicator=ip,
        asn=None,  # RDAP IP lookup does not directly return ASN; a
        # separate autnum lookup would be needed and is out of scope for
        # this pass — never fabricated here.
        network_prefix=payload.get("startAddress")
        and payload.get("endAddress")
        and f"{payload.get('startAddress')} - {payload.get('endAddress')}",
        organization=org_name,
        country=country,
        registration_date=next(
            (
                e.get("date")
                for e in payload.get("events", []) or []
                if e.get("eventAction") == "registration"
            ),
            None,
        ),
        rir_source=rdap_base_url,
        fetched_at=now,
    )
    return enrichment, ProviderCallOutcome(_PROVIDER, True, None, now, "ok")
