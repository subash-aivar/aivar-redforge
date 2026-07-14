"""IPinfo Lite geolocation fallback adapter — used only when no local
MaxMind database is configured.

Official terms: ipinfo.io/terms-of-service permit "internal business
purposes"; reselling/redistributing the raw content is prohibited. We
use this strictly as internal enrichment for RedForge's own operators —
never resold or re-exposed as a standalone dataset. IPinfo Lite only
returns country + ASN (coarse) — no city/lat-lon, which is why this is
a fallback, not the primary path.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

from redforge.domain.threat_intel.results import GeoEnrichment, ProviderCallOutcome
from redforge.infrastructure.threat_intel.http_client import ThreatIntelHttpClient
from redforge.infrastructure.threat_intel.providers._shared import outcome_for_exception

logger = logging.getLogger(__name__)

_PROVIDER = "ipinfo_lite"


async def lookup_ip(
    client: ThreatIntelHttpClient,
    token: str,
    ip: str,
) -> tuple[GeoEnrichment | None, ProviderCallOutcome]:
    now = datetime.now(UTC).isoformat()
    url = f"https://ipinfo.io/lite/{ip}"
    try:
        result = await client.get(
            _PROVIDER,
            url,
            params={"token": token},
            max_requests_per_window=30,
            window_seconds=60,
        )
    except Exception as exc:
        return None, outcome_for_exception(_PROVIDER, exc, now)

    if result.status_code in (401, 403):
        return None, ProviderCallOutcome(_PROVIDER, False, "auth_failure", now, "invalid token")
    if result.status_code == 429:
        return None, ProviderCallOutcome(
            _PROVIDER, False, "rate_limited", now, "provider throttled the request"
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

    asn_field = payload.get("asn")  # e.g. "AS15169"
    enrichment = GeoEnrichment(
        provider=_PROVIDER,
        indicator=ip,
        country=payload.get("country"),
        country_code=payload.get("country_code"),
        region=None,  # not provided by the Lite tier
        city=None,  # not provided by the Lite tier
        latitude=None,
        longitude=None,
        asn=asn_field,
        organization=payload.get("as_name"),
        timezone=None,
        is_approximate=True,
        database_version_or_fetched_at=now,
        fetched_at=now,
    )
    return enrichment, ProviderCallOutcome(_PROVIDER, True, None, now, "ok")
