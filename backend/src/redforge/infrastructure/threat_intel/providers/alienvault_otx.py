"""AlienVault OTX (LevelBlue Open Threat Exchange) IOC correlation adapter.

Official docs: https://otx.alienvault.com/api — free with account/API
key. No numeric rate limit is published; we self-impose a conservative
window (see `max_requests_per_window` below) since the provider's own
support forum shows other integrators hitting undocumented throttling
at volume.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

from redforge.domain.threat_intel.results import IocMatch, ProviderCallOutcome
from redforge.infrastructure.threat_intel.http_client import ThreatIntelHttpClient
from redforge.infrastructure.threat_intel.providers._shared import outcome_for_exception

logger = logging.getLogger(__name__)

_PROVIDER = "alienvault_otx"


def _indicator_path_type(indicator_type: str) -> str:
    return {"ip": "IPv4", "domain": "domain", "url": "url", "hash": "file"}[indicator_type]


async def check_indicator(
    client: ThreatIntelHttpClient,
    api_key: str,
    indicator: str,
    indicator_type: str,
) -> tuple[IocMatch | None, ProviderCallOutcome]:
    now = datetime.now(UTC).isoformat()
    otx_type = _indicator_path_type(indicator_type)
    url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{indicator}/general"
    try:
        result = await client.get(
            _PROVIDER,
            url,
            headers={"X-OTX-API-KEY": api_key},
            max_requests_per_window=10,
            window_seconds=60,
        )
    except Exception as exc:
        return None, outcome_for_exception(_PROVIDER, exc, now)

    if result.status_code in (401, 403):
        return None, ProviderCallOutcome(_PROVIDER, False, "auth_failure", now, "invalid API key")
    if result.status_code == 404:
        # Genuinely "no pulses reference this indicator" — a real, honest
        # negative result, not an error.
        return None, ProviderCallOutcome(_PROVIDER, True, None, now, "no pulses found")
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

    pulse_info = payload.get("pulse_info") or {}
    pulses = pulse_info.get("pulses") or []
    if not pulses:
        return None, ProviderCallOutcome(_PROVIDER, True, None, now, "no pulses found")

    tags: set[str] = set()
    malware_families: set[str] = set()
    for pulse in pulses[:25]:
        for tag in pulse.get("tags", []) or []:
            tags.add(tag)
        for family in pulse.get("malware_families", []) or []:
            name = family.get("display_name") if isinstance(family, dict) else str(family)
            if name:
                malware_families.add(name)

    match = IocMatch(
        provider=_PROVIDER,
        indicator=indicator,
        indicator_type=indicator_type,
        threat_type="pulse_reference",
        malware_family=", ".join(sorted(malware_families)) or None,
        tags=tuple(sorted(tags))[:20],
        provider_first_seen=None,
        provider_last_seen=pulses[0].get("modified") if pulses else None,
        provider_reference_id=pulses[0].get("id") if pulses else None,
        fetched_at=now,
    )
    return match, ProviderCallOutcome(_PROVIDER, True, None, now, f"{len(pulses)} pulse(s)")
