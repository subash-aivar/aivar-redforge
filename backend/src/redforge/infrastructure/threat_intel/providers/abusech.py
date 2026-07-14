"""abuse.ch (URLhaus + ThreatFox) IOC adapter — OPTIONAL, ships disabled
by default.

Official docs explicitly state: "Use of the API by companies, networks,
or individuals with commercial or for-profit needs may require a paid
subscription for the enhanced abuse.ch commercial API." RedForge is a
commercial product, so this adapter is built and ready but must be
explicitly enabled per organization, with an admin-facing disclaimer
requiring the operator to confirm their own compliance (free Community
API for internal/eval use, or a Spamhaus Technology commercial
subscription) before it is used. See
docs/M18_INTELLIGENCE_PROVIDER_DECISION_MATRIX.md.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

from redforge.domain.threat_intel.results import IocMatch, ProviderCallOutcome
from redforge.infrastructure.threat_intel.http_client import ThreatIntelHttpClient
from redforge.infrastructure.threat_intel.providers._shared import outcome_for_exception

logger = logging.getLogger(__name__)

_PROVIDER = "abusech"
_THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
_URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/host/"


async def check_threatfox_ioc(
    client: ThreatIntelHttpClient,
    auth_key: str,
    indicator: str,
) -> tuple[IocMatch | None, ProviderCallOutcome]:
    """ThreatFox `search_ioc` query — works for ip:port, domain, url, hash."""
    now = datetime.now(UTC).isoformat()
    try:
        result = await client.post(
            _PROVIDER,
            _THREATFOX_URL,
            headers={"Auth-Key": auth_key},
            json_body={"query": "search_ioc", "search_term": indicator},
            max_requests_per_window=15,
            window_seconds=60,
        )
    except Exception as exc:
        return None, outcome_for_exception(_PROVIDER, exc, now)

    if result.status_code in (401, 403):
        return None, ProviderCallOutcome(_PROVIDER, False, "auth_failure", now, "invalid Auth-Key")
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

    if payload.get("query_status") != "ok" or not payload.get("data"):
        return None, ProviderCallOutcome(_PROVIDER, True, None, now, "no IOC match")

    entry = payload["data"][0]
    match = IocMatch(
        provider=_PROVIDER,
        indicator=indicator,
        indicator_type="ip",
        threat_type=entry.get("threat_type"),
        malware_family=entry.get("malware"),
        tags=tuple(entry.get("tags") or []),
        provider_first_seen=entry.get("first_seen"),
        provider_last_seen=entry.get("last_seen"),
        provider_reference_id=str(entry.get("id")) if entry.get("id") else None,
        fetched_at=now,
    )
    return match, ProviderCallOutcome(_PROVIDER, True, None, now, "ok")


async def check_urlhaus_host(
    client: ThreatIntelHttpClient,
    auth_key: str,
    host: str,
) -> tuple[IocMatch | None, ProviderCallOutcome]:
    now = datetime.now(UTC).isoformat()
    try:
        result = await client.post(
            _PROVIDER,
            _URLHAUS_URL,
            headers={"Auth-Key": auth_key},
            json_body={"host": host},
            max_requests_per_window=15,
            window_seconds=60,
        )
    except Exception as exc:
        return None, outcome_for_exception(_PROVIDER, exc, now)

    if result.status_code in (401, 403):
        return None, ProviderCallOutcome(_PROVIDER, False, "auth_failure", now, "invalid Auth-Key")
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

    if payload.get("query_status") != "ok" or not payload.get("urls"):
        return None, ProviderCallOutcome(_PROVIDER, True, None, now, "no URLhaus match")

    urls = payload["urls"]
    match = IocMatch(
        provider=_PROVIDER,
        indicator=host,
        indicator_type="domain",
        threat_type="malware_distribution",
        malware_family=None,
        tags=tuple({tag for entry in urls for tag in (entry.get("tags") or [])})[:20],
        provider_first_seen=payload.get("firstseen"),
        provider_last_seen=urls[0].get("date_added") if urls else None,
        provider_reference_id=str(payload.get("id")) if payload.get("id") else None,
        fetched_at=now,
    )
    return match, ProviderCallOutcome(_PROVIDER, True, None, now, f"{len(urls)} URL(s)")
