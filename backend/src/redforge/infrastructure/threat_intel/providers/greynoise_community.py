"""GreyNoise Community API adapter — OPTIONAL, ships disabled by default.

Official docs: docs.greynoise.io/docs/using-the-greynoise-community-api
— the Community tier is capped at 50 combined searches/week across the
API and the web Visualizer. That quota is incompatible with automatic
per-event enrichment, so this adapter is wired for manual/on-demand
lookups only and must be explicitly enabled per organization (see
`ThreatIntelProviderConfigService`); it is never called from the
automatic IOC correlation pipeline.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

from redforge.domain.threat_intel.results import ProviderCallOutcome, ReputationEvidence
from redforge.infrastructure.threat_intel.http_client import ThreatIntelHttpClient
from redforge.infrastructure.threat_intel.providers._shared import outcome_for_exception

logger = logging.getLogger(__name__)

_PROVIDER = "greynoise_community"


async def check_ip(
    client: ThreatIntelHttpClient,
    api_key: str,
    ip: str,
) -> tuple[ReputationEvidence | None, ProviderCallOutcome]:
    now = datetime.now(UTC).isoformat()
    url = f"https://api.greynoise.io/v3/community/{ip}"
    try:
        result = await client.get(
            _PROVIDER,
            url,
            headers={"key": api_key},
            max_requests_per_window=2,
            window_seconds=3600,  # 50/week self-imposed hard cap
        )
    except Exception as exc:
        return None, outcome_for_exception(_PROVIDER, exc, now)

    if result.status_code in (401, 403):
        return None, ProviderCallOutcome(_PROVIDER, False, "auth_failure", now, "invalid API key")
    if result.status_code == 429:
        return None, ProviderCallOutcome(
            _PROVIDER, False, "quota_exhausted", now, "weekly Community quota hit"
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

    classification = payload.get("classification")
    evidence = ReputationEvidence(
        provider=_PROVIDER,
        indicator=ip,
        indicator_type="ip",
        confidence_score=None,
        confidence_semantics=(
            "GreyNoise classification is categorical (benign/malicious/"
            "unknown), not a numeric score — it indicates whether this IP "
            "is known internet background-noise scanning activity."
        ),
        categories=(classification,) if classification else (),
        report_count=None,
        distinct_reporter_count=None,
        last_reported_at=payload.get("last_seen"),
        provider_reference_id=None,
        fetched_at=now,
        raw_provider_url=url,
    )
    return evidence, ProviderCallOutcome(_PROVIDER, True, None, now, "ok")
