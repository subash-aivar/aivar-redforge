"""AbuseIPDB reputation adapter.

Official docs: https://docs.abuseipdb.com/ — free tier requires an
account + API key, 1,000 `/check` requests/day. No commercial-use
prohibition documented (verified during this pass; see
docs/M18_INTELLIGENCE_PROVIDER_DECISION_MATRIX.md). Only the queried
public IP is ever sent — never any tenant/customer payload.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

from redforge.domain.threat_intel.results import ProviderCallOutcome, ReputationEvidence
from redforge.infrastructure.threat_intel.http_client import ThreatIntelHttpClient
from redforge.infrastructure.threat_intel.providers._shared import outcome_for_exception

logger = logging.getLogger(__name__)

_BASE_URL = "https://api.abuseipdb.com/api/v2/check"
_PROVIDER = "abuseipdb"

_CATEGORY_LABELS: dict[int, str] = {
    3: "fraud_orders",
    4: "ddos_attack",
    5: "ftp_brute_force",
    6: "ping_of_death",
    7: "phishing",
    8: "fraud_voip",
    9: "open_proxy",
    10: "web_spam",
    11: "email_spam",
    14: "port_scan",
    15: "hacking",
    16: "sql_injection",
    18: "brute_force",
    19: "bad_web_bot",
    20: "exploited_host",
    21: "web_app_attack",
    22: "ssh",
    23: "iot_targeted",
}


async def check_ip(
    client: ThreatIntelHttpClient,
    api_key: str,
    ip: str,
) -> tuple[ReputationEvidence | None, ProviderCallOutcome]:
    """Query AbuseIPDB's `/check` endpoint for a single public IP."""
    now = datetime.now(UTC).isoformat()
    try:
        result = await client.get(
            _PROVIDER,
            _BASE_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""},
            max_requests_per_window=20,
            window_seconds=60,
        )
    except Exception as exc:
        return None, outcome_for_exception(_PROVIDER, exc, now)

    if result.status_code == 401 or result.status_code == 403:
        return None, ProviderCallOutcome(
            _PROVIDER, False, "auth_failure", now, "invalid or missing API key"
        )
    if result.status_code == 429:
        return None, ProviderCallOutcome(
            _PROVIDER, False, "rate_limited", now, "daily quota exhausted"
        )
    if result.status_code != 200:
        return None, ProviderCallOutcome(
            _PROVIDER, False, "provider_error", now, f"HTTP {result.status_code}"
        )

    try:
        payload = json.loads(result.body)["data"]
    except (json.JSONDecodeError, KeyError, TypeError):
        return None, ProviderCallOutcome(
            _PROVIDER, False, "malformed_response", now, "unexpected response shape"
        )

    categories: set[str] = set()
    for report in payload.get("reports", []) or []:
        for cat_id in report.get("categories", []) or []:
            label = _CATEGORY_LABELS.get(cat_id)
            if label:
                categories.add(label)

    evidence = ReputationEvidence(
        provider=_PROVIDER,
        indicator=ip,
        indicator_type="ip",
        confidence_score=float(payload.get("abuseConfidenceScore", 0)),
        confidence_semantics=(
            "AbuseIPDB abuseConfidenceScore: 0-100 likelihood that community "
            "abuse reports for this IP are legitimate — not a universal "
            "threat probability."
        ),
        categories=tuple(sorted(categories)),
        report_count=payload.get("totalReports"),
        distinct_reporter_count=payload.get("numDistinctUsers"),
        last_reported_at=payload.get("lastReportedAt"),
        provider_reference_id=None,
        fetched_at=now,
        raw_provider_url=_BASE_URL,
    )
    return evidence, ProviderCallOutcome(_PROVIDER, True, None, now, "ok")
