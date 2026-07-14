"""Spamhaus DROP/EDROP local blocklist adapter.

Official source: https://www.spamhaus.org/drop/drop.txt (DROP) and
https://www.spamhaus.org/drop/edrop.txt (EDROP), combined by Spamhaus
into a single list. Free, keyless, no account. The only restriction is
on using the "Spamhaus" name in marketing/commercial materials — the
data itself carries no commercial-use prohibition (see decision matrix).

Privacy note: this is the best-behaved provider in this bounded context
— we download the full CIDR list on our own schedule and match locally.
No per-IP query is ever sent to Spamhaus.
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import UTC, datetime

from redforge.domain.threat_intel.results import ProviderCallOutcome, ReputationEvidence
from redforge.infrastructure.threat_intel.http_client import ThreatIntelHttpClient
from redforge.infrastructure.threat_intel.providers._shared import outcome_for_exception

logger = logging.getLogger(__name__)

_PROVIDER = "spamhaus_drop"
_DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
_EDROP_URL = "https://www.spamhaus.org/drop/edrop.txt"


def parse_drop_list(text: str) -> list[tuple[ipaddress.IPv4Network, str]]:
    """Parse the plain-text DROP/EDROP format: `CIDR ; SBL_reference`.
    Blank lines and `;`-prefixed comment lines are skipped."""
    entries: list[tuple[ipaddress.IPv4Network, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split(";", 1)
        cidr = parts[0].strip()
        reference = parts[1].strip() if len(parts) > 1 else ""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if isinstance(network, ipaddress.IPv4Network):
            entries.append((network, reference))
    return entries


async def fetch_drop_lists(
    client: ThreatIntelHttpClient,
) -> tuple[list[tuple[ipaddress.IPv4Network, str]] | None, ProviderCallOutcome]:
    """Download and parse both DROP and EDROP. Callers should cache the
    result for ~24h — Spamhaus regenerates these lists periodically, not
    continuously, so more-frequent polling has no benefit."""
    now = datetime.now(UTC).isoformat()
    entries: list[tuple[ipaddress.IPv4Network, str]] = []
    try:
        for url in (_DROP_URL, _EDROP_URL):
            result = await client.get(
                _PROVIDER,
                url,
                max_requests_per_window=4,
                window_seconds=3600,
            )
            if result.status_code != 200:
                return None, ProviderCallOutcome(
                    _PROVIDER,
                    False,
                    "provider_error",
                    now,
                    f"HTTP {result.status_code} from {url}",
                )
            entries.extend(parse_drop_list(result.body.decode("utf-8", errors="replace")))
    except Exception as exc:
        return None, outcome_for_exception(_PROVIDER, exc, now)

    return entries, ProviderCallOutcome(
        _PROVIDER, True, None, now, f"{len(entries)} networks loaded"
    )


def match_ip(
    ip: str,
    drop_entries: list[tuple[ipaddress.IPv4Network, str]],
) -> ReputationEvidence | None:
    """Pure, local, offline lookup — no network call. `drop_entries` is
    whatever the caller last cached from `fetch_drop_lists`."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if not isinstance(addr, ipaddress.IPv4Address):
        return None
    for network, reference in drop_entries:
        if addr in network:
            now = datetime.now(UTC).isoformat()
            return ReputationEvidence(
                provider=_PROVIDER,
                indicator=ip,
                indicator_type="ip",
                confidence_score=None,
                confidence_semantics=(
                    "Spamhaus DROP/EDROP membership — this network block is "
                    "one Spamhaus has identified as hijacked or entirely "
                    "controlled by cybercriminals. Binary evidence, not a "
                    "numeric score."
                ),
                categories=("hijacked_or_criminal_netblock",),
                report_count=None,
                distinct_reporter_count=None,
                last_reported_at=None,
                provider_reference_id=reference or None,
                fetched_at=now,
                raw_provider_url=_DROP_URL,
            )
    return None
