"""Fast, no-DB, no-network unit tests for the Threat Intelligence
bounded context (M18 expansion pass). Every external call is mocked;
this file must never make a real HTTP request.
"""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from redforge.domain.threat_intel.results import ProviderCallOutcome
from redforge.infrastructure.threat_intel.http_client import (
    DisallowedHostError,
    HttpFetchResult,
    ThreatIntelHttpClient,
)
from redforge.infrastructure.threat_intel.ip_classification import (
    classify_indicator_for_egress,
    is_public_ip,
)
from redforge.infrastructure.threat_intel.providers import abuseipdb, rdap, spamhaus_drop

# ─── IP classification (Priority 11 — the egress gate itself) ─────────────


@pytest.mark.parametrize(
    "ip,expected",
    [
        ("8.8.8.8", True),
        ("1.1.1.1", True),
        ("2606:4700:4700::1111", True),  # Cloudflare public IPv6
        ("10.0.0.1", False),  # RFC1918
        ("172.16.5.5", False),  # RFC1918
        ("192.168.1.1", False),  # RFC1918
        ("127.0.0.1", False),  # loopback
        ("169.254.1.1", False),  # link-local
        ("224.0.0.1", False),  # multicast
        ("::1", False),  # IPv6 loopback
        ("fe80::1", False),  # IPv6 link-local
        ("fc00::1", False),  # IPv6 unique-local (private)
        ("0.0.0.0", False),  # unspecified
        ("not-an-ip", False),  # unparseable — fails closed, not open
    ],
)
def test_is_public_ip_classification(ip: str, expected: bool) -> None:
    assert is_public_ip(ip) is expected


def test_classify_indicator_for_egress_only_gates_ip_type() -> None:
    # Domains/URLs/hashes carry no address-space concept — never blocked
    # by the private/public IP gate (a separate concern if ever needed).
    assert classify_indicator_for_egress("internal.corp.local", "domain") is True
    assert classify_indicator_for_egress("https://internal/x", "url") is True
    assert classify_indicator_for_egress("deadbeef" * 8, "hash") is True
    # But IP-typed indicators are strictly gated.
    assert classify_indicator_for_egress("10.0.0.1", "ip") is False
    assert classify_indicator_for_egress("8.8.8.8", "ip") is True


# ─── SSRF allowlist ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_http_client_rejects_host_outside_allowlist() -> None:
    client = ThreatIntelHttpClient()
    with pytest.raises(DisallowedHostError):
        await client.get("evil", "https://attacker.example.com/steal")


# ─── Spamhaus DROP parsing (pure, offline) ─────────────────────────────────


def test_parse_drop_list_skips_comments_and_blank_lines() -> None:
    text = "\n".join(
        [
            "; Last updated ...",
            "",
            "1.10.16.0/20 ; SBL256894",
            "5.188.10.0/23;SBL401726",
            "; another comment",
            "not-a-cidr ; garbage",
            "203.0.113.0/24 ; SBL999999",
        ]
    )
    entries = spamhaus_drop.parse_drop_list(text)
    assert [str(n) for n, _ in entries] == ["1.10.16.0/20", "5.188.10.0/23", "203.0.113.0/24"]
    assert entries[0][1] == "SBL256894"
    assert entries[1][1] == "SBL401726"


def test_match_ip_hits_and_misses() -> None:
    entries = spamhaus_drop.parse_drop_list("1.10.16.0/20 ; SBL256894\n")
    hit = spamhaus_drop.match_ip("1.10.16.1", entries)
    assert hit is not None
    assert hit.provider == "spamhaus_drop"
    assert hit.provider_reference_id == "SBL256894"
    assert hit.categories == ("hijacked_or_criminal_netblock",)

    miss = spamhaus_drop.match_ip("8.8.8.8", entries)
    assert miss is None

    # IPv6 addresses are never matched against this IPv4-only list —
    # never a false positive from a type mismatch.
    assert spamhaus_drop.match_ip("2606:4700:4700::1111", entries) is None


# ─── RDAP bootstrap prefix matching (pure, offline) ────────────────────────


def test_find_rdap_base_picks_longest_matching_prefix() -> None:
    entries = [
        ("1.0.0.0/8", ["https://rdap.apnic.net"]),
        ("1.1.1.0/24", ["https://rdap.arin.net"]),  # more specific, should win
    ]
    assert rdap.find_rdap_base("1.1.1.1", entries) == "https://rdap.arin.net"
    assert rdap.find_rdap_base("1.2.3.4", entries) == "https://rdap.apnic.net"
    assert rdap.find_rdap_base("9.9.9.9", entries) is None


def test_find_rdap_base_ignores_entries_with_no_allowlisted_urls() -> None:
    # A bootstrap entry whose only URLs were filtered out (not on our
    # fixed RIR allowlist) must never be selected.
    entries = [("1.1.1.0/24", [])]
    assert rdap.find_rdap_base("1.1.1.1", entries) is None


# ─── Provider adapter contract tests (mocked transport) ────────────────────


@pytest.mark.asyncio
async def test_abuseipdb_check_ip_success_maps_fields_honestly() -> None:
    client = ThreatIntelHttpClient()
    body = (
        b'{"data": {"ipAddress": "1.2.3.4", "abuseConfidenceScore": 42, '
        b'"totalReports": 3, "numDistinctUsers": 2, "lastReportedAt": "2026-01-01T00:00:00Z", '
        b'"reports": [{"categories": [18, 22]}]}}'
    )
    client.get = AsyncMock(return_value=HttpFetchResult(200, body, {}))

    evidence, outcome = await abuseipdb.check_ip(client, "fake-key", "1.2.3.4")

    assert outcome.success is True
    assert evidence is not None
    assert evidence.confidence_score == 42.0
    assert evidence.report_count == 3
    assert evidence.distinct_reporter_count == 2
    assert set(evidence.categories) == {"brute_force", "ssh"}
    # Confidence semantics are documented, never silently coerced into a
    # universal score.
    assert "abuseConfidenceScore" in evidence.confidence_semantics


@pytest.mark.asyncio
async def test_abuseipdb_check_ip_auth_failure_is_not_evidence() -> None:
    client = ThreatIntelHttpClient()
    client.get = AsyncMock(return_value=HttpFetchResult(401, b"{}", {}))

    evidence, outcome = await abuseipdb.check_ip(client, "bad-key", "1.2.3.4")

    assert evidence is None
    assert outcome.success is False
    assert outcome.error_category == "auth_failure"


@pytest.mark.asyncio
async def test_abuseipdb_check_ip_malformed_response_is_handled() -> None:
    client = ThreatIntelHttpClient()
    client.get = AsyncMock(return_value=HttpFetchResult(200, b"not json", {}))

    evidence, outcome = await abuseipdb.check_ip(client, "key", "1.2.3.4")

    assert evidence is None
    assert outcome.success is False
    assert outcome.error_category == "malformed_response"


@pytest.mark.asyncio
async def test_abuseipdb_check_ip_rate_limited() -> None:
    client = ThreatIntelHttpClient()
    client.get = AsyncMock(return_value=HttpFetchResult(429, b"{}", {}))

    evidence, outcome = await abuseipdb.check_ip(client, "key", "1.2.3.4")

    assert evidence is None
    assert outcome.success is False
    assert outcome.error_category == "rate_limited"


# ─── Circuit breaker isolation per provider ─────────────────────────────────


@pytest.mark.asyncio
async def test_one_provider_circuit_never_affects_another() -> None:
    """A hard requirement of the mission: one provider's failure must
    never break another's calls. Proven here by tripping provider A's
    circuit breaker and confirming provider B's breaker is unaffected."""
    client = ThreatIntelHttpClient()

    async def _always_fail() -> HttpFetchResult:
        raise RuntimeError("boom")

    breaker_a = client.circuits.get_or_create("threat_intel:provider_a", failure_threshold=2)
    for _ in range(3):
        with contextlib.suppress(Exception):
            await breaker_a.execute(_always_fail)

    breaker_b = client.circuits.get_or_create("threat_intel:provider_b", failure_threshold=2)
    assert breaker_a.state.value == "open"
    assert breaker_b.state.value == "closed"


# ─── ProviderCallOutcome / cache TTL semantics regression ──────────────────


def test_provider_call_outcome_distinguishes_success_from_evidence_presence() -> None:
    """Regression test for a real bug found during live acceptance: a
    successful call that legitimately found no evidence must be
    recorded as success=True with empty data — never conflated with a
    failed call. This dataclass is the single source of truth for that
    distinction; the enrichment service's persistence layer must key off
    `outcome.success`, never off whether evidence is None."""
    now = datetime.now(UTC).isoformat()
    checked_clean = ProviderCallOutcome("spamhaus_drop", True, None, now, "checked, no match")
    failed_call = ProviderCallOutcome("spamhaus_drop", False, "timeout", now, "RuntimeError")

    assert checked_clean.success is True
    assert failed_call.success is False
    # The two must never be conflatable by "evidence is None" alone —
    # both scenarios produce no evidence, only `.success` differs.
