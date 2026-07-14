"""Shared, provider-agnostic helpers for adapter implementations."""

from __future__ import annotations

from redforge.domain.threat_intel.results import ProviderCallOutcome


def fail(provider: str, category: str, now: str, detail: str) -> tuple[None, ProviderCallOutcome]:
    """Shorthand for the common `return None, ProviderCallOutcome(...)`
    failure case — keeps call sites under the line-length limit."""
    return None, ProviderCallOutcome(provider, False, category, now, detail)


def ok_empty(provider: str, now: str, detail: str) -> tuple[None, ProviderCallOutcome]:
    """Shorthand for an honest negative result (no evidence found, which
    is success, not failure)."""
    return None, ProviderCallOutcome(provider, True, None, now, detail)


def outcome_for_exception(provider: str, exc: Exception, now: str) -> ProviderCallOutcome:
    """Map a raised exception to a secret-free, low-cardinality error
    category — never includes the exception's own message verbatim,
    since some transports embed request headers/URLs in their repr."""
    name = type(exc).__name__
    category = (
        "timeout"
        if "Timeout" in name
        else "rate_limited"
        if "RateLimited" in name
        else "circuit_open"
        if "CircuitOpen" in name
        else "response_too_large"
        if "TooLarge" in name
        else "disallowed_host"
        if "DisallowedHost" in name
        else "transport_error"
    )
    return ProviderCallOutcome(provider, False, category, now, name)
