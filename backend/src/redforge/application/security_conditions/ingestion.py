"""Typed Security Condition ingestion contract — M8.

This dataclass is the ONLY shape through which a condition can be
created — routers, M6 network analysis, and M7 cloud analysis must all
construct one of these and call
`TenantSecurityConditionService.ingest()`; none of them write
`security_conditions` ORM rows directly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

MAX_EVIDENCE_ITEMS = 5
MAX_EVIDENCE_VALUE_LENGTH = 500

_REDACTED = "[REDACTED]"

# Defense-in-depth secret-shaped-value redaction. Evidence is sourced
# from deterministic M6/M7 analyzers today, neither of which passes
# credential material — but the sanitizer itself must not trust
# callers to never do so; a credential-shaped value must never survive
# into persisted evidence, the condition API, or Security Graph
# attributes even if a future producer accidentally includes one.
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key ID
    re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*\S+"),
    re.compile(r"(?i)\b(?:x-)?session[_-]?token\s*[:=]\s*\S+"),
    re.compile(r"(?i)bearer\s+[a-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)authorization\s*[:=]\s*\S+"),
    re.compile(r"sk-[a-zA-Z0-9]{16,}"),  # generic provider/OAuth secret token shape
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)(?:client[_-]?secret|bind[_-]?password|mfa[_-]?secret)\s*[:=]\s*\S+"),
)


def _redact_secrets(value: str) -> str:
    redacted = value
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub(_REDACTED, redacted)
    return redacted


@dataclass(frozen=True, slots=True)
class SecurityConditionInput:
    organization_id: str
    affected_asset_id: str
    source_category: str
    stable_rule_id: str
    evidence_state: str
    severity: str
    title: str
    summary: str
    remediation: str = ""
    qualifier: str = ""
    canonical_references: tuple[str, ...] = ()
    evidence: tuple[tuple[str, str], ...] = ()  # (label, value) pairs


def sanitize_evidence(evidence: tuple[tuple[str, str], ...]) -> list[dict[str, str]]:
    """Bounded, sanitized evidence — at most `MAX_EVIDENCE_ITEMS`
    entries, each value truncated to `MAX_EVIDENCE_VALUE_LENGTH`
    characters with truncation made explicit (never silently altered
    and called complete)."""
    sanitized: list[dict[str, str]] = []
    for label, value in evidence[:MAX_EVIDENCE_ITEMS]:
        redacted_value = _redact_secrets(value)
        truncated = len(redacted_value) > MAX_EVIDENCE_VALUE_LENGTH
        safe_value = redacted_value[:MAX_EVIDENCE_VALUE_LENGTH]
        sanitized.append({
            "label": _redact_secrets(label)[:100],
            "value": safe_value,
            "truncated": "true" if truncated else "false",
        })
    return sanitized
