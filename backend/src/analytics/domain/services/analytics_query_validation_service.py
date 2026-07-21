"""AnalyticsQueryValidationService — C5 invariants (Phase 2)."""

from __future__ import annotations

import re

from analytics.domain.exceptions.domain_exceptions import AnalyticsQueryValidationError

FORBIDDEN_PATTERNS = (
    re.compile(r";"),
    re.compile(r"\b(DROP|ALTER|INSERT|UPDATE|DELETE|TRUNCATE|GRANT|REVOKE|UNION)\b", re.I),
    re.compile(r"--"),
    re.compile(r"/\*"),
    # No string-formatted SQL (C5) — only named bound params
    re.compile(r"%s"),
    re.compile(r"%\("),
    re.compile(r"\{[^}]+\}"),
    re.compile(r"\bOR\b\s+1\s*=\s*1", re.I),
    re.compile(r"\bAND\b\s+1\s*=\s*1", re.I),
)
MAX_ROWS_ABSOLUTE = 10_000
BLOCKED_SCHEMAS = (
    "public.",
    "redforge.",
    "exposure.",
    "vulnerability.",
    "detection.",
    "campaign.",
    "ai_posture.",
    "ml_pipeline.",
    "reporting.",
)


class AnalyticsQueryValidationService:
    def validate_template(self, template: str) -> None:
        if ":tenant_id" not in template:
            raise AnalyticsQueryValidationError("Template must contain :tenant_id parameter")
        lowered = template.lower()
        if "analytics." not in lowered:
            raise AnalyticsQueryValidationError("Template must reference analytics schema tables")
        for schema in BLOCKED_SCHEMAS:
            if schema in lowered:
                raise AnalyticsQueryValidationError(
                    f"Template must not reference non-analytics schema: {schema}"
                )
        for pat in FORBIDDEN_PATTERNS:
            if pat.search(template):
                raise AnalyticsQueryValidationError("Template contains forbidden SQL constructs")

    def sanitize_parameters(
        self, parameters: dict[str, object], *, tenant_id: str
    ) -> dict[str, object]:
        cleaned = dict(parameters)
        cleaned["tenant_id"] = tenant_id
        return cleaned
