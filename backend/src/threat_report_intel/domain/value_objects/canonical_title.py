"""Canonical-title normalization for threat_report_intel.

A `ThreatReport`'s dedup identity within a scope is its
`canonical_title`. Normalization mirrors `campaign_intel`'s
`normalize_canonical_name` convention exactly (defined locally, never
imported), so that "Operation Cloud Hopper: Technical Analysis",
"  operation-cloud-hopper: technical_analysis " and
"OPERATION CLOUD HOPPER: TECHNICAL ANALYSIS" all collapse to one
identity:

    - Unicode NFKC normalization
    - strip surrounding whitespace
    - lowercase
    - collapse every internal run of whitespace/underscore/hyphen to a
      single ASCII space

The aggregate keeps the analyst's real, NON-normalized `title` as a
separate stored display value; `canonical_title` is derived from it and
exists solely as the scope-level dedup key. The two are never
conflated: `title` is what a human reads, `canonical_title` is what
uniqueness is enforced on.

The result must be non-empty — an all-whitespace or all-punctuation
title is rejected as `InvalidCanonicalTitleError`.
"""

from __future__ import annotations

import re
import unicodedata

from threat_report_intel.domain.exceptions.domain_exceptions import (
    InvalidCanonicalTitleError,
)

_SEPARATOR_RUN = re.compile(r"[\s_\-]+")


def normalize_canonical_title(raw: str) -> str:
    if not isinstance(raw, str):
        raise InvalidCanonicalTitleError(str(raw))
    normalized = unicodedata.normalize("NFKC", raw).strip().lower()
    normalized = _SEPARATOR_RUN.sub(" ", normalized).strip()
    if not normalized:
        raise InvalidCanonicalTitleError(raw)
    return normalized
