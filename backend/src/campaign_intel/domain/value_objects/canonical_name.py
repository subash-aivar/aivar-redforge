"""Canonical-name normalization for campaign_intel.

A `Campaign`'s dedup identity within a scope is its `canonical_name`.
Normalization is strong and deterministic so that "Cloud Hopper",
"  cloud-hopper ", and "CLOUD_HOPPER" all collapse to a single identity:

    - Unicode NFKC normalization
    - strip surrounding whitespace
    - lowercase
    - collapse every internal run of whitespace/underscore/hyphen to a
      single ASCII space

The result must be non-empty — an all-whitespace or all-punctuation
name is rejected as `InvalidCanonicalNameError`.
"""

from __future__ import annotations

import re
import unicodedata

from campaign_intel.domain.exceptions.domain_exceptions import InvalidCanonicalNameError

_SEPARATOR_RUN = re.compile(r"[\s_\-]+")


def normalize_canonical_name(raw: str) -> str:
    if not isinstance(raw, str):
        raise InvalidCanonicalNameError(str(raw))
    normalized = unicodedata.normalize("NFKC", raw).strip().lower()
    normalized = _SEPARATOR_RUN.sub(" ", normalized).strip()
    if not normalized:
        raise InvalidCanonicalNameError(raw)
    return normalized
