"""IndicatorValue / IndicatorCanonicalKey — deterministic normalization
and deduplication for ioc_intelligence (M51.2 Phase A).

Generalizes `redforge.domain.threat_intel.fusion_value_objects.
CanonicalIndicatorKey`'s exact `{type}:{normalized_value}` pattern, but
built for `IocType` (ip/domain/url/hash) rather than
`FusedIndicatorType` (technique/tactic/vulnerability/...) — that
module's own indicator type vocabulary belongs to attack-pattern/
campaign/malware-shaped reference data, not observable IOCs (see the
M51.2 Phase A repository audit). No network calls — normalization is
pure string/format validation, never a DNS/WHOIS/reputation lookup.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from ioc_intelligence.domain.exceptions.domain_exceptions import (
    InvalidIndicatorCanonicalKeyError,
    InvalidIndicatorValueError,
)
from ioc_intelligence.domain.value_objects.enums import IocType

_CANONICAL_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{1,15}:.{1,2048}$")

_DOMAIN_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_HASH_HEX_RE = re.compile(r"^[0-9a-f]+$")
_HASH_VALID_LENGTHS = frozenset({32, 40, 64, 96, 128})  # MD5, SHA1, SHA256, SHA384, SHA512


def normalize_indicator_value(ioc_type: IocType, raw_value: str) -> str:
    """Deterministic, pure normalization — equivalent raw values for the
    same `ioc_type` always produce the same output. Raises
    `InvalidIndicatorValueError` for anything that doesn't parse as a
    genuine value of that type; never silently accepts garbage."""
    value = raw_value.strip()
    if not value:
        raise InvalidIndicatorValueError(ioc_type.value, raw_value, "value is empty")

    if ioc_type is IocType.IP:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise InvalidIndicatorValueError(
                ioc_type.value, raw_value, "not a valid IPv4/IPv6 address"
            ) from exc

    if ioc_type is IocType.DOMAIN:
        candidate = value.lower().rstrip(".")
        labels = candidate.split(".")
        if len(labels) < 2 or not all(_DOMAIN_LABEL_RE.match(label) for label in labels):
            raise InvalidIndicatorValueError(ioc_type.value, raw_value, "not a valid domain name")
        return candidate

    if ioc_type is IocType.URL:
        parts = urlsplit(value)
        if not parts.scheme or not parts.netloc:
            raise InvalidIndicatorValueError(
                ioc_type.value, raw_value, "not a valid absolute URL (missing scheme or host)"
            )
        normalized_netloc = parts.netloc.lower()
        return parts._replace(scheme=parts.scheme.lower(), netloc=normalized_netloc).geturl()

    if ioc_type is IocType.HASH:
        candidate = value.lower()
        if not _HASH_HEX_RE.match(candidate) or len(candidate) not in _HASH_VALID_LENGTHS:
            raise InvalidIndicatorValueError(
                ioc_type.value,
                raw_value,
                "not a recognized hex hash length (MD5/SHA1/SHA256/SHA384/SHA512)",
            )
        return candidate

    raise InvalidIndicatorValueError(ioc_type.value, raw_value, "unsupported indicator type")


@dataclass(frozen=True, slots=True)
class IndicatorCanonicalKey:
    """Deterministic deduplication key: `{type}:{normalized_value}`.
    Two observations of the same underlying indicator — however they
    were originally formatted — always collide on one `IOC`."""

    value: str

    def __post_init__(self) -> None:
        if not _CANONICAL_KEY_RE.match(self.value):
            raise InvalidIndicatorCanonicalKeyError(self.value)

    @classmethod
    def for_type(cls, ioc_type: IocType, raw_value: str) -> IndicatorCanonicalKey:
        normalized = normalize_indicator_value(ioc_type, raw_value)
        return cls(f"{ioc_type.value}:{normalized}")

    @property
    def ioc_type(self) -> IocType:
        prefix, _sep, _rest = self.value.partition(":")
        return IocType(prefix)

    @property
    def normalized_value(self) -> str:
        _prefix, _sep, rest = self.value.partition(":")
        return rest

    def __str__(self) -> str:
        return self.value
