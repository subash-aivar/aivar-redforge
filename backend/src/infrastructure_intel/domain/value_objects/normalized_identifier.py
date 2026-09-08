"""Per-type identifier normalization for infrastructure_intel.

An `Infrastructure` record's dedup identity within a scope is
`(infrastructure_type, normalized_identifier)`. Normalization is
type-directed, strong and deterministic, so that every construction
path (factory, repository rehydration) yields exactly one form:

    ASN               "as15169", "AS 15169", "15169"  -> "AS15169"
    IP_ADDRESS        " 2001:0DB8::1 "                -> "2001:db8::1"
                      (canonical form via the `ipaddress` stdlib)
    DOMAIN / URL      "  EVIL.Example.COM "           -> "evil.example.com"
    HOSTING_PROVIDER  "  Bullet-Proof_Hosting "       -> "bullet proof hosting"
    CLOUD_PROVIDER    (same free-text collapse as HOSTING_PROVIDER)

Format-validated, not over-engineered: this rejects the unusable
(empty, an ASN that is not a number, an IP that is not an IP) without
pretending to resolve, reach, or verify anything about the real
infrastructure.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata

from infrastructure_intel.domain.exceptions.domain_exceptions import (
    InvalidNormalizedIdentifierError,
)
from infrastructure_intel.domain.value_objects.enums import InfrastructureType

_SEPARATOR_RUN = re.compile(r"[\s_\-]+")
_ASN_PATTERN = re.compile(r"^(?:AS)?(\d{1,10})$", re.I)


def _collapse_free_text(raw: str) -> str:
    normalized = unicodedata.normalize("NFKC", raw).strip().lower()
    return _SEPARATOR_RUN.sub(" ", normalized).strip()


def _normalize_asn(raw: str) -> str:
    match = _ASN_PATTERN.match(_SEPARATOR_RUN.sub("", unicodedata.normalize("NFKC", raw).strip()))
    if match is None:
        raise InvalidNormalizedIdentifierError(InfrastructureType.ASN.value, raw)
    return f"AS{int(match.group(1))}"


def _normalize_ip(raw: str) -> str:
    try:
        return str(ipaddress.ip_address(unicodedata.normalize("NFKC", raw).strip()))
    except ValueError as exc:
        raise InvalidNormalizedIdentifierError(InfrastructureType.IP_ADDRESS.value, raw) from exc


def _normalize_lowercase(raw: str, infrastructure_type: InfrastructureType) -> str:
    normalized = unicodedata.normalize("NFKC", raw).strip().lower()
    if not normalized or _SEPARATOR_RUN.fullmatch(normalized):
        raise InvalidNormalizedIdentifierError(infrastructure_type.value, raw)
    return normalized


def normalize_identifier(infrastructure_type: InfrastructureType, raw: str) -> str:
    if not isinstance(raw, str):
        raise InvalidNormalizedIdentifierError(str(infrastructure_type), str(raw))

    if infrastructure_type is InfrastructureType.ASN:
        return _normalize_asn(raw)
    if infrastructure_type is InfrastructureType.IP_ADDRESS:
        return _normalize_ip(raw)
    if infrastructure_type in (InfrastructureType.DOMAIN, InfrastructureType.URL):
        return _normalize_lowercase(raw, infrastructure_type)

    # HOSTING_PROVIDER / CLOUD_PROVIDER are free-text names — collapsed
    # the same way an adversary-tool canonical name is.
    normalized = _collapse_free_text(raw)
    if not normalized:
        raise InvalidNormalizedIdentifierError(infrastructure_type.value, raw)
    return normalized
