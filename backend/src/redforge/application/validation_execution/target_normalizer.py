"""Target normalization for M11 active validation.

Takes an `AITarget.endpoint` (already validated at the domain layer to
match `^https?://\\S+$`, per `domain.ai_targets.value_objects.EndpointUrl`)
and re-validates it strictly enough to safely drive real network
activity: rejects anything a naive client could use to smuggle a
credential, confuse a parser, or reach an unintended host.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from redforge.domain.validation_execution.exceptions import TargetNormalizationError

_ALLOWED_SCHEMES = frozenset({"http", "https"})


@dataclass(frozen=True, slots=True)
class NormalizedTarget:
    scheme: str
    hostname: str
    port: int
    path: str
    query: str
    original_url: str

    @property
    def is_https(self) -> bool:
        return self.scheme == "https"

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.hostname}:{self.port}"


def normalize_target(endpoint_url: str) -> NormalizedTarget:
    """Raises TargetNormalizationError for anything unsafe to dispatch
    against. Never silently coerces an ambiguous URL into a "best
    guess" — an ambiguous or malformed target is always rejected."""
    try:
        parts = urlsplit(endpoint_url)
    except ValueError as exc:
        raise TargetNormalizationError(f"unparseable URL: {exc}") from exc

    scheme = parts.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise TargetNormalizationError(f"unsupported scheme '{parts.scheme}'")

    if parts.username is not None or parts.password is not None:
        raise TargetNormalizationError("URL userinfo (user:pass@host) is not permitted")

    hostname = parts.hostname
    if not hostname:
        raise TargetNormalizationError("missing or ambiguous host")

    # urlsplit already rejects the most common ambiguous-host shapes
    # (multiple '@', malformed IPv6 brackets) by raising ValueError or
    # returning None for .hostname — but explicitly reject a handful of
    # additional shapes that parse "successfully" yet are still
    # ambiguous/unsafe to dispatch against.
    if "\\" in endpoint_url or " " in hostname:
        raise TargetNormalizationError("ambiguous host syntax")
    if hostname.count("@") > 0:
        raise TargetNormalizationError("ambiguous host syntax")

    try:
        port = parts.port if parts.port is not None else (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise TargetNormalizationError(f"invalid port: {exc}") from exc

    return NormalizedTarget(
        scheme=scheme,
        hostname=hostname,
        port=port,
        path=parts.path or "/",
        query=parts.query,
        original_url=endpoint_url,
    )
