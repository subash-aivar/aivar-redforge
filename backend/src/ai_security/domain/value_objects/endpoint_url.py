"""EndpointUrl — a validated URL-shaped string value object (M47A).
Deliberately opaque: this domain layer only checks a non-empty
http(s):// scheme shape, it never connects to or resolves the URL."""

from __future__ import annotations

from dataclasses import dataclass

from ai_security.domain.exceptions.domain_exceptions import InvalidEndpointUrlError


@dataclass(frozen=True, slots=True)
class EndpointUrl:
    value: str

    def __post_init__(self) -> None:
        stripped = self.value.strip()
        if not stripped or not (stripped.startswith("http://") or stripped.startswith("https://")):
            raise InvalidEndpointUrlError(self.value)

    def __str__(self) -> str:
        return self.value
