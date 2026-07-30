"""ServiceBanner value object (M49A) — the identified service running
behind an `OpenPort` (e.g. `ssh` / `OpenSSH 9.6`), including the
raw banner text used for downstream fingerprinting."""

from __future__ import annotations

from dataclasses import dataclass

from attack_surface_management.domain.exceptions.domain_exceptions import (
    InvalidTechnologyFingerprintError,
)

_HIGH_RISK_SERVICE_NAMES = frozenset({"telnet", "rdp", "smb", "ftp", "vnc"})


@dataclass(frozen=True, slots=True)
class ServiceBanner:
    name: str
    version: str | None = None
    banner: str | None = None

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise InvalidTechnologyFingerprintError("service name must be non-empty")
        object.__setattr__(self, "name", self.name.strip().lower())

    @property
    def is_high_risk_service(self) -> bool:
        return self.name in _HIGH_RISK_SERVICE_NAMES

    def __str__(self) -> str:
        return f"{self.name} {self.version}" if self.version else self.name
