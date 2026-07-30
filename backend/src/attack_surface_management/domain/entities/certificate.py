"""Certificate entity (M49A) — a TLS certificate observed serving an
`Asset`. Owned exclusively within the `Asset` aggregate. Identity
(`certificate_id`) is preserved across status transitions
(valid -> expired/revoked) via `dataclasses.replace`."""

from __future__ import annotations

import dataclasses
from datetime import datetime

from attack_surface_management.domain.exceptions.domain_exceptions import (
    InvalidCertificateWindowError,
)
from attack_surface_management.domain.value_objects.enums import CertificateStatus
from attack_surface_management.domain.value_objects.identifiers import CertificateId


@dataclasses.dataclass(frozen=True, slots=True)
class Certificate:
    certificate_id: CertificateId
    common_name: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    status: CertificateStatus

    def __post_init__(self) -> None:
        if not self.common_name.strip():
            raise InvalidCertificateWindowError("common_name must be non-empty")
        if self.not_before >= self.not_after:
            raise InvalidCertificateWindowError("not_before must precede not_after")

    def is_expired(self, now: datetime) -> bool:
        return now >= self.not_after

    def expires_within(self, now: datetime, window_days: int) -> bool:
        return 0 <= (self.not_after - now).days <= window_days

    def revoke(self) -> Certificate:
        return dataclasses.replace(self, status=CertificateStatus.REVOKED)

    def mark_expired(self) -> Certificate:
        return dataclasses.replace(self, status=CertificateStatus.EXPIRED)
