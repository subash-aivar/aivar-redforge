"""DnsRecordEntry entity (M49A) — a single DNS record observed for an
`Asset`. Owned exclusively within the `Asset` aggregate; individually
identified so records can be added/removed independently as discovery
data changes without replacing the whole DNS record set."""

from __future__ import annotations

import dataclasses
from datetime import datetime

from attack_surface_management.domain.exceptions.domain_exceptions import InvalidDnsRecordError
from attack_surface_management.domain.value_objects.enums import DnsRecordType
from attack_surface_management.domain.value_objects.identifiers import DnsRecordId


@dataclasses.dataclass(frozen=True, slots=True)
class DnsRecordEntry:
    record_id: DnsRecordId
    record_type: DnsRecordType
    name: str
    value: str
    ttl_seconds: int
    detected_at: datetime

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise InvalidDnsRecordError("name must be non-empty")
        if not self.value.strip():
            raise InvalidDnsRecordError("value must be non-empty")
        if self.ttl_seconds < 0:
            raise InvalidDnsRecordError(f"ttl_seconds must be >= 0, got {self.ttl_seconds}")
