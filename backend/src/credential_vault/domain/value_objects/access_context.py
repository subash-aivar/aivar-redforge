"""Access context value object for resolution and mutation audit trails."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from credential_vault.domain.value_objects.identifiers import PrincipalId


@dataclass(frozen=True, slots=True)
class AccessContext:
    """Carries caller identity + access reason for audit trail."""

    principal_id: PrincipalId
    purpose: str
    client_ip: str | None
    request_id: str | None
    break_glass: bool = False
    justification: str | None = None

    def __post_init__(self) -> None:
        if not self.purpose:
            raise ValueError("purpose required")
        if len(self.purpose) > 512:
            raise ValueError("purpose max 512 chars")
        if self.break_glass and not self.justification:
            raise ValueError("justification required for break-glass access")
        if self.justification is not None and len(self.justification) > 2048:
            raise ValueError("justification max 2048 chars")
        if self.request_id is not None and len(self.request_id) > 128:
            raise ValueError("request_id max 128 chars")
        if self.client_ip is not None:
            try:
                ipaddress.ip_address(self.client_ip)
            except ValueError as exc:
                raise ValueError("client_ip must be valid IPv4/IPv6") from exc
