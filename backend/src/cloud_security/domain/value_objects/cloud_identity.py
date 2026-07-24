"""CloudIdentity — a reference to an IAM principal reported by a
provider (M45A). A foundation-level value object only; identity
graph/permission analysis is out of scope for this milestone."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from cloud_security.domain.exceptions.domain_exceptions import EmptyIdentifierError

if TYPE_CHECKING:
    from cloud_security.domain.value_objects.enums import CloudIdentityType


@dataclass(frozen=True, slots=True)
class CloudIdentity:
    identity_id: str
    identity_type: CloudIdentityType
    display_name: str

    def __post_init__(self) -> None:
        if not self.identity_id.strip():
            raise EmptyIdentifierError("CloudIdentity.identity_id")
