"""Rotation context value object."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from credential_vault.domain.value_objects.audit_types import RotationTrigger
    from credential_vault.domain.value_objects.identifiers import (
        PrincipalId,
        RotationPolicyId,
        VersionId,
    )


@dataclass(frozen=True, slots=True)
class RotationContext:
    """Captures why and how a rotation was initiated."""

    trigger: RotationTrigger
    initiated_by: PrincipalId
    previous_version_id: VersionId
    policy_id: RotationPolicyId | None
    notes: str | None

    def __post_init__(self) -> None:
        if self.notes is not None and len(self.notes) > 1024:
            raise ValueError("notes max 1024 chars")
