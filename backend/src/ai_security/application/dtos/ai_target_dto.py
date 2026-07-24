"""AiTargetDTO — the read-only projection of an `AiTarget` returned
by the application layer (M47A). Never mutated; rebuilt fresh from the
aggregate each time."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class AiTargetDTO:
    target_id: str
    tenant_id: str
    name: str
    target_type: str
    registered_at: datetime
