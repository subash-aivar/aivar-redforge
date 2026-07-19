"""Credential name value object."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CredentialName:
    """Unique within tenant. Immutable after creation."""

    value: str

    def __post_init__(self) -> None:
        stripped = self.value.strip()
        if not stripped:
            raise ValueError("name empty")
        if len(stripped) > 256:
            raise ValueError("name max 256 chars")
        if not re.fullmatch(r"[\w\-\./ ]+", stripped):
            raise ValueError("name contains invalid characters")
        object.__setattr__(self, "value", stripped)
