"""Payload domain value objects."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime

_PAYLOAD_KEY_RE = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+)+$")
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+([.-][A-Za-z0-9.-]+)?$")


@dataclass(frozen=True, slots=True)
class PayloadKey:
    value: str

    def __post_init__(self) -> None:
        if not _PAYLOAD_KEY_RE.match(self.value):
            raise ValueError(
                f"PayloadKey must be category.name (lowercase): {self.value!r}"
            )

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class PayloadVersionRef:
    value: str

    def __post_init__(self) -> None:
        if not _SEMVER_RE.match(self.value):
            raise ValueError(f"PayloadVersion must be semver: {self.value!r}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class PayloadHash:
    value: str

    def __post_init__(self) -> None:
        if len(self.value) != 64 or any(c not in "0123456789abcdef" for c in self.value):
            raise ValueError("PayloadHash must be lowercase SHA-256 hex")

    @classmethod
    def from_bytes(cls, data: bytes) -> PayloadHash:
        return cls(hashlib.sha256(data).hexdigest())

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class PayloadStorageRef:
    value: str

    def __post_init__(self) -> None:
        if not self.value:
            raise ValueError("PayloadStorageRef must not be empty")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class PayloadCapabilities:
    technique_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.technique_ids:
            raise ValueError("PayloadCapabilities must list at least one technique")


@dataclass(frozen=True, slots=True)
class ApprovedForEngagementClasses:
    classifications: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PayloadSignature:
    value: str

    def __post_init__(self) -> None:
        if not self.value:
            raise ValueError("PayloadSignature must not be empty")


@dataclass(frozen=True, slots=True)
class PayloadVersionSnapshot:
    """Immutable version record inside the Payload aggregate."""

    version: PayloadVersionRef
    payload_hash: PayloadHash
    storage_ref: PayloadStorageRef
    capabilities: PayloadCapabilities
    published_at: datetime
    vulnerability_refs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PluginHash:
    value: str

    def __post_init__(self) -> None:
        if len(self.value) != 64 or any(c not in "0123456789abcdef" for c in self.value):
            raise ValueError("PluginHash must be lowercase SHA-256 hex")


@dataclass(frozen=True, slots=True)
class PluginCapabilities:
    technique_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.technique_ids:
            raise ValueError("PluginCapabilities must list at least one technique")


@dataclass(frozen=True, slots=True)
class PluginVersion:
    value: str

    def __post_init__(self) -> None:
        if not self.value:
            raise ValueError("PluginVersion must not be empty")
