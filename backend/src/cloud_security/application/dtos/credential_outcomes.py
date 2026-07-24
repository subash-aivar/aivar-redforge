"""Immutable command-outcome DTOs for Credential Integration (M45D).
Read-once results returned synchronously to the caller — never
persisted, never carrying secret material."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cloud_security.application.dtos.credential_reference_record import (
        CredentialReferenceRecord,
    )


@dataclass(frozen=True, slots=True)
class CredentialAttached:
    record: CredentialReferenceRecord


@dataclass(frozen=True, slots=True)
class CredentialReplaced:
    record: CredentialReferenceRecord


@dataclass(frozen=True, slots=True)
class CredentialDetached:
    association_id: str
    tenant_id: str


class CredentialValidationStatus(StrEnum):
    VALID = "valid"
    INVALID = "invalid"
    # No ICredentialReferenceProvider is registered to check against —
    # this milestone never assumes validity by default.
    UNVERIFIABLE = "unverifiable"


@dataclass(frozen=True, slots=True)
class CredentialValidated:
    association_id: str
    status: CredentialValidationStatus
    reason: str = ""


class BatchCredentialStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    PARTIALLY_SUCCEEDED = "partially_succeeded"


@dataclass(frozen=True, slots=True)
class BatchCredentialFailure:
    index: int
    error_type: str
    message: str


@dataclass(frozen=True, slots=True)
class BatchCredentialResult:
    status: BatchCredentialStatus
    attached: tuple[CredentialAttached, ...] = field(default_factory=tuple)
    failures: tuple[BatchCredentialFailure, ...] = field(default_factory=tuple)

    @property
    def succeeded_count(self) -> int:
        return len(self.attached)

    @property
    def failed_count(self) -> int:
        return len(self.failures)
