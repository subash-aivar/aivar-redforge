"""Credential and version state enums."""

from __future__ import annotations

from enum import StrEnum


class CredentialState(StrEnum):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    ROTATING = "ROTATING"
    DISABLED = "DISABLED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    DELETED = "DELETED"


class VersionState(StrEnum):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    SUPERSEDED = "SUPERSEDED"
    REVOKED = "REVOKED"
