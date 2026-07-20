"""Domain events for DetectionException aggregate."""

from __future__ import annotations

from dataclasses import dataclass

from detection.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionExceptionRequested(BaseDomainEvent):
    exception_type: str
    requester: str


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionExceptionApproved(BaseDomainEvent):
    approver: str


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionExceptionRejected(BaseDomainEvent):
    rejector: str
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionExceptionExpired(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionExceptionRevoked(BaseDomainEvent):
    revoker: str
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionExceptionRenewed(BaseDomainEvent):
    renewed_until: str
    renewer: str
