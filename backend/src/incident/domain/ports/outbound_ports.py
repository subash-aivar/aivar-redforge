"""Outbound ACL ports for incident BC."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ISecurityGraphWritePort(ABC):
    @abstractmethod
    async def write_incident_node(self, tenant_id: str, payload: dict[str, Any]) -> None: ...

    @abstractmethod
    async def write_containment_node(self, tenant_id: str, payload: dict[str, Any]) -> None: ...


class IAnalyticsIncidentEventPort(ABC):
    @abstractmethod
    async def publish_classified(self, event: Any) -> None: ...

    @abstractmethod
    async def publish_closed(self, event: Any) -> None: ...


class ICommunicationNotificationPort(ABC):
    @abstractmethod
    async def notify_phase_transition(
        self, tenant_id: str, incident_id: str, phase: str, message: str
    ) -> None: ...


class IITSMNotificationPort(ABC):
    @abstractmethod
    async def create_ticket(self, tenant_id: str, incident_id: str, summary: str) -> str: ...


class IDetectionFindingEventPort(ABC):
    """Inbound translation surface for DetectionFindingEscalated."""

    @abstractmethod
    async def translate_escalation(self, payload: dict[str, Any]) -> dict[str, Any]: ...
