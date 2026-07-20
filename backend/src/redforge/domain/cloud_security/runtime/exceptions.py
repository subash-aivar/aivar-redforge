"""Runtime visibility domain exceptions."""

from __future__ import annotations

from redforge.core.exceptions import NotFoundError, ValidationError


class InvalidRuntimeArgumentError(ValidationError):
    def __init__(self, field: str, message: str) -> None:
        self.field = field
        super().__init__(message=f"{field}: {message}", details={field: message})


class RuntimeEventNotFoundError(NotFoundError):
    def __init__(self, event_id: str) -> None:
        super().__init__(resource="CloudRuntimeEvent", identifier=event_id)
        self.event_id = event_id


class RuntimeArtifactNotFoundError(NotFoundError):
    def __init__(self, artifact_id: str) -> None:
        super().__init__(resource="RuntimeArtifactRecord", identifier=artifact_id)
        self.artifact_id = artifact_id
