"""Entities for runtime visibility."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class RuntimeMetadata:
    provider_event_id: str
    event_name: str
    region: str = ""
    user_agent: str = ""
    request_id: str = ""
    attributes: tuple[tuple[str, str], ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "provider_event_id": self.provider_event_id,
            "event_name": self.event_name,
            "region": self.region,
            "user_agent": self.user_agent,
            "request_id": self.request_id,
            "attributes": dict(self.attributes),
        }

    @classmethod
    def from_dict(cls, data: dict[str, object] | None) -> RuntimeMetadata:
        if not data:
            return cls(provider_event_id="", event_name="")
        attrs_raw = data.get("attributes") or {}
        attrs: list[tuple[str, str]] = []
        if isinstance(attrs_raw, dict):
            attrs = [(str(k), str(v)) for k, v in attrs_raw.items()]
        return cls(
            provider_event_id=str(data.get("provider_event_id", "")),
            event_name=str(data.get("event_name", "")),
            region=str(data.get("region", "")),
            user_agent=str(data.get("user_agent", "")),
            request_id=str(data.get("request_id", "")),
            attributes=tuple(attrs),
        )


def _as_int(value: object, *, default: int = 0) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str) and value.strip():
        return int(value)
    return default


@dataclass(frozen=True, slots=True)
class RuntimeArtifact:
    artifact_id: str
    artifact_type: str
    name: str
    digest: str = ""
    path: str = ""
    size_bytes: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_id": self.artifact_id,
            "artifact_type": self.artifact_type,
            "name": self.name,
            "digest": self.digest,
            "path": self.path,
            "size_bytes": self.size_bytes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> RuntimeArtifact:
        return cls(
            artifact_id=str(data.get("artifact_id") or uuid4()),
            artifact_type=str(data.get("artifact_type", "unknown")),
            name=str(data.get("name", "")),
            digest=str(data.get("digest", "")),
            path=str(data.get("path", "")),
            size_bytes=_as_int(data.get("size_bytes", 0) or 0),
        )


@dataclass(frozen=True, slots=True)
class RuntimeEvidence:
    evidence_id: str
    summary: str
    details: dict[str, Any]

    def to_dict(self) -> dict[str, object]:
        return {
            "evidence_id": self.evidence_id,
            "summary": self.summary,
            "details": dict(self.details),
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> RuntimeEvidence:
        details = data.get("details") or {}
        return cls(
            evidence_id=str(data.get("evidence_id") or uuid4()),
            summary=str(data.get("summary", "")),
            details=dict(details) if isinstance(details, dict) else {},
        )


@dataclass(frozen=True, slots=True)
class RuntimeCorrelationReference:
    target_kind: str
    target_id: str
    relationship: str = "related_to"

    def to_dict(self) -> dict[str, object]:
        return {
            "target_kind": self.target_kind,
            "target_id": self.target_id,
            "relationship": self.relationship,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> RuntimeCorrelationReference:
        return cls(
            target_kind=str(data.get("target_kind", "")),
            target_id=str(data.get("target_id", "")),
            relationship=str(data.get("relationship", "related_to")),
        )
