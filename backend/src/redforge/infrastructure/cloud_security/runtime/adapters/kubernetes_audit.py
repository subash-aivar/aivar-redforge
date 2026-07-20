"""Kubernetes audit-log-like raw dict adapter (no client-go / kubernetes SDK)."""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from datetime import UTC, datetime
from typing import Any

from redforge.domain.cloud_security.ports import RawRuntimeEvent


def normalize_kubernetes_audit(record: dict[str, Any]) -> dict[str, Any]:
    user = record.get("user") or {}
    if not isinstance(user, dict):
        user = {}
    object_ref = record.get("objectRef") or {}
    if not isinstance(object_ref, dict):
        object_ref = {}
    source_ips = record.get("sourceIPs") or []
    source_ip = str(source_ips[0]) if isinstance(source_ips, list) and source_ips else ""

    event_time_raw = (
        record.get("requestReceivedTimestamp")
        or record.get("stageTimestamp")
        or record.get("event_time")
    )
    if isinstance(event_time_raw, datetime):
        event_time = event_time_raw
    elif isinstance(event_time_raw, str) and event_time_raw:
        event_time = datetime.fromisoformat(event_time_raw.replace("Z", "+00:00"))
    else:
        event_time = datetime.now(UTC)

    event_id = str(record.get("auditID") or record.get("event_id") or "")
    verb = str(record.get("verb") or "")
    resource = str(object_ref.get("resource") or "")
    name = str(object_ref.get("name") or "")
    namespace = str(object_ref.get("namespace") or "")
    event_name = f"{verb}:{resource}" if verb or resource else str(record.get("event_name") or "")
    return {
        "provider": "kubernetes",
        "source": "KUBERNETES_AUDIT",
        "event_id": event_id,
        "event_time": event_time.isoformat(),
        "event_name": event_name,
        "region": "",
        "source_ip": source_ip,
        "user_agent": str(record.get("userAgent") or ""),
        "identity": {
            "principal_id": str(user.get("uid") or user.get("username") or ""),
            "principal_type": "ServiceAccount"
            if str(user.get("username") or "").startswith("system:serviceaccount:")
            else "User",
            "principal_name": str(user.get("username") or ""),
            "account_id": "",
        },
        "container": {
            "namespace": namespace,
            "pod_name": name if resource == "pods" else "",
            "workload_name": name,
            "container_id": "",
            "image": "",
        },
        "response_code": int((record.get("responseStatus") or {}).get("code") or 0)
        if isinstance(record.get("responseStatus"), dict)
        else 0,
        "raw": dict(record),
    }


class KubernetesAuditAdapter:
    def __init__(self, payloads: Sequence[dict[str, Any]] | None = None) -> None:
        self._payloads = list(payloads or [])

    def seed(self, *payloads: dict[str, Any]) -> None:
        self._payloads.extend(payloads)

    def clear(self) -> None:
        self._payloads.clear()

    async def stream_events(self) -> AsyncIterator[dict[str, Any] | RawRuntimeEvent]:
        for payload in self._payloads:
            items = payload.get("items")
            records = items if isinstance(items, list) else [payload]
            for record in records:
                if not isinstance(record, dict):
                    continue
                normalized = normalize_kubernetes_audit(record)
                yield RawRuntimeEvent(
                    event_id=str(normalized.get("event_id") or ""),
                    event_time=datetime.fromisoformat(
                        str(normalized["event_time"]).replace("Z", "+00:00")
                    ),
                    source="KUBERNETES_AUDIT",
                    payload=normalized,
                )
