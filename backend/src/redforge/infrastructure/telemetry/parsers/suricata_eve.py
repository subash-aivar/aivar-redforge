"""Suricata EVE JSON parser — M18 customer-owned telemetry ingestion.

Parses Suricata's EVE (Extensible Vanguard Events) JSON log format.
Only event types that carry genuinely useful security signals are
normalised; unsupported types are skipped with an explicit reason.

Supported:
  alert     — IDS/IPS signature alerts (the primary use case)
  flow      — completed TCP/UDP flow records with traffic counts
  netflow   — NetFlow-like records with byte/packet counts
  dns       — DNS queries/responses (privacy-aware: only query name and
              type; answer rdata is intentionally excluded)
  http      — HTTP metadata (method, status, host, url path only;
              request/response bodies excluded)
  tls       — TLS connection metadata (version, SNI, JA3 only)

Unsupported (never parsed):
  fileinfo, anomaly, smtp, ssh, ftp, smb, modbus, dnp3, krb5, tftp,
  pkthdr, stats, drop, wake_up — either irrelevant to network security
  correlation, privacy-sensitive beyond what is allowlisted, or
  carry no additional signal beyond what alert/flow already provide.

Malformed records never crash ingestion — ParseError is raised per
record and the caller is expected to skip+count them.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

# Maximum raw record size we will attempt to parse.
_MAX_RECORD_BYTES = 64 * 1024  # 64 KB

# Event types we explicitly support
_SUPPORTED_TYPES = frozenset(
    {"alert", "flow", "netflow", "dns", "http", "tls"}
)

# DNS rdata fields we explicitly exclude for privacy
_DNS_EXCLUDED_FIELDS = frozenset({"answers", "grouped", "authorities"})


class ParseError(Exception):
    """Raised when a single record cannot be parsed. Never fatal to the
    batch — callers should catch, count, and continue."""


@dataclass(slots=True)
class ParsedEvent:
    """Normalised security event from one raw Suricata EVE JSON record."""

    format: str  # always "suricata_eve"
    event_type: str
    source_event_id: str
    event_ts: datetime
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: str | None
    action: str | None
    severity: str | None
    signature: str | None
    signature_id: str | None
    bytes_in: int | None
    bytes_out: int | None
    packets_in: int | None
    packets_out: int | None


def parse_record(raw: str | bytes) -> ParsedEvent | None:
    """Parse one EVE JSON record. Returns None for unsupported event
    types (not an error — just skip). Raises ParseError for malformed
    records.

    This function is deterministic and has no I/O side effects — safe
    to call in tight loops and in tests without any infrastructure."""
    if isinstance(raw, (bytes, bytearray)):
        if len(raw) > _MAX_RECORD_BYTES:
            raise ParseError(f"record too large: {len(raw)} bytes")
        try:
            raw = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as e:
            raise ParseError(f"invalid UTF-8: {e}") from e
    elif len(raw) > _MAX_RECORD_BYTES:
        raise ParseError(f"record too large: {len(raw)} chars")

    try:
        obj: dict[str, Any] = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ParseError(f"invalid JSON: {e}") from e

    if not isinstance(obj, dict):
        raise ParseError("expected JSON object, got array or scalar")

    event_type = obj.get("event_type", "")
    if not isinstance(event_type, str) or not event_type:
        raise ParseError("missing or non-string event_type")

    if event_type not in _SUPPORTED_TYPES:
        return None  # explicitly unsupported — skip silently

    ts_raw = obj.get("timestamp", "")
    event_ts = _parse_timestamp(ts_raw)

    src_ip = _str(obj.get("src_ip"))
    dst_ip = _str(obj.get("dest_ip"))
    src_port = _port(obj.get("src_port"))
    dst_port = _port(obj.get("dest_port"))
    proto = _str(obj.get("proto"))
    flow_id = obj.get("flow_id")

    # Event-type-specific extraction
    action: str | None = None
    severity: str | None = None
    signature: str | None = None
    signature_id: str | None = None
    bytes_in: int | None = None
    bytes_out: int | None = None
    packets_in: int | None = None
    packets_out: int | None = None

    if event_type == "alert":
        alert = obj.get("alert", {})
        if not isinstance(alert, dict):
            raise ParseError("alert.alert is not a dict")
        action = _str(alert.get("action"))
        sev_raw = alert.get("severity")
        severity = _suricata_severity(sev_raw) if sev_raw is not None else None
        signature = _str(alert.get("signature"))
        sid = alert.get("signature_id")
        signature_id = str(int(sid)) if isinstance(sid, (int, float)) else _str(sid)

    elif event_type in ("flow", "netflow"):
        flow = obj.get(event_type, {})
        if isinstance(flow, dict):
            bytes_in = _bigint(flow.get("bytes_toclient") or flow.get("bytes_to_client"))
            bytes_out = _bigint(flow.get("bytes_toserver") or flow.get("bytes_to_server"))
            packets_in = _bigint(flow.get("pkts_toclient") or flow.get("pkts_to_client"))
            packets_out = _bigint(flow.get("pkts_toserver") or flow.get("pkts_to_server"))
            state = _str(flow.get("state"))
            if state:
                action = state.lower()

    elif event_type == "dns":
        dns = obj.get("dns", {})
        if isinstance(dns, dict):
            # Restrict to allowlisted fields — no answer rdata
            qtype = _str(dns.get("type") or dns.get("rrtype"))
            rrname = _str(dns.get("rrname"))
            if rrname:
                # Store only query name + type in the signature field
                signature = f"DNS {qtype or ''} {rrname}".strip()

    elif event_type == "http":
        http = obj.get("http", {})
        if isinstance(http, dict):
            method = _str(http.get("http_method"))
            status = http.get("status")
            host = _str(http.get("hostname"))
            url = _str(http.get("url"))
            # Compose a safe summary; never include body content
            parts = [p for p in [method, host, url, str(status) if status else None] if p]
            signature = " ".join(parts) if parts else None

    elif event_type == "tls":
        tls = obj.get("tls", {})
        if isinstance(tls, dict):
            sni = _str(tls.get("sni"))
            version = _str(tls.get("version"))
            ja3_raw = tls.get("ja3")
            ja3 = _str(ja3_raw.get("hash") if isinstance(ja3_raw, dict) else None)
            parts = [p for p in [version, sni, f"ja3={ja3}" if ja3 else None] if p]
            signature = " ".join(parts) if parts else None

    # Source event ID: use flow_id if present, else deterministic hash of key fields
    if flow_id is not None:
        source_event_id = f"suricata_flow_{flow_id}_{event_type}"
    else:
        h = hashlib.sha256(
            f"{event_type}|{ts_raw}|{src_ip}|{dst_ip}|{src_port}|{dst_port}|{signature_id}".encode()
        ).hexdigest()[:32]
        source_event_id = f"suricata_hash_{h}"

    return ParsedEvent(
        format="suricata_eve",
        event_type=f"suricata_{event_type}",
        source_event_id=source_event_id,
        event_ts=event_ts,
        src_ip=_safe_ip(src_ip),
        dst_ip=_safe_ip(dst_ip),
        src_port=src_port,
        dst_port=dst_port,
        protocol=proto.lower() if proto else None,
        action=action,
        severity=severity,
        signature=signature,
        signature_id=signature_id,
        bytes_in=bytes_in,
        bytes_out=bytes_out,
        packets_in=packets_in,
        packets_out=packets_out,
    )


def parse_batch(
    lines: Sequence[str | bytes], max_records: int = 1000
) -> tuple[list[ParsedEvent], int, int]:
    """Parse up to max_records EVE JSON lines. Returns (events, skipped_count,
    error_count). Malformed records increment error_count; unsupported event
    types increment skipped_count. Neither stops the batch."""
    events: list[ParsedEvent] = []
    skipped = 0
    errors = 0
    for line in lines[:max_records]:
        line_stripped = line.strip()
        if not line_stripped:
            skipped += 1
            continue
        try:
            result = parse_record(line_stripped)
        except ParseError:
            errors += 1
            continue
        if result is None:
            skipped += 1
        else:
            events.append(result)
    return events, skipped, errors


# ── Private helpers ────────────────────────────────────────────────────────


def _parse_timestamp(ts_raw: Any) -> datetime:
    if not ts_raw:
        raise ParseError("missing timestamp")
    ts = str(ts_raw)
    # Suricata timestamps: "2023-01-15T10:00:00.123456+0000" or ISO 8601 variants
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            dt = datetime.strptime(ts, fmt)
            return dt.astimezone(UTC) if dt.tzinfo else dt.replace(tzinfo=UTC)
        except ValueError:
            continue
    raise ParseError(f"unparseable timestamp: {ts!r}")


def _str(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s if s else None


def _port(v: Any) -> int | None:
    if v is None:
        return None
    try:
        p = int(v)
        return p if 0 <= p <= 65535 else None
    except (TypeError, ValueError):
        return None


def _bigint(v: Any) -> int | None:
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _safe_ip(ip: str | None) -> str | None:
    if not ip:
        return None
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        return None


def _suricata_severity(v: Any) -> str:
    """Suricata numeric severity 1-4 → canonical severity string."""
    try:
        n = int(v)
    except (TypeError, ValueError):
        return "info"
    return {1: "critical", 2: "high", 3: "medium", 4: "low"}.get(n, "info")
