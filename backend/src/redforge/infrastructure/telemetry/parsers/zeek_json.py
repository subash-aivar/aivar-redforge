"""Zeek (formerly Bro) JSON log parser — M18 customer-owned telemetry.

Parses Zeek JSON-format logs (produced via the json-logs policy or the
zeek-json-logs package). Supports a curated set of log types that carry
genuine network security signal.

Supported:
  conn      — completed TCP/UDP/ICMP connections with byte/packet counts
  notice    — Zeek notice framework events (IDS-style alerts)
  ssl       — TLS/SSL connection metadata (version, SNI, subject, issuer)
  dns       — DNS queries (query name and type only; answers excluded)

Unsupported (never parsed, explicitly declared):
  http, files, x509, weird, dpd, smtp, ssh, ftp, smb, kerberos, dce_rpc,
  ntlm, pe, rdp, rfb, sip, snmp, syslog, tunnel, intel, signatures,
  capture_loss, traceroute, reporter — either privacy-sensitive beyond
  the allowlisted fields, carry no additional signal above conn/notice,
  or have ambiguous semantics in multi-sensor environments.

Zeek UID is preserved as the source event ID where present.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

_MAX_RECORD_BYTES = 64 * 1024
_SUPPORTED_TYPES = frozenset({"conn", "notice", "ssl", "dns"})


class ParseError(Exception):
    pass


@dataclass(slots=True)
class ParsedEvent:
    format: str  # always "zeek_json"
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


def parse_record(raw: str | bytes, log_type: str | None = None) -> ParsedEvent | None:
    """Parse one Zeek JSON record. log_type may be supplied explicitly (e.g.
    from the filename) or inferred from the `_path` field in the record itself.
    Returns None for unsupported types; raises ParseError for malformed records."""
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
        raise ParseError("expected JSON object")

    # Determine log type: explicit argument > _path field > skip
    ltype = log_type or _str(obj.get("_path")) or _str(obj.get("log_type"))
    if not ltype or ltype not in _SUPPORTED_TYPES:
        return None

    ts_raw = obj.get("ts")
    event_ts = _parse_ts(ts_raw)

    uid = _str(obj.get("uid"))
    src_ip = _safe_ip(_str(obj.get("id.orig_h") or obj.get("orig_h")))
    dst_ip = _safe_ip(_str(obj.get("id.resp_h") or obj.get("resp_h")))
    src_port = _port(obj.get("id.orig_p") or obj.get("orig_p"))
    dst_port = _port(obj.get("id.resp_p") or obj.get("resp_p"))
    proto = _str(obj.get("proto"))

    action: str | None = None
    severity: str | None = None
    signature: str | None = None
    signature_id: str | None = None
    bytes_in: int | None = None
    bytes_out: int | None = None
    packets_in: int | None = None
    packets_out: int | None = None

    if ltype == "conn":
        conn_state = _str(obj.get("conn_state"))
        action = conn_state
        bytes_in = _bigint(obj.get("resp_bytes") or obj.get("resp_ip_bytes"))
        bytes_out = _bigint(obj.get("orig_bytes") or obj.get("orig_ip_bytes"))
        packets_in = _bigint(obj.get("resp_pkts"))
        packets_out = _bigint(obj.get("orig_pkts"))
        service = _str(obj.get("service"))
        if service:
            signature = f"service:{service}"

    elif ltype == "notice":
        note = _str(obj.get("note"))
        msg = _str(obj.get("msg"))
        signature = note or msg
        signature_id = note
        action = "notice"
        # Some notice types carry severity via sub (sub-message)
        # We don't fabricate a severity — leave None unless explicitly present
        sub = _str(obj.get("sub"))
        if sub and "critical" in sub.lower():
            severity = "critical"
        elif sub and "high" in sub.lower():
            severity = "high"

    elif ltype == "ssl":
        sni = _str(obj.get("server_name"))
        version = _str(obj.get("version"))
        subject = _str(obj.get("subject"))
        parts = [p for p in [version, sni, subject] if p]
        signature = " ".join(parts) if parts else None
        established = obj.get("established")
        action = "established" if established else "attempted"

    elif ltype == "dns":
        query = _str(obj.get("query"))
        qtype = _str(obj.get("qtype_name") or obj.get("qtype"))
        if query:
            signature = f"DNS {qtype or ''} {query}".strip()
        action = "query"

    source_event_id: str
    if uid:
        source_event_id = f"zeek_{ltype}_{uid}"
    else:
        h = hashlib.sha256(
            f"{ltype}|{ts_raw}|{src_ip}|{dst_ip}|{src_port}|{dst_port}|{signature}".encode()
        ).hexdigest()[:32]
        source_event_id = f"zeek_hash_{h}"

    return ParsedEvent(
        format="zeek_json",
        event_type=f"zeek_{ltype}",
        source_event_id=source_event_id,
        event_ts=event_ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
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
    lines: Sequence[str | bytes],
    log_type: str | None = None,
    max_records: int = 1000,
) -> tuple[list[ParsedEvent], int, int]:
    events: list[ParsedEvent] = []
    skipped = 0
    errors = 0
    for line in lines[:max_records]:
        stripped = line.strip()
        if not stripped:
            skipped += 1
            continue
        try:
            result = parse_record(stripped, log_type=log_type)
        except ParseError:
            errors += 1
            continue
        if result is None:
            skipped += 1
        else:
            events.append(result)
    return events, skipped, errors


# ── Private helpers ────────────────────────────────────────────────────────


def _parse_ts(ts_raw: Any) -> datetime:
    if ts_raw is None:
        raise ParseError("missing ts field")
    # Zeek timestamp is a float (Unix epoch) or ISO string
    try:
        return datetime.fromtimestamp(float(ts_raw), tz=UTC)
    except (TypeError, ValueError, OverflowError, OSError):
        pass
    # Try ISO string fallback
    ts = str(ts_raw)
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(ts, fmt)
            return dt.astimezone(UTC) if dt.tzinfo else dt.replace(tzinfo=UTC)
        except ValueError:
            continue
    raise ParseError(f"unparseable ts: {ts_raw!r}")


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
