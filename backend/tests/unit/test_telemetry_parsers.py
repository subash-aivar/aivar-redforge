"""Unit tests for Suricata EVE JSON and Zeek JSON parsers — M18.

All tests are deterministic, offline, and have no I/O side effects.
They verify:
  - Correct normalization of supported event types
  - Graceful skip of unsupported event types (not an error)
  - Malformed record isolation (ParseError raised, batch continues)
  - Oversized record rejection
  - Deduplication key generation
  - Private IP handling (passthrough — classifier is at ingestion layer)
  - Zero-ingestion for empty batches
"""

from __future__ import annotations

import json

import pytest

from redforge.infrastructure.telemetry.parsers import suricata_eve, zeek_json


# ── Suricata EVE JSON ──────────────────────────────────────────────────────


def _alert(extra: dict | None = None) -> str:
    base: dict = {
        "timestamp": "2024-01-15T10:00:00.000+0000",
        "flow_id": 123456789,
        "event_type": "alert",
        "src_ip": "1.2.3.4",
        "dest_ip": "10.0.0.1",
        "src_port": 44321,
        "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "action": "blocked",
            "severity": 1,
            "signature": "ET MALWARE Ransomware Beacon",
            "signature_id": 2034567,
        },
    }
    if extra:
        base.update(extra)
    return json.dumps(base)


class TestSuricataAlert:
    def test_parses_basic_alert(self) -> None:
        ev, sk, err = suricata_eve.parse_batch([_alert()])
        assert len(ev) == 1
        assert sk == 0
        assert err == 0
        e = ev[0]
        assert e.event_type == "suricata_alert"
        assert e.format == "suricata_eve"
        assert e.src_ip == "1.2.3.4"
        assert e.dst_ip == "10.0.0.1"
        assert e.src_port == 44321
        assert e.dst_port == 443
        assert e.protocol == "tcp"
        assert e.action == "blocked"
        assert e.severity == "critical"  # severity=1 → critical
        assert e.signature == "ET MALWARE Ransomware Beacon"
        assert e.signature_id == "2034567"

    def test_severity_mapping(self) -> None:
        for sev_in, sev_out in [(1, "critical"), (2, "high"), (3, "medium"), (4, "low")]:
            a = json.loads(_alert())
            a["alert"]["severity"] = sev_in
            ev, _, _ = suricata_eve.parse_batch([json.dumps(a)])
            assert ev[0].severity == sev_out, f"severity {sev_in} → {ev[0].severity}"

    def test_source_event_id_uses_flow_id(self) -> None:
        ev, _, _ = suricata_eve.parse_batch([_alert()])
        assert ev[0].source_event_id.startswith("suricata_flow_123456789")

    def test_source_event_id_fallback_to_hash(self) -> None:
        a = json.loads(_alert())
        del a["flow_id"]
        ev, _, _ = suricata_eve.parse_batch([json.dumps(a)])
        assert ev[0].source_event_id.startswith("suricata_hash_")

    def test_dedup_key_stable(self) -> None:
        a = json.loads(_alert())
        del a["flow_id"]
        raw = json.dumps(a)
        ev1, _, _ = suricata_eve.parse_batch([raw])
        ev2, _, _ = suricata_eve.parse_batch([raw])
        assert ev1[0].source_event_id == ev2[0].source_event_id


class TestSuricataFlow:
    def test_parses_flow_with_bytes(self) -> None:
        rec = json.dumps({
            "timestamp": "2024-01-15T10:01:00.000+0000",
            "flow_id": 999,
            "event_type": "flow",
            "src_ip": "192.168.1.5",
            "dest_ip": "8.8.8.8",
            "src_port": 12345,
            "dest_port": 53,
            "proto": "UDP",
            "flow": {
                "bytes_toclient": 1024,
                "bytes_toserver": 256,
                "pkts_toclient": 10,
                "pkts_toserver": 5,
                "state": "established",
            },
        })
        ev, _, _ = suricata_eve.parse_batch([rec])
        assert len(ev) == 1
        e = ev[0]
        assert e.event_type == "suricata_flow"
        assert e.bytes_in == 1024
        assert e.bytes_out == 256
        assert e.packets_in == 10
        assert e.packets_out == 5
        assert e.action == "established"


class TestSuricataUnsupported:
    def test_unsupported_type_skipped_not_errored(self) -> None:
        for etype in ("fileinfo", "anomaly", "stats", "drop", "wake_up", "smtp"):
            rec = json.dumps({
                "timestamp": "2024-01-15T10:00:00.000+0000",
                "event_type": etype,
                "src_ip": "1.2.3.4",
                "dest_ip": "5.6.7.8",
            })
            ev, sk, err = suricata_eve.parse_batch([rec])
            assert len(ev) == 0, f"{etype} should be skipped"
            assert sk == 1, f"{etype} should increment skipped"
            assert err == 0, f"{etype} should not increment errors"


class TestSuricataMalformed:
    def test_empty_line_skipped(self) -> None:
        ev, sk, err = suricata_eve.parse_batch(["", "  "])
        assert len(ev) == 0
        assert sk == 2
        assert err == 0

    def test_invalid_json_counted_as_error(self) -> None:
        ev, sk, err = suricata_eve.parse_batch(["not json"])
        assert err == 1
        assert len(ev) == 0

    def test_missing_event_type_is_error(self) -> None:
        ev, sk, err = suricata_eve.parse_batch(['{"src_ip":"1.2.3.4"}'])
        assert err == 1

    def test_oversized_record_is_error(self) -> None:
        big = "x" * (65 * 1024)
        ev, sk, err = suricata_eve.parse_batch([big])
        assert err == 1

    def test_batch_continues_after_malformed(self) -> None:
        records = ["not json", _alert(), "also not json", _alert()]
        ev, sk, err = suricata_eve.parse_batch(records)
        assert len(ev) == 2
        assert err == 2

    def test_max_records_enforced(self) -> None:
        records = [_alert()] * 2000
        ev, _, _ = suricata_eve.parse_batch(records, max_records=5)
        assert len(ev) == 5


class TestSuricataDns:
    def test_dns_query_stored_without_rdata(self) -> None:
        rec = json.dumps({
            "timestamp": "2024-01-15T10:02:00.000+0000",
            "event_type": "dns",
            "src_ip": "192.168.1.10",
            "dest_ip": "8.8.8.8",
            "src_port": 54321,
            "dest_port": 53,
            "proto": "UDP",
            "dns": {
                "type": "query",
                "rrname": "example.com",
                "rrtype": "A",
                "answers": [{"rrname": "example.com", "rdata": "1.2.3.4"}],
            },
        })
        ev, _, _ = suricata_eve.parse_batch([rec])
        assert len(ev) == 1
        # Answers/rdata should NOT appear in signature
        assert "rdata" not in (ev[0].signature or "")
        assert "answers" not in (ev[0].signature or "")
        assert "example.com" in (ev[0].signature or "")


# ── Zeek JSON ─────────────────────────────────────────────────────────────


def _zeek_conn(extra: dict | None = None) -> str:
    base: dict = {
        "_path": "conn",
        "ts": 1705312800.0,
        "uid": "CZeekUID001",
        "id.orig_h": "1.2.3.4",
        "id.resp_h": "5.6.7.8",
        "id.orig_p": 12345,
        "id.resp_p": 80,
        "proto": "tcp",
        "conn_state": "SF",
        "orig_bytes": 2048,
        "resp_bytes": 8192,
        "orig_pkts": 15,
        "resp_pkts": 30,
    }
    if extra:
        base.update(extra)
    return json.dumps(base)


class TestZeekConn:
    def test_parses_basic_conn(self) -> None:
        ev, sk, err = zeek_json.parse_batch([_zeek_conn()])
        assert len(ev) == 1
        e = ev[0]
        assert e.format == "zeek_json"
        assert e.event_type == "zeek_conn"
        assert e.src_ip == "1.2.3.4"
        assert e.dst_ip == "5.6.7.8"
        assert e.src_port == 12345
        assert e.dst_port == 80
        assert e.protocol == "tcp"
        assert e.action == "SF"
        assert e.bytes_out == 2048
        assert e.bytes_in == 8192
        assert e.packets_out == 15
        assert e.packets_in == 30

    def test_uid_used_as_source_event_id(self) -> None:
        ev, _, _ = zeek_json.parse_batch([_zeek_conn()])
        assert ev[0].source_event_id == "zeek_conn_CZeekUID001"

    def test_no_uid_falls_back_to_hash(self) -> None:
        c = json.loads(_zeek_conn())
        del c["uid"]
        ev, _, _ = zeek_json.parse_batch([json.dumps(c)])
        assert ev[0].source_event_id.startswith("zeek_hash_")

    def test_log_type_hint_overrides_path(self) -> None:
        c = json.loads(_zeek_conn())
        del c["_path"]
        ev, _, _ = zeek_json.parse_batch([json.dumps(c)], log_type="conn")
        assert len(ev) == 1


class TestZeekNotice:
    def test_parses_notice(self) -> None:
        rec = json.dumps({
            "_path": "notice",
            "ts": 1705312900.0,
            "uid": "CNotice001",
            "id.orig_h": "10.0.0.5",
            "id.resp_h": "1.2.3.4",
            "note": "Scan::Port_Scan",
            "msg": "192.168.1.5 scanned at least 15 unique ports of 1.2.3.4",
        })
        ev, _, _ = zeek_json.parse_batch([rec])
        assert len(ev) == 1
        assert ev[0].event_type == "zeek_notice"
        assert ev[0].signature_id == "Scan::Port_Scan"
        assert ev[0].action == "notice"


class TestZeekUnsupported:
    def test_unsupported_types_skipped(self) -> None:
        for ltype in ("http", "files", "x509", "weird", "smtp", "ftp"):
            rec = json.dumps({"_path": ltype, "ts": 1705312800.0})
            ev, sk, err = zeek_json.parse_batch([rec])
            assert len(ev) == 0
            assert sk == 1
            assert err == 0

    def test_missing_path_and_no_hint_skipped(self) -> None:
        rec = json.dumps({"ts": 1705312800.0, "uid": "CXX"})
        ev, sk, err = zeek_json.parse_batch([rec])
        assert sk == 1

    def test_unknown_hint_skipped(self) -> None:
        rec = json.dumps({"ts": 1705312800.0, "uid": "CXX"})
        ev, sk, err = zeek_json.parse_batch([rec], log_type="weird")
        assert sk == 1


class TestZeekMalformed:
    def test_invalid_json_is_error(self) -> None:
        ev, sk, err = zeek_json.parse_batch(["not json"])
        assert err == 1
        assert len(ev) == 0

    def test_missing_ts_is_error(self) -> None:
        rec = json.dumps({"_path": "conn", "uid": "X"})
        ev, sk, err = zeek_json.parse_batch([rec])
        assert err == 1

    def test_batch_continues_after_malformed(self) -> None:
        records = ["not json", _zeek_conn(), "bad", _zeek_conn()]
        ev, sk, err = zeek_json.parse_batch(records)
        assert len(ev) == 2
        assert err == 2

    def test_oversized_record_is_error(self) -> None:
        big = "z" * (65 * 1024)
        ev, sk, err = zeek_json.parse_batch([big])
        assert err == 1


class TestZeekDns:
    def test_dns_query_omits_answers(self) -> None:
        rec = json.dumps({
            "_path": "dns",
            "ts": 1705312800.0,
            "uid": "CDns001",
            "id.orig_h": "192.168.1.5",
            "id.resp_h": "8.8.8.8",
            "id.orig_p": 54321,
            "id.resp_p": 53,
            "proto": "udp",
            "query": "malware.example.com",
            "qtype_name": "A",
            "answers": ["1.2.3.4"],
        })
        ev, _, _ = zeek_json.parse_batch([rec])
        assert len(ev) == 1
        sig = ev[0].signature or ""
        assert "1.2.3.4" not in sig
        assert "malware.example.com" in sig


class TestPrivateIPPassthrough:
    """Private IPs are parsed normally — the no-egress gate is at ingestion,
    not at the parser. Parsers must not silently drop private-IP records."""

    def test_private_src_ip_parsed(self) -> None:
        rec = _alert({"src_ip": "192.168.1.5", "dest_ip": "10.0.0.1"})
        ev, _, _ = suricata_eve.parse_batch([rec])
        assert len(ev) == 1
        assert ev[0].src_ip == "192.168.1.5"

    def test_private_ips_in_zeek_conn(self) -> None:
        c = json.loads(_zeek_conn({"id.orig_h": "10.0.0.5", "id.resp_h": "172.16.0.1"}))
        ev, _, _ = zeek_json.parse_batch([json.dumps(c)])
        assert len(ev) == 1
        assert ev[0].src_ip == "10.0.0.5"


class TestBatchSizeLimit:
    def test_zeek_batch_respects_max_records(self) -> None:
        records = [_zeek_conn()] * 2000
        ev, _, _ = zeek_json.parse_batch(records, max_records=10)
        assert len(ev) == 10
