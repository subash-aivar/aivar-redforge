"""Direct unit tests for `application/network_security/orchestrator.py`'s
`_detect_drift()`/`_compute_reactivated_keys()` and
`domain/network_security/entity.py`'s `NetworkStateSnapshot.build()` —
exercising drift scenarios that are real but were not otherwise directly
proven end-to-end (TLS certificate rotation; condition reactivation;
deterministic snapshot ordering independent of input order).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from redforge.application.network_security.orchestrator import (
    _compute_reactivated_keys,
    _detect_drift,
)
from redforge.domain.network_security.entity import (
    NetworkServiceSnapshotEntry,
    NetworkStateSnapshot,
)
from redforge.shared.identifiers import EntityId

_ORG = EntityId.generate()
_POLICY = EntityId.generate()


def _snapshot(
    resolved_ips: list[str], reachable_ports: list[int],
    services: list[NetworkServiceSnapshotEntry] | None = None,
    active_condition_keys: list[str] | None = None,
) -> NetworkStateSnapshot:
    return NetworkStateSnapshot.build(
        organization_id=_ORG, policy_id=_POLICY, run_id=EntityId.generate(),
        resolved_ips=resolved_ips, reachable_ports=reachable_ports,
        services=services or [], active_condition_keys=active_condition_keys or [],
        active_correlation_keys=[],
    )


class TestSnapshotDeterministicOrdering:
    def test_snapshot_is_insensitive_to_input_order(self) -> None:
        a = _snapshot(["10.0.0.2", "10.0.0.1"], [443, 22])
        b = _snapshot(["10.0.0.1", "10.0.0.2"], [22, 443])
        assert a.content_fingerprint == b.content_fingerprint
        assert a.resolved_ips == b.resolved_ips == ("10.0.0.1", "10.0.0.2")
        assert a.reachable_ports == b.reachable_ports == (22, 443)

    def test_snapshot_services_ordered_by_port_regardless_of_input_order(self) -> None:
        svc_443 = NetworkServiceSnapshotEntry(443, "tls", None, "fp-443")
        svc_22 = NetworkServiceSnapshotEntry(22, "ssh", "SSH_BANNER_V1", None)
        a = _snapshot(["10.0.0.1"], [22, 443], services=[svc_443, svc_22])
        b = _snapshot(["10.0.0.1"], [22, 443], services=[svc_22, svc_443])
        assert a.content_fingerprint == b.content_fingerprint
        assert [s.port for s in a.services] == [22, 443]

    def test_duplicate_ips_collapse_in_snapshot(self) -> None:
        snap = _snapshot(["10.0.0.1", "10.0.0.1", "10.0.0.1"], [22])
        assert snap.resolved_ips == ("10.0.0.1",)

    def test_changed_truth_changes_fingerprint(self) -> None:
        a = _snapshot(["10.0.0.1"], [22])
        b = _snapshot(["10.0.0.1"], [22, 443])
        assert a.content_fingerprint != b.content_fingerprint


class TestTlsCertificateChangeDrift:
    def test_tls_fingerprint_change_on_same_port_produces_deterministic_drift(self) -> None:
        prev = _snapshot(
            ["10.0.0.1"], [443],
            services=[NetworkServiceSnapshotEntry(443, "tls", None, "fingerprint-a")],
        )
        current = _snapshot(
            ["10.0.0.1"], [443],
            services=[NetworkServiceSnapshotEntry(443, "tls", None, "fingerprint-b")],
        )
        events = _detect_drift(prev, current)
        categories = {str(e.category) for e in events}
        assert "tls_certificate_changed" in categories

    def test_identical_tls_fingerprint_produces_no_drift(self) -> None:
        prev = _snapshot(
            ["10.0.0.1"], [443],
            services=[NetworkServiceSnapshotEntry(443, "tls", None, "fingerprint-a")],
        )
        current = _snapshot(
            ["10.0.0.1"], [443],
            services=[NetworkServiceSnapshotEntry(443, "tls", None, "fingerprint-a")],
        )
        assert _detect_drift(prev, current) == []

    def test_protocol_change_on_same_port_produces_deterministic_drift(self) -> None:
        prev = _snapshot(
            ["10.0.0.1"], [8443],
            services=[NetworkServiceSnapshotEntry(8443, "http", None, None)],
        )
        current = _snapshot(
            ["10.0.0.1"], [8443],
            services=[NetworkServiceSnapshotEntry(8443, "tls", None, "fp")],
        )
        events = _detect_drift(prev, current)
        categories = {str(e.category) for e in events}
        assert "protocol_changed" in categories


class TestConditionReactivation:
    def test_condition_first_observed_before_previous_snapshot_is_reactivation(self) -> None:
        long_ago = (datetime.now(UTC) - timedelta(days=30)).isoformat()
        prev = _snapshot(["10.0.0.1"], [443], active_condition_keys=[])
        current = _snapshot(["10.0.0.1"], [443], active_condition_keys=["cond:a"])

        reactivated = _compute_reactivated_keys(prev, current, {"cond:a": long_ago})
        assert reactivated == frozenset({"cond:a"})

        events = _detect_drift(prev, current, reactivated)
        categories = {str(e.category) for e in events}
        assert "condition_reactivated" in categories
        assert "condition_appeared" not in categories

    def test_condition_first_observed_after_previous_snapshot_is_a_fresh_appearance(
        self,
    ) -> None:
        prev = _snapshot(["10.0.0.1"], [443], active_condition_keys=[])
        current = _snapshot(["10.0.0.1"], [443], active_condition_keys=["cond:b"])
        just_now = datetime.now(UTC).isoformat()

        reactivated = _compute_reactivated_keys(prev, current, {"cond:b": just_now})
        assert reactivated == frozenset()

        events = _detect_drift(prev, current, reactivated)
        categories = {str(e.category) for e in events}
        assert "condition_appeared" in categories
        assert "condition_reactivated" not in categories

    def test_no_previous_snapshot_never_classifies_as_reactivation(self) -> None:
        current = _snapshot(["10.0.0.1"], [443], active_condition_keys=["cond:c"])
        assert _compute_reactivated_keys(None, current, {"cond:c": "irrelevant"}) == frozenset()

    def test_condition_resolution_produces_deterministic_drift(self) -> None:
        prev = _snapshot(["10.0.0.1"], [443], active_condition_keys=["cond:d"])
        current = _snapshot(["10.0.0.1"], [443], active_condition_keys=[])
        events = _detect_drift(prev, current)
        categories = {str(e.category) for e in events}
        assert "condition_resolved" in categories
