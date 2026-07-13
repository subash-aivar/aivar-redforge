"""Target-level configuration drift detection between ValidationSnapshots.

This is distinct from the campaign-level DriftDetector
(application/campaigns/drift_detector.py) which compares two campaigns.
This detector compares ConfigurationFingerprints between adjacent or
baseline-vs-current snapshots.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.domain.posture.value_objects import DriftEvent

if TYPE_CHECKING:
    from redforge.domain.posture.entity import ValidationSnapshot
    from redforge.domain.posture.value_objects import DriftType


class DriftDetector:
    """Detects configuration drift between two ValidationSnapshots.

    Usage:
        detector = DriftDetector()
        event = detector.detect(source_snapshot, target_snapshot)
        if event:
            # configuration changed between the two runs
    """

    def detect(
        self,
        source: ValidationSnapshot,
        target: ValidationSnapshot,
    ) -> DriftEvent | None:
        """Compare fingerprints; return a DriftEvent if anything changed."""
        drift_types: list[DriftType] = source.fingerprint.diff(target.fingerprint)
        if not drift_types:
            return None

        changed = ", ".join(dt.value.replace("_", " ") for dt in drift_types)
        description = (
            f"Configuration drift detected between snapshot "
            f"{source.id[:8]} and {target.id[:8]}: {changed}"
        )
        return DriftEvent(
            source_snapshot_id=source.id,
            target_snapshot_id=target.id,
            drift_types=tuple(drift_types),
            description=description,
        )

    def detect_from_baseline(
        self,
        baseline_snapshot_id: str,
        baseline_fingerprint: object,
        current: ValidationSnapshot,
    ) -> DriftEvent | None:
        """Compare a baseline fingerprint (not a full snapshot) to a current snapshot.

        Used when the baseline snapshot is no longer in the window but the
        baseline's fingerprint is still available on the ValidationBaseline entity.
        """
        from redforge.domain.posture.value_objects import ConfigurationFingerprint

        if not isinstance(baseline_fingerprint, ConfigurationFingerprint):
            return None

        drift_types: list[DriftType] = baseline_fingerprint.diff(current.fingerprint)
        if not drift_types:
            return None

        changed = ", ".join(dt.value.replace("_", " ") for dt in drift_types)
        description = (
            f"Configuration drift detected from baseline "
            f"(snapshot {baseline_snapshot_id[:8]}) to current "
            f"(snapshot {current.id[:8]}): {changed}"
        )
        return DriftEvent(
            source_snapshot_id=baseline_snapshot_id,
            target_snapshot_id=current.id,
            drift_types=tuple(drift_types),
            description=description,
        )
