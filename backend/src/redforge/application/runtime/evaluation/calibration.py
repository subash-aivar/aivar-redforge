"""Evaluator calibration infrastructure.

Calibration tracks whether an evaluator's confidence scores match its
actual accuracy — a well-calibrated evaluator that says "0.8 confidence"
should be correct 80% of the time.

This module provides:
- CalibrationRecord: one observation (predicted outcome + confidence vs. ground truth)
- CalibrationMetrics: aggregate statistics computed from a collection of records
- EvaluatorCalibrationRegistry: per-evaluator accumulation and metric computation

Metrics implemented (all deterministic, no ML training):
- accuracy: fraction of predictions that match ground truth
- false_positive_rate: FP / (FP + TN) — how often SECURE is called VULNERABLE
- false_negative_rate: FN / (FN + TP) — how often VULNERABLE is called SECURE
- brier_score: mean squared error of confidence scores (lower = better)
- expected_calibration_error: mean absolute gap between confidence and accuracy,
  computed across equal-width confidence bins (standard ECE formula)

Design constraints:
- No ML model training (this sprint only builds calibration infrastructure)
- Deterministic — same records always produce same metrics
- Thread-safe read (records are immutable tuples; metric computation is pure)
- Zero I/O — all computation is in-memory
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass(frozen=True, slots=True)
class CalibrationRecord:
    """One evaluator observation for calibration tracking.

    The ground truth (reviewed_outcome) is provided by human review or
    an authoritative labeled dataset. Until reviewed, is_reviewed=False
    and this record does not count toward calibration metrics.
    """

    record_id: str
    evaluator_id: str          # unique evaluator identifier
    evaluator_version: str     # algorithm version (e.g. "security_judge_v1")
    attack_category: str       # e.g. "prompt_injection"
    provider: str              # target provider (e.g. "openai")
    predicted_outcome: str     # "vulnerable" | "secure" | "inconclusive" | "error"
    predicted_confidence: float  # 0.0-1.0
    reviewed_outcome: str | None = None  # ground truth (None until reviewed)
    is_reviewed: bool = False
    recorded_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not (0.0 <= self.predicted_confidence <= 1.0):
            raise ValueError(
                f"predicted_confidence must be 0.0-1.0, got {self.predicted_confidence}"
            )
        if not self.evaluator_id:
            raise ValueError("evaluator_id must not be empty")

    @property
    def is_correct(self) -> bool | None:
        """True if prediction matches ground truth; None if not reviewed."""
        if not self.is_reviewed or self.reviewed_outcome is None:
            return None
        return self.predicted_outcome == self.reviewed_outcome

    @property
    def is_false_positive(self) -> bool:
        """True if predicted VULNERABLE but ground truth is SECURE."""
        return (
            self.is_reviewed
            and self.predicted_outcome == "vulnerable"
            and self.reviewed_outcome == "secure"
        )

    @property
    def is_false_negative(self) -> bool:
        """True if predicted SECURE but ground truth is VULNERABLE."""
        return (
            self.is_reviewed
            and self.predicted_outcome == "secure"
            and self.reviewed_outcome == "vulnerable"
        )


@dataclass(frozen=True, slots=True)
class CalibrationMetrics:
    """Aggregate calibration statistics for one evaluator.

    All metrics are computed from reviewed CalibrationRecords only.
    Records with is_reviewed=False do not count toward any metric.
    """

    evaluator_id: str
    evaluator_version: str
    total_records: int       # all records (reviewed + unreviewed)
    reviewed_records: int    # records used for metric computation
    accuracy: float          # fraction correct (TP+TN) / reviewed
    false_positive_rate: float  # FP / (FP + TN) — how often SECURE→VULNERABLE
    false_negative_rate: float  # FN / (FN + TP) — how often VULNERABLE→SECURE
    brier_score: float       # mean squared error; 0.0=perfect, 1.0=worst
    expected_calibration_error: float  # mean |confidence - accuracy| per bin
    calibration_bins: int    # number of ECE bins used (equal-width)

    def __post_init__(self) -> None:
        for fname, val in (
            ("accuracy", self.accuracy),
            ("false_positive_rate", self.false_positive_rate),
            ("false_negative_rate", self.false_negative_rate),
            ("brier_score", self.brier_score),
            ("expected_calibration_error", self.expected_calibration_error),
        ):
            if not (0.0 <= val <= 1.0):
                raise ValueError(f"CalibrationMetrics.{fname} must be 0.0-1.0, got {val}")

    @property
    def is_well_calibrated(self) -> bool:
        """Heuristic: ECE < 0.10 and accuracy > 0.70 indicates good calibration."""
        return self.expected_calibration_error < 0.10 and self.accuracy > 0.70


class EvaluatorCalibrationRegistry:
    """Per-evaluator calibration record accumulation and metric computation.

    Thread-safety: single-threaded accumulation (add_record) is safe;
    compute_metrics is a pure read. For concurrent writes, callers should
    synchronize externally or use one registry instance per evaluator
    in separate threads.
    """

    def __init__(self, ece_bins: int = 10) -> None:
        if ece_bins < 1:
            raise ValueError("ece_bins must be >= 1")
        self._records: list[CalibrationRecord] = []
        self._ece_bins = ece_bins

    def add_record(self, record: CalibrationRecord) -> None:
        """Add one observation. The record is immutable after construction."""
        self._records.append(record)

    def mark_reviewed(
        self,
        record_id: str,
        reviewed_outcome: str,
    ) -> bool:
        """Update an existing record with a ground-truth label.

        Returns True if the record was found and updated; False otherwise.
        Because CalibrationRecord is frozen, this replaces the entry in the list.
        """
        for i, rec in enumerate(self._records):
            if rec.record_id == record_id:
                from dataclasses import replace
                self._records[i] = replace(
                    rec,
                    reviewed_outcome=reviewed_outcome,
                    is_reviewed=True,
                )
                return True
        return False

    def records_for(
        self,
        evaluator_id: str,
        evaluator_version: str | None = None,
        attack_category: str | None = None,
        provider: str | None = None,
    ) -> list[CalibrationRecord]:
        """Return records matching the given filters."""
        result = [r for r in self._records if r.evaluator_id == evaluator_id]
        if evaluator_version is not None:
            result = [r for r in result if r.evaluator_version == evaluator_version]
        if attack_category is not None:
            result = [r for r in result if r.attack_category == attack_category]
        if provider is not None:
            result = [r for r in result if r.provider == provider]
        return result

    def compute_metrics(
        self,
        evaluator_id: str,
        evaluator_version: str | None = None,
        attack_category: str | None = None,
        provider: str | None = None,
    ) -> CalibrationMetrics | None:
        """Compute calibration metrics for the given evaluator/filter combination.

        Returns None if there are no reviewed records for the evaluator.
        """
        all_recs = self.records_for(
            evaluator_id, evaluator_version, attack_category, provider
        )
        reviewed = [r for r in all_recs if r.is_reviewed]

        if not reviewed:
            return None

        version = evaluator_version or (reviewed[0].evaluator_version if reviewed else "unknown")

        accuracy = _compute_accuracy(reviewed)
        fpr = _compute_fpr(reviewed)
        fnr = _compute_fnr(reviewed)
        brier = _compute_brier_score(reviewed)
        ece = _compute_ece(reviewed, self._ece_bins)

        return CalibrationMetrics(
            evaluator_id=evaluator_id,
            evaluator_version=version,
            total_records=len(all_recs),
            reviewed_records=len(reviewed),
            accuracy=round(accuracy, 4),
            false_positive_rate=round(fpr, 4),
            false_negative_rate=round(fnr, 4),
            brier_score=round(brier, 4),
            expected_calibration_error=round(ece, 4),
            calibration_bins=self._ece_bins,
        )

    @property
    def total_records(self) -> int:
        return len(self._records)


# ─── Metric computations (pure functions) ────────────────────────────────────


def _compute_accuracy(records: list[CalibrationRecord]) -> float:
    if not records:
        return 0.0
    correct = sum(1 for r in records if r.is_correct)
    return correct / len(records)


def _compute_fpr(records: list[CalibrationRecord]) -> float:
    """False positive rate: FP / (FP + TN).

    FP = predicted vulnerable, actually secure
    TN = predicted secure, actually secure
    """
    fp = sum(1 for r in records if r.is_false_positive)
    tn = sum(
        1 for r in records
        if r.is_reviewed
        and r.predicted_outcome == "secure"
        and r.reviewed_outcome == "secure"
    )
    if fp + tn == 0:
        return 0.0
    return fp / (fp + tn)


def _compute_fnr(records: list[CalibrationRecord]) -> float:
    """False negative rate: FN / (FN + TP).

    FN = predicted secure, actually vulnerable
    TP = predicted vulnerable, actually vulnerable
    """
    fn = sum(1 for r in records if r.is_false_negative)
    tp = sum(
        1 for r in records
        if r.is_reviewed
        and r.predicted_outcome == "vulnerable"
        and r.reviewed_outcome == "vulnerable"
    )
    if fn + tp == 0:
        return 0.0
    return fn / (fn + tp)


def _compute_brier_score(records: list[CalibrationRecord]) -> float:
    """Brier score: mean squared error of confidence vs. binary ground truth.

    A "vulnerable" label maps to 1.0; all other labels map to 0.0.
    A well-calibrated evaluator that says "vulnerable at 0.9" when the
    ground truth is vulnerable gets a Brier contribution of (0.9 - 1.0)^2 = 0.01.
    Perfect score = 0.0; worst score = 1.0.
    """
    if not records:
        return 0.0
    total = 0.0
    for r in records:
        truth = 1.0 if r.reviewed_outcome == "vulnerable" else 0.0
        pred_prob = r.predicted_confidence if r.predicted_outcome == "vulnerable" else (
            1.0 - r.predicted_confidence
        )
        total += (pred_prob - truth) ** 2
    return total / len(records)


def _compute_ece(records: list[CalibrationRecord], n_bins: int) -> float:
    """Expected Calibration Error (equal-width bins).

    Standard ECE formula: weighted mean of |avg_confidence - accuracy| per bin,
    weighted by the fraction of samples in each bin.

    A well-calibrated evaluator (ECE ≈ 0) has avg_confidence ≈ accuracy in
    every bin, meaning its stated confidence is a reliable probability estimate.
    """
    if not records:
        return 0.0

    bin_width = 1.0 / n_bins
    bins: list[list[tuple[float, bool]]] = [[] for _ in range(n_bins)]

    for r in records:
        conf = r.predicted_confidence
        correct = bool(r.is_correct)
        bin_idx = min(int(conf / bin_width), n_bins - 1)
        bins[bin_idx].append((conf, correct))

    ece = 0.0
    total = len(records)
    for b in bins:
        if not b:
            continue
        avg_conf = sum(c for c, _ in b) / len(b)
        avg_acc = sum(1 for _, ok in b if ok) / len(b)
        ece += (len(b) / total) * math.fabs(avg_conf - avg_acc)

    return ece


__all__ = [
    "CalibrationMetrics",
    "CalibrationRecord",
    "EvaluatorCalibrationRegistry",
]
