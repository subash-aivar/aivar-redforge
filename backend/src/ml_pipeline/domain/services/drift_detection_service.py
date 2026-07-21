"""PSI drift detection — auto-deprecate at PSI >= 0.20."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass(frozen=True, slots=True)
class DriftResult:
    psi: float
    severe: bool
    moderate: bool


class DriftDetectionService:
    MODERATE = 0.10
    SEVERE = 0.20

    def compute_psi(
        self, expected: list[float], actual: list[float], *, bins: int = 10
    ) -> DriftResult:
        if len(expected) < 2 or len(actual) < 2:
            return DriftResult(0.0, False, False)
        exp = np.asarray(expected, dtype=float)
        act = np.asarray(actual, dtype=float)
        breakpoints = np.linspace(min(exp.min(), act.min()), max(exp.max(), act.max()), bins + 1)
        exp_counts, _ = np.histogram(exp, bins=breakpoints)
        act_counts, _ = np.histogram(act, bins=breakpoints)
        exp_pct = exp_counts / max(exp_counts.sum(), 1)
        act_pct = act_counts / max(act_counts.sum(), 1)
        # Avoid div by zero
        exp_pct = np.where(exp_pct == 0, 1e-6, exp_pct)
        act_pct = np.where(act_pct == 0, 1e-6, act_pct)
        psi = float(np.sum((act_pct - exp_pct) * np.log(act_pct / exp_pct)))
        return DriftResult(psi, psi >= self.SEVERE, self.MODERATE <= psi < self.SEVERE)
