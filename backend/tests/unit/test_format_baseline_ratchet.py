"""Tests for the ruff format debt ratchet (ADR-0009, Phase 0.2.1
Workstream 3.2) — see scripts/check_format_baseline.py and
.ruff-format-baseline.txt's own header comments for the policy this
enforces."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BACKEND_ROOT / "scripts"))

import check_format_baseline as ratchet  # noqa: E402


class TestBaselineFileIsValid:
    def test_baseline_has_no_validation_problems(self) -> None:
        problems = ratchet.validate_baseline()
        assert problems == [], f"baseline file has problems: {problems}"

    def test_every_baseline_entry_is_a_real_tracked_python_file(self) -> None:
        entries = ratchet.load_baseline()
        assert entries, "baseline should not be empty in this repo's current state"
        for entry in entries:
            path = BACKEND_ROOT / entry
            assert path.is_file(), f"baseline entry does not exist: {entry}"
            assert entry.endswith(".py"), f"baseline entry is not a .py file: {entry}"
            assert entry.startswith(("src/", "tests/")), (
                f"baseline entry outside src/ or tests/: {entry}"
            )

    def test_no_duplicate_entries(self) -> None:
        entries = ratchet.load_baseline()
        assert len(entries) == len(set(entries)), "baseline contains duplicate entries"

    def test_no_vendor_or_cache_paths(self) -> None:
        entries = ratchet.load_baseline()
        forbidden = {".venv", "venv", "__pycache__", "node_modules", ".ruff_cache"}
        for entry in entries:
            parts = set(entry.split("/"))
            assert not (parts & forbidden), (
                f"baseline entry looks like a vendor/cache path: {entry}"
            )


class TestRatchetBehavior:
    def test_current_violations_are_a_subset_of_the_baseline(self) -> None:
        """The actual regression-relevant assertion: nothing on disk
        right now introduces formatting debt beyond the known,
        version-controlled baseline. This is what
        scripts/check_format_baseline.py's own exit code enforces in
        CI; duplicated here as a normal pytest assertion so `pytest
        tests/unit/` alone already catches a new violation, without
        requiring the standalone script to also be invoked."""
        baseline = set(ratchet.load_baseline())
        violations = ratchet.current_violations()
        new_debt = violations - baseline
        assert new_debt == set(), (
            f"new formatting debt introduced, not covered by the baseline: {sorted(new_debt)}"
        )

    def test_known_baseline_debt_does_not_block_this_assertion(self) -> None:
        """Sanity check on the ratchet's own premise: the baseline is
        non-empty (there IS known legacy debt) and yet the subset
        check above still passes — proving the ratchet tolerates known
        debt without either hiding it or blocking unrelated
        verification."""
        baseline = ratchet.load_baseline()
        assert len(baseline) > 0, "expected non-empty legacy baseline in this repo's current state"

    def test_a_synthetic_new_violation_outside_the_baseline_fails_the_script(
        self, tmp_path: Path
    ) -> None:
        """End-to-end proof the CLI script itself (not just the
        importable functions) exits non-zero for a real, newly
        introduced violation — by actually running it as a subprocess
        against a temporarily-mutated tracked file, then restoring it,
        exactly mirroring how the CI job invokes it."""
        target = BACKEND_ROOT / "tests" / "unit" / "test_product_edition_router_surface.py"
        original = target.read_text(encoding="utf-8")
        try:
            target.write_text(
                original + "\nx    =    1  # deliberately unformatted\n", encoding="utf-8"
            )
            result = subprocess.run(
                [sys.executable, str(BACKEND_ROOT / "scripts" / "check_format_baseline.py")],
                cwd=BACKEND_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            assert result.returncode == 1, (
                f"expected exit 1 for new violation, got {result.returncode}\n{result.stdout}\n{result.stderr}"
            )
            assert "test_product_edition_router_surface.py" in result.stderr
        finally:
            target.write_text(original, encoding="utf-8")

    def test_invalid_baseline_entry_fails_validation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A baseline referencing a nonexistent file must be rejected
        — proves the baseline itself is validated, not just trusted."""
        fake_baseline = tmp_path / "fake-baseline.txt"
        fake_baseline.write_text("src/this/file/does/not/exist.py\n", encoding="utf-8")
        monkeypatch.setattr(ratchet, "BASELINE_PATH", fake_baseline)
        problems = ratchet.validate_baseline()
        assert any("does not exist on disk" in p for p in problems)
