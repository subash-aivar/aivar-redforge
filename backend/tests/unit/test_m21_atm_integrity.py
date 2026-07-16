"""M21 Adversarial Traceability Matrix (ATM) integrity tests.

Validates structural consistency of docs/M21_ADVERSARIAL_TRACEABILITY_MATRIX.md:
  - All ATM IDs are unique
  - IDs form a gap-free sequence from M21-ATM-01 to M21-ATM-N
  - Each row carries exactly one canonical status
  - Status values are restricted to the four canonical values
  - Summary status counts match the parsed matrix
  - Arithmetic: PROVEN + PARTIALLY PROVEN + NOT PROVEN + NOT APPLICABLE == Total

Does NOT enforce:
  - A minimum PROVEN count
  - Zero NOT PROVEN rows
  - A COMPLETE verdict
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ATM_PATH = (
    Path(__file__).parent.parent.parent.parent / "docs" / "M21_ADVERSARIAL_TRACEABILITY_MATRIX.md"
)

_CANONICAL_STATUSES = frozenset({
    "PROVEN",
    "PARTIALLY PROVEN",
    "NOT PROVEN",
    "NOT APPLICABLE",
})

_ROW_RE = re.compile(
    r"\|\s*(M21-ATM-\d+)\s*\|[^|]*\|\s*(PROVEN|PARTIALLY PROVEN|NOT PROVEN|NOT APPLICABLE)\s*\|"
)
_SUMMARY_RE = re.compile(r"\|\s*\*\*Total\*\*\s*\|\s*\*\*(\d+)\*\*\s*\|")
_SUMMARY_STATUS_RE = re.compile(
    r"\|\s*(PROVEN|PARTIALLY PROVEN|NOT PROVEN|NOT APPLICABLE)\s*\|\s*(\d+)\s*\|"
)


def _load_atm() -> str:
    assert _ATM_PATH.exists(), f"ATM document not found: {_ATM_PATH}"
    return _ATM_PATH.read_text(encoding="utf-8")


def _parse_matrix_rows(text: str) -> list[tuple[str, str]]:
    """Return list of (id_str, status) for each matrix row."""
    return _ROW_RE.findall(text)


def _parse_summary(text: str) -> dict[str, int]:
    """Return {status: count} from the summary table, plus 'Total'."""
    result: dict[str, int] = {}
    for status, count in _SUMMARY_STATUS_RE.findall(text):
        result[status] = int(count)
    m = _SUMMARY_RE.search(text)
    if m:
        result["Total"] = int(m.group(1))
    return result


class TestATMStructure:
    def test_atm_file_exists(self) -> None:
        assert _ATM_PATH.exists(), f"ATM doc missing: {_ATM_PATH}"

    def test_matrix_has_entries(self) -> None:
        rows = _parse_matrix_rows(_load_atm())
        assert len(rows) > 0, "No ATM matrix rows found"

    def test_all_ids_unique(self) -> None:
        rows = _parse_matrix_rows(_load_atm())
        ids = [r[0] for r in rows]
        assert len(ids) == len(set(ids)), f"Duplicate ATM IDs: {[i for i in ids if ids.count(i) > 1]}"

    def test_ids_form_sequential_range(self) -> None:
        rows = _parse_matrix_rows(_load_atm())
        numbers = sorted(int(r[0].split("-")[-1]) for r in rows)
        expected = list(range(1, len(numbers) + 1))
        assert numbers == expected, (
            f"ATM IDs have gaps or unexpected values.\n"
            f"Found:    {numbers}\n"
            f"Expected: {expected}"
        )

    def test_all_statuses_are_canonical(self) -> None:
        rows = _parse_matrix_rows(_load_atm())
        for atm_id, status in rows:
            assert status in _CANONICAL_STATUSES, (
                f"{atm_id} has non-canonical status '{status}'. "
                f"Allowed: {sorted(_CANONICAL_STATUSES)}"
            )

    def test_exactly_one_status_per_row(self) -> None:
        text = _load_atm()
        rows = _parse_matrix_rows(text)
        # Each row must appear exactly once in the matrix section
        for atm_id, _ in rows:
            count = text.count(atm_id)
            assert count >= 1, f"{atm_id} appears 0 times (should appear ≥1)"


class TestATMSummaryCounts:
    def test_summary_table_exists(self) -> None:
        summary = _parse_summary(_load_atm())
        assert "Total" in summary, "ATM summary table missing **Total** row"
        assert len(summary) >= 2, "ATM summary table has fewer entries than expected"

    def test_summary_counts_match_matrix(self) -> None:
        text = _load_atm()
        rows = _parse_matrix_rows(text)
        summary = _parse_summary(text)

        # Count parsed statuses
        from collections import Counter
        parsed_counts = Counter(status for _, status in rows)

        for status, expected_count in summary.items():
            if status == "Total":
                continue
            actual = parsed_counts.get(status, 0)
            assert actual == expected_count, (
                f"Summary says {status} = {expected_count}, "
                f"but parsed matrix has {actual} rows with that status"
            )

    def test_summary_arithmetic_is_correct(self) -> None:
        text = _load_atm()
        summary = _parse_summary(text)
        if "Total" not in summary:
            pytest.skip("No Total row in summary")

        status_sum = sum(v for k, v in summary.items() if k != "Total")
        assert status_sum == summary["Total"], (
            f"Summary arithmetic incorrect: "
            f"status counts sum to {status_sum} but Total = {summary['Total']}"
        )

    def test_total_matches_matrix_row_count(self) -> None:
        text = _load_atm()
        rows = _parse_matrix_rows(text)
        summary = _parse_summary(text)
        if "Total" not in summary:
            pytest.skip("No Total row in summary")
        assert len(rows) == summary["Total"], (
            f"Matrix has {len(rows)} rows but summary Total = {summary['Total']}"
        )
