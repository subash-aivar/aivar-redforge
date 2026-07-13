"""Mechanical integrity check for docs/M16_ADVERSARIAL_TRACEABILITY_MATRIX.md.

Parses the per-scenario table directly from the doc (repository truth, not
memory) and asserts:
  - scenario numbers are exactly {1..95}, no duplicates, no gaps, nothing
    outside that range
  - every row's Status column is exactly one of the four canonical values
  - the doc's own summary table's counts match a mechanical recount of the
    per-row statuses

This exists because a prior pass's summary table (PROVEN=93, NOT
APPLICABLE=6) did not sum to 95 — a bookkeeping error, not a scenario-count
error. This test makes that class of error impossible to silently
reintroduce.
"""

from __future__ import annotations

import re
from pathlib import Path

_DOC_PATH = (
    Path(__file__).resolve().parents[3] / "docs" / "M16_ADVERSARIAL_TRACEABILITY_MATRIX.md"
)
_EXPECTED_SCENARIOS = set(range(1, 96))
_VALID_STATUSES = {"PROVEN", "NOT APPLICABLE", "PARTIALLY PROVEN", "NOT PROVEN"}

_ROW_RE = re.compile(r"^\|\s*(\d+)\s*\|(.*)\|\s*$")


def _parse_rows() -> list[tuple[int, str, str]]:
    """Returns [(scenario_number, status, raw_line), ...] for every
    per-scenario table row (skips the header/separator and any other
    table in the doc, e.g. the Summary table, by requiring the first
    cell to be a bare integer)."""
    rows: list[tuple[int, str, str]] = []
    for line in _DOC_PATH.read_text().splitlines():
        match = _ROW_RE.match(line)
        if match is None:
            continue
        scenario_number = int(match.group(1))
        cells = [c.strip() for c in match.group(2).split("|")]
        # Columns after the leading '#' cell: Scenario, Test file, Test
        # function, Proof type, Status, Evidence/reason.
        assert len(cells) >= 5, f"malformed row for scenario {scenario_number}: {line!r}"
        status = cells[4]
        rows.append((scenario_number, status, line))
    return rows


def _parse_summary_counts() -> dict[str, int]:
    text = _DOC_PATH.read_text()
    summary_section = text.split("## Summary", 1)[1].split("## Remaining gap", 1)[0]
    counts: dict[str, int] = {}
    for line in summary_section.splitlines():
        match = re.match(r"^\|\s*([A-Za-z ()/,'-]+?)\s*\|\s*(\d+)\s*\|\s*$", line)
        if match is None:
            continue
        label, count = match.group(1).strip(), int(match.group(2))
        if label.upper().startswith("NOT APPLICABLE"):
            counts["NOT APPLICABLE"] = count
        elif label.upper().startswith("PARTIALLY PROVEN"):
            counts["PARTIALLY PROVEN"] = count
        elif label.upper().startswith("NOT PROVEN"):
            counts["NOT PROVEN"] = count
        elif label.upper().startswith("PROVEN"):
            counts["PROVEN"] = count
    return counts


def test_scenario_numbers_are_exactly_1_to_95_no_duplicates_no_gaps() -> None:
    rows = _parse_rows()
    numbers = [n for n, _, _ in rows]

    duplicates = {n for n in numbers if numbers.count(n) > 1}
    assert duplicates == set(), f"duplicate scenario numbers found: {sorted(duplicates)}"

    seen = set(numbers)
    missing = _EXPECTED_SCENARIOS - seen
    assert missing == set(), f"missing scenario numbers: {sorted(missing)}"

    out_of_range = seen - _EXPECTED_SCENARIOS
    assert out_of_range == set(), f"scenario numbers outside 1..95: {sorted(out_of_range)}"

    assert len(rows) == 95, f"expected exactly 95 rows, found {len(rows)}"


def test_every_row_has_exactly_one_valid_status() -> None:
    rows = _parse_rows()
    invalid = [(n, status) for n, status, _ in rows if status not in _VALID_STATUSES]
    assert invalid == [], (
        f"rows with a status outside {_VALID_STATUSES} (must be exactly one canonical "
        f"value, not a hybrid annotation): {invalid}"
    )


def test_summary_counts_match_mechanical_recount_of_rows() -> None:
    rows = _parse_rows()
    recounted: dict[str, int] = {status: 0 for status in _VALID_STATUSES}
    for _, status, _ in rows:
        recounted[status] += 1

    declared = _parse_summary_counts()
    assert declared == recounted, (
        f"Summary table counts {declared} do not match a mechanical recount of the "
        f"95 per-scenario rows {recounted}. Fix the Summary table to match repository "
        f"truth — do not adjust row statuses merely to make arithmetic pass."
    )

    total = sum(recounted.values())
    assert total == 95, f"recounted total {total} != 95"
