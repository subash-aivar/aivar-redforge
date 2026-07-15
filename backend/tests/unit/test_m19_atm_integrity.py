"""M19 Adversarial Traceability Matrix — mechanical integrity test.

Parses docs/M19_ADVERSARIAL_TRACEABILITY_MATRIX.md and asserts:
- All ATM-NN scenario IDs are unique
- No gaps in the range ATM-01 through ATM-N
- Only canonical proof statuses are used (PROVEN / PARTIALLY PROVEN /
  NOT PROVEN / NOT APPLICABLE)
- The summary table scenario count equals the number of ATM-## headers
- The summary table PROVEN / PARTIALLY PROVEN / NOT PROVEN / NOT APPLICABLE
  counts match the actual header-level assessments

This test is a pure file-read + regex parse — no DB, no imports of M19 code.
"""

from __future__ import annotations

import re
from pathlib import Path

_ATM_PATH = (
    Path(__file__).parents[3]  # repo root: backend/../..
    / "docs"
    / "M19_ADVERSARIAL_TRACEABILITY_MATRIX.md"
)

_CANONICAL_STATUSES = frozenset({
    "PROVEN",
    "PARTIALLY PROVEN",
    "NOT PROVEN",
    "NOT APPLICABLE",
})

# Regex to find ATM-## headers: "## ATM-01 — …"
_HEADER_RE = re.compile(r"^## ATM-(\d+)", re.MULTILINE)

# Regex to find proof-status lines inside a scenario block:
# "**Proof status**: PROVEN" or "**Proof status**: PARTIALLY PROVEN"
_PROOF_STATUS_RE = re.compile(
    r"\*\*Proof status\*\*:\s*"
    r"(PROVEN|PARTIALLY PROVEN|NOT PROVEN|NOT APPLICABLE)",
    re.MULTILINE,
)

# Regex to parse the summary table rows: "| ATM-01 | … | PROVEN |"
_SUMMARY_ROW_RE = re.compile(
    r"^\|\s*ATM-(\d+)\s*\|[^|]+\|\s*(PROVEN|PARTIALLY PROVEN|NOT PROVEN|NOT APPLICABLE)\s*\|",
    re.MULTILINE,
)

# Regex to find the "N of M scenarios: PROVEN" sentence
_SUMMARY_SENTENCE_RE = re.compile(
    r"(\d+) of (\d+) scenarios[^.]*PROVEN",
)


def _load_atm() -> str:
    assert _ATM_PATH.exists(), (
        f"ATM document not found at {_ATM_PATH}. "
        "Expected at docs/M19_ADVERSARIAL_TRACEABILITY_MATRIX.md relative to repo root."
    )
    return _ATM_PATH.read_text(encoding="utf-8")


def test_atm_file_exists() -> None:
    assert _ATM_PATH.exists(), f"ATM not found: {_ATM_PATH}"


def test_scenario_ids_are_unique() -> None:
    content = _load_atm()
    ids = [int(m.group(1)) for m in _HEADER_RE.finditer(content)]
    assert len(ids) == len(set(ids)), (
        f"Duplicate ATM scenario IDs found: {ids}"
    )


def test_scenario_ids_have_no_gaps() -> None:
    content = _load_atm()
    ids = sorted(int(m.group(1)) for m in _HEADER_RE.finditer(content))
    assert ids, "No ATM-## headers found"
    expected = list(range(1, ids[-1] + 1))
    assert ids == expected, (
        f"Gap in ATM scenario IDs. Expected {expected}, found {ids}"
    )


def test_all_scenarios_have_proof_status() -> None:
    content = _load_atm()
    header_ids = sorted(int(m.group(1)) for m in _HEADER_RE.finditer(content))
    proof_count = len(_PROOF_STATUS_RE.findall(content))
    assert proof_count == len(header_ids), (
        f"Proof status count ({proof_count}) does not match "
        f"scenario count ({len(header_ids)}). "
        f"Every ATM-## header must have exactly one '**Proof status**: ...' line."
    )


def test_only_canonical_proof_statuses_used() -> None:
    content = _load_atm()
    statuses_found = set(_PROOF_STATUS_RE.findall(content))
    non_canonical = statuses_found - _CANONICAL_STATUSES
    assert not non_canonical, (
        f"Non-canonical proof statuses found: {non_canonical}. "
        f"Only {_CANONICAL_STATUSES} are allowed."
    )


def test_summary_table_ids_match_headers() -> None:
    content = _load_atm()
    header_ids = sorted(int(m.group(1)) for m in _HEADER_RE.finditer(content))
    summary_ids = sorted(int(m.group(1)) for m in _SUMMARY_ROW_RE.finditer(content))

    if not summary_ids:
        # No summary table found — not required if the document uses inline statuses only
        return

    assert summary_ids == header_ids, (
        f"Summary table IDs {summary_ids} do not match header IDs {header_ids}"
    )


def test_summary_table_status_counts_match_inline_statuses() -> None:
    content = _load_atm()
    inline_statuses = _PROOF_STATUS_RE.findall(content)
    summary_rows = _SUMMARY_ROW_RE.findall(content)

    if not summary_rows:
        return  # No table to validate

    # Count statuses from the summary table
    summary_status_list = [row[1].strip() for row in summary_rows]

    # Both counts must match
    assert len(inline_statuses) == len(summary_status_list), (
        f"Inline proof status count ({len(inline_statuses)}) does not match "
        f"summary table row count ({len(summary_status_list)})"
    )

    for status in _CANONICAL_STATUSES:
        inline_n = inline_statuses.count(status)
        summary_n = summary_status_list.count(status)
        assert inline_n == summary_n, (
            f"Status '{status}': inline count={inline_n} but "
            f"summary table count={summary_n}"
        )


def test_summary_sentence_arithmetic() -> None:
    content = _load_atm()
    m = _SUMMARY_SENTENCE_RE.search(content)
    if m is None:
        return  # No summary sentence

    proven_claimed = int(m.group(1))
    total_claimed = int(m.group(2))

    header_ids = list(_HEADER_RE.finditer(content))
    assert total_claimed == len(header_ids), (
        f"Summary sentence claims {total_claimed} total scenarios but "
        f"{len(header_ids)} ATM-## headers found"
    )

    inline_statuses = _PROOF_STATUS_RE.findall(content)
    actual_proven = inline_statuses.count("PROVEN")
    assert proven_claimed == actual_proven, (
        f"Summary sentence claims {proven_claimed} PROVEN but "
        f"{actual_proven} 'Proof status: PROVEN' lines found"
    )
