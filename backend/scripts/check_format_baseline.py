#!/usr/bin/env python3
"""ruff format debt ratchet (ADR-0009, Phase 0.2.1 Workstream 3.2).

See `.ruff-format-baseline.txt`'s own header for the policy this
enforces. Short version: any file `ruff format --check` currently
flags MUST already be listed in the baseline file, or this script
exits non-zero. This is what makes new formatting debt impossible to
introduce while the large pre-existing debt inherited from before this
policy remains tolerated (not silently fixed, not silently hidden).

Run from the `backend/` directory (matches every other backend CI job's
`working-directory: backend`):

    python scripts/check_format_baseline.py

Exit codes:
    0  every current violation is a known baseline entry (or there are
       no violations at all)
    1  at least one file violates formatting but is NOT in the
       baseline — new debt, must be fixed before merging
    2  the baseline file itself is invalid (see validate_baseline())
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
BASELINE_PATH = BACKEND_ROOT / ".ruff-format-baseline.txt"
CHECKED_DIRS = ("src", "tests")


def load_baseline() -> list[str]:
    """Every non-comment, non-blank line, in file order (for
    duplicate-detection — callers needing a set should wrap this)."""
    lines = BASELINE_PATH.read_text(encoding="utf-8").splitlines()
    return [line for line in lines if line.strip() and not line.lstrip().startswith("#")]


def validate_baseline() -> list[str]:
    """Returns a list of human-readable problems; empty means valid.
    Every entry must be: a real, currently-tracked file under src/ or
    tests/, ending in .py, listed exactly once, with no leading/
    trailing whitespace — never a glob, a directory, or a path outside
    this backend."""
    problems: list[str] = []
    entries = load_baseline()

    seen: dict[str, int] = {}
    for entry in entries:
        seen[entry] = seen.get(entry, 0) + 1
    for entry, count in seen.items():
        if count > 1:
            problems.append(f"duplicate baseline entry ({count}x): {entry}")

    for entry in entries:
        if entry != entry.strip():
            problems.append(f"baseline entry has leading/trailing whitespace: {entry!r}")
            continue
        if not entry.endswith(".py"):
            problems.append(f"baseline entry is not a .py file: {entry}")
            continue
        if not (entry.startswith("src/") or entry.startswith("tests/")):
            problems.append(f"baseline entry outside src/ or tests/: {entry}")
            continue
        if any(
            part in {".venv", "venv", "__pycache__", "node_modules", ".ruff_cache"}
            for part in entry.split("/")
        ):
            problems.append(f"baseline entry looks like a vendor/cache path: {entry}")
            continue
        resolved = BACKEND_ROOT / entry
        if not resolved.is_file():
            problems.append(f"baseline entry does not exist on disk: {entry}")
            continue

    sorted_entries = sorted(set(entries))
    if entries != sorted_entries and sorted(entries) == sorted_entries:
        # Only a soft/ordering note, not a hard failure — still surfaced
        # so the file stays easy to review/diff over time.
        problems.append(
            "baseline is not sorted (cosmetic only, but keep it sorted for reviewable diffs)"
        )

    return problems


def current_violations() -> set[str]:
    """The set of backend/-relative paths `ruff format --check`
    currently flags. Uses `--diff` and parses the unified-diff `--- `
    header lines rather than the terse `Would reformat: ...` summary —
    the latter's presence/absence is sensitive to whether ruff detects
    an interactive terminal, which is not a stable property to depend
    on in CI or in any non-interactive invocation; `--diff`'s unified-
    diff format is not."""
    proc = subprocess.run(
        ["ruff", "format", "--diff", *CHECKED_DIRS],
        cwd=BACKEND_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    violations: set[str] = set()
    for line in proc.stdout.splitlines():
        if line.startswith("--- "):
            violations.add(line[len("--- ") :].strip())
    return violations


def main() -> int:
    baseline_problems = validate_baseline()
    if baseline_problems:
        print("BASELINE FILE IS INVALID:", file=sys.stderr)
        for problem in baseline_problems:
            print(f"  - {problem}", file=sys.stderr)
        return 2

    baseline = set(load_baseline())
    violations = current_violations()

    new_debt = sorted(violations - baseline)
    stale_baseline_entries = sorted(baseline - violations)

    if stale_baseline_entries:
        print(
            f"INFO: {len(stale_baseline_entries)} baseline entries are already "
            "formatting-clean and could be removed from .ruff-format-baseline.txt "
            "(not a failure — just an opportunity to shrink the debt):"
        )
        for entry in stale_baseline_entries:
            print(f"  - {entry}")

    if new_debt:
        print(
            f"\nFAIL: {len(new_debt)} file(s) fail `ruff format --check` and are "
            "NOT in .ruff-format-baseline.txt — this is NEW formatting debt, not "
            "tolerated by the ratchet:",
            file=sys.stderr,
        )
        for entry in new_debt:
            print(f"  - {entry}", file=sys.stderr)
        print(
            "\nFix with: ruff format <path> for each file above, then re-run this "
            "script. Do NOT add these files to the baseline — the baseline is only "
            "for debt that predates this policy (see its own header comment).",
            file=sys.stderr,
        )
        return 1

    print(
        f"OK: {len(violations)} pre-existing formatting violation(s), all present "
        f"in the {len(baseline)}-entry baseline. No new formatting debt."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
