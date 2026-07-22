"""Orchestrate full M36 code generation."""

from __future__ import annotations

from . import (
    write_autonomous,
    write_autonomous_app,
    write_expanded_tests,
    write_migrations_wiring,
    write_posture_threat,
)


def main() -> None:
    write_autonomous.write()
    write_autonomous_app.write()
    write_posture_threat.write()
    write_migrations_wiring.write()
    write_expanded_tests.write()
    print("M36 generation complete.")
