#!/usr/bin/env python3
"""Generate complete M36 bounded contexts from frozen architecture."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from m36_gen.write_all import main

if __name__ == "__main__":
    main()
