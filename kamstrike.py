#!/usr/bin/env python3
"""KAMSTRIKE launcher, so the tool runs straight from a clone with no install."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from kamstrike.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
