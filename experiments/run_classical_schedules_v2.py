#!/usr/bin/env python3
"""Run corrected CLASSICAL-SCHEDULES-0002 without replaying failed cases."""
from pathlib import Path
import run_classical_schedules as runner

runner.SPEC = runner.ROOT / "experiments/CLASSICAL-SCHEDULES-0002.json"

if __name__ == "__main__":
    raise SystemExit(runner.main())
