#!/usr/bin/env python3
"""Run corrected CLASSICAL-SCHEDULES-0003 with proven tamper negatives."""
import run_classical_schedules as runner

runner.SPEC = runner.ROOT / "experiments/CLASSICAL-SCHEDULES-0003.json"

if __name__ == "__main__":
    raise SystemExit(runner.main())
