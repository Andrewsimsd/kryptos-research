#!/usr/bin/env python3
"""Run BLIND-0004 with fresh hidden seed and final audit gates."""

from pathlib import Path

from run_blind import ROOT
from run_blind_v2 import main


if __name__ == "__main__":
    raise SystemExit(main(spec_path=ROOT / "experiments/BLIND-0004.json",
                          family="BLIND-0004", runner_path=Path(__file__).resolve()))
