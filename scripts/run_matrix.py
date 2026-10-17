"""
TenantShield - Run Layer-Kill Matrix Script
===========================================
Executes the Level 8 Layer-Kill Matrix across all 4 configurations:
(a) all controls on
(b) app ownership check off
(c) RLS off
(d) both off
Usage:
    python scripts/run_matrix.py
"""

import asyncio
from pathlib import Path
import sys

# Ensure project root in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from verifier.matrix_runner import LayerKillMatrixRunner


def main():
    runner = LayerKillMatrixRunner()
    report = asyncio.run(runner.run_matrix())
    print("[SUCCESS] Layer-Kill Matrix completed successfully.")


if __name__ == "__main__":
    main()
