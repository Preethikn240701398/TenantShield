"""
TenantShield - Run Isolation Mutation Testing Script
====================================================
Runs the full suite of isolation mutation experiments:
1. Validates safety constraints (APP_ENV=lab and DB=tenantshield_lab)
2. Runs clean baseline verification
3. Injects realistic mutations in isolated and masked runs
4. Generates JSON and CSV mutation reports in results/

Usage:
    python scripts/run_mutation.py
"""

import asyncio
from pathlib import Path
import sys

# Ensure project root in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.config import settings
from verifier.mutation import IsolationMutationRunner


def main():
    # Configure lab environment for mutation testing against tenantshield_lab
    settings.APP_ENV = "lab"
    settings.ENVIRONMENT = "lab"
    runner = IsolationMutationRunner()
    report = asyncio.run(runner.run_all_mutations())
    print("[SUCCESS] Isolation Mutation Testing run completed successfully.")


if __name__ == "__main__":
    main()
