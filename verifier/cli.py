"""
TenantShield - Verification CLI Entrypoint
==========================================
Enables executing the verifier directly via `python -m verifier` or `python -m verifier.cli`.
"""

import asyncio
import sys
from verifier.runner import VerificationRunner


def main() -> None:
    runner = VerificationRunner()
    report = asyncio.run(runner.run_verification())
    if report["summary"]["leaked_attacks"] > 0 or report["summary"]["tenant_b_canary_integrity"] != "INTACT":
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
