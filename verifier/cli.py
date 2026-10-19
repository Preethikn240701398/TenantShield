"""
TenantShield - Verification CLI Entrypoint
==========================================
Enables executing the verifier directly via `python -m verifier` or `python -m verifier.cli`.
"""

import argparse
import asyncio
import sys
from verifier.runner import VerificationRunner


def main() -> None:
    parser = argparse.ArgumentParser(description="TenantShield Verification CLI")
    parser.add_argument(
        "--mode",
        choices=["all", "secure_only", "vulnerable_only", "secure", "vulnerable"],
        default="all",
        help="Verification scope mode: 'all' (default), 'vulnerable_only', or 'secure_only'",
    )
    args = parser.parse_args()

    if args.mode in ("vulnerable_only", "vulnerable"):
        target_mode = "vulnerable_only"
    elif args.mode in ("secure_only", "secure"):
        target_mode = "secure_only"
    else:
        target_mode = "all"

    runner = VerificationRunner(mode=target_mode)
    report = asyncio.run(runner.run_verification())

    summary = report["summary"]
    if summary["leaked_attacks"] > 0:
        sys.exit(1)

    if target_mode != "vulnerable_only" and summary["tenant_b_canary_integrity"] != "INTACT":
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
