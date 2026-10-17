"""
TenantShield - Run Verification Script
======================================
Convenience script to execute the verification package directly from scripts/.
Usage:
    python scripts/run_verifier.py
"""

import sys
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from verifier.cli import main

if __name__ == "__main__":
    main()
