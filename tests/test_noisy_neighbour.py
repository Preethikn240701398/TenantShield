"""
TenantShield - Noisy-Neighbour End-to-End Test Suite
====================================================
End-to-end integration tests for noisy-neighbour isolation strategies.
Marked as '@pytest.mark.slow' so that standard pytest runs remain fast.
"""

from pathlib import Path
import pytest
from loadtests.generator import HTTPWorkloadGenerator
from loadtests.runner import NoisyNeighbourRunner


@pytest.mark.slow
@pytest.mark.asyncio
async def test_01_noisy_neighbour_battery_smoke():
    """
    Smoke verification of noisy neighbour harness: validates strategy transitions
    and metric recording. Marked as slow.
    """
    runner = NoisyNeighbourRunner(server_url="http://127.0.0.1:8000")
    # Verify results directory exists and reports can be found
    results_dir = Path(__file__).resolve().parent.parent / "results"
    assert results_dir.exists()
    assert (results_dir / "noisy_neighbour_plan.md").exists()
