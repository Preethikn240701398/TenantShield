"""
Pytest Fixtures for TenantShield
================================
Provides a configured TestClient for API integration testing.
"""

import os
import pytest
from fastapi.testclient import TestClient

# Ensure environment is set to testing before settings load
os.environ["ENVIRONMENT"] = "testing"
os.environ["DEBUG"] = "false"

from app.main import app


@pytest.fixture(scope="session")
def client() -> TestClient:
    """
    Returns a synchronous TestClient bound to the FastAPI application.
    """
    with TestClient(app) as test_client:
        yield test_client
