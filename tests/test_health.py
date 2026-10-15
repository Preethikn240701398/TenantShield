"""
TenantShield - Health and System Endpoint Tests
===============================================
Verifies operational availability of base endpoints:
- GET /
- GET /health
"""

from fastapi.testclient import TestClient


def test_root_endpoint(client: TestClient) -> None:
    """
    Test that the root endpoint returns 200 OK and valid service metadata.
    """
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "TenantShield"
    assert data["status"] == "online"
    assert "version" in data
    assert "docs_url" in data


def test_health_endpoint(client: TestClient) -> None:
    """
    Test that the health endpoint returns 200 OK, accurately reports
    overall status based on database connectivity, and provides component status.
    """
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "timestamp" in data
    assert "components" in data
    assert data["components"]["api"] == "healthy"
    assert "database" in data["components"]

    db_info = data["components"]["database"]
    assert "status" in db_info

    # Health endpoint must not claim healthy if database is unavailable
    if db_info["status"] == "connected":
        assert data["status"] == "healthy"
    else:
        assert data["status"] == "degraded"
