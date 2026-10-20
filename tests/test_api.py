"""Integration tests for the FastAPI API."""

from unittest.mock import patch, MagicMock
import pytest
from fastapi.testclient import TestClient
from soc_analyst.api.app import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def mock_llm():
    with patch("soc_analyst.agents.soc_analyst.get_llm") as mock_get:
        mock_model = MagicMock()
        mock_model.invoke.side_effect = Exception("Mock LLM offline")
        mock_get.return_value = mock_model
        yield mock_model


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "llm_provider" in data
    assert "elasticsearch" in data


def test_settings_endpoint():
    response = client.get("/api/settings")
    assert response.status_code == 200
    data = response.json()
    assert "llm_provider" in data
    assert "elasticsearch_host" in data


def test_demo_analyze_endpoint():
    response = client.post("/demo/analyze")
    assert response.status_code == 200
    data = response.json()
    assert "analyses" in data
    assert "incident_report_markdown" in data
    assert len(data["analyses"]) == 3
    # Check that ioc_extractor successfully enriched indicators in fallback
    for analysis in data["analyses"]:
        assert len(analysis["indicators"]) > 0


def test_chat_endpoint_fallback():
    # Test fallback chat with a demo alert
    response = client.post(
        "/chat",
        json={"message": "How do I remediate this threat?", "alert_id": "demo-001"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "response" in data
    assert "remediate" in data["response"] or "block" in data["response"].lower()


def test_ioc_enrich_endpoint():
    response = client.get("/api/iocs/enrich?value=203.0.113.45")
    assert response.status_code == 200
    data = response.json()
    assert data["value"] == "203.0.113.45"
    assert "reputation" in data
    assert "source" in data


def test_incident_status_update_endpoint():
    # Trigger demo analysis first to seed the cache
    client.post("/demo/analyze")
    
    # Get correlated incidents
    response = client.get("/incidents/correlated")
    assert response.status_code == 200
    incidents = response.json()["incidents"]
    assert len(incidents) > 0
    inc_id = incidents[0]["incident_id"]
    
    # Update status
    update_resp = client.post(f"/api/incidents/{inc_id}/status", json={"status": "Investigating"})
    assert update_resp.status_code == 200
    assert update_resp.json()["status"] == "success"
    
    # Verify status in get list
    verify_resp = client.get("/incidents/correlated")
    new_incidents = verify_resp.json()["incidents"]
    matching = next((i for i in new_incidents if i["incident_id"] == inc_id), None)
    assert matching is not None
    assert matching["status"] == "Investigating"


def test_demo_reset_endpoint():
    # Seed the cache
    client.post("/demo/analyze")
    # Verify cached incidents exist
    resp = client.get("/incidents/correlated")
    assert len(resp.json()["incidents"]) > 0
    
    # Call reset
    reset_resp = client.post("/demo/reset")
    assert reset_resp.status_code == 200
    assert reset_resp.json()["status"] == "success"
