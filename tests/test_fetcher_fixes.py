"""Tests for LiveAlertFetcher cursor advancement, checkpoint persistence, and AlertProcessor caching."""

import json
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
import pytest

from soc_analyst.models.schemas import SecurityAlert, AlertAnalysis, Severity
from soc_analyst.services.live_alert_fetcher import LiveAlertFetcher
from soc_analyst.services.alert_processor import AlertProcessor


def test_cursor_advances_even_when_all_alerts_are_processed(tmp_path):
    """Verify that if search returns hits that are already in _processed_ids, the cursor still advances to prevent freeze."""
    checkpoint_file = tmp_path / "fetcher_checkpoint.json"
    fetcher = LiveAlertFetcher(checkpoint_path=checkpoint_file)
    
    t0 = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 8, 28, 10, 5, 0, tzinfo=timezone.utc)
    
    fetcher._last_processed_timestamp = t0
    fetcher.client = MagicMock()
    
    # Mock search returning a hit at t1
    fetcher.client.search.return_value = {
        "hits": {
            "hits": [
                {
                    "_id": "hit-101",
                    "_source": {
                        "id": "hit-101",
                        "timestamp": t1.isoformat(),
                        "rule": {"id": "100060", "level": 5, "description": "SSH failed"},
                        "agent": {"name": "navu-pc", "ip": "192.168.1.5"},
                        "data": {"srcip": "10.0.0.1"}
                    }
                }
            ]
        }
    }
    
    # Mark hit-101 as already processed
    fetcher._processed_ids.add("hit-101")
    
    # Call fetch_new_alerts
    import asyncio
    new_alerts = asyncio.run(fetcher.fetch_new_alerts())
    
    assert len(new_alerts) == 0
    # Crucial assertion: timestamp must have advanced to t1 even though hit was duplicate
    assert fetcher._last_processed_timestamp == t1
    
    # Check that checkpoint file on disk was updated
    assert checkpoint_file.exists()
    saved_data = json.loads(checkpoint_file.read_text(encoding="utf-8"))
    assert saved_data["last_processed_timestamp"] == t1.isoformat()
    assert "hit-101" in saved_data["processed_ids"]


def test_checkpoint_loaded_on_restart(tmp_path):
    """Verify that a new LiveAlertFetcher instance loads saved checkpoint and does not re-poll from default lookback."""
    checkpoint_file = tmp_path / "fetcher_checkpoint.json"
    t_saved = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)
    
    checkpoint_file.write_text(json.dumps({
        "last_processed_timestamp": t_saved.isoformat(),
        "processed_ids": ["hit-saved-1", "hit-saved-2"]
    }), encoding="utf-8")
    
    fetcher = LiveAlertFetcher(checkpoint_path=checkpoint_file)
    assert fetcher._last_processed_timestamp == t_saved
    assert "hit-saved-1" in fetcher._processed_ids
    assert "hit-saved-2" in fetcher._processed_ids


def test_alert_processor_does_not_reanalyze_cached_alert(tmp_path):
    """Verify AlertProcessor returns cached analysis without re-invoking the LLM agent."""
    processor = AlertProcessor()
    
    alert = SecurityAlert(
        id="alert-cached-test-01",
        timestamp=datetime.now(timezone.utc),
        rule_id="100060",
        rule_description="SSH auth failure",
        rule_level=5,
        agent_name="navu-pc",
        agent_ip="192.168.1.5",
        source_ip="10.0.0.2",
        full_log="Failed password"
    )
    
    mock_analysis = AlertAnalysis(
        alert_id=alert.id,
        summary="Cached summary",
        threat_explanation="Cached threat",
        attack_narrative="Cached narrative",
        severity=Severity.MEDIUM,
        priority_score=60.0,
    )
    
    # Pre-populate cache
    processor._analysis_cache[alert.id] = mock_analysis
    
    mock_agent = MagicMock()
    processor._agent = mock_agent
    
    import asyncio
    result = asyncio.run(processor.analyze_single(alert))
    # Ensure agent.analyze_alert was never called
    mock_agent.analyze_alert.assert_not_called()
    assert result.summary == "Cached summary"
    assert result.alert_id == alert.id
