"""Unit tests for the Alert Prioritizer."""

from datetime import datetime
from soc_analyst.agents.prioritizer import AlertPrioritizer
from soc_analyst.models.schemas import SecurityAlert, MitreMapping, Severity


def test_prioritizer_scoring():
    prioritizer = AlertPrioritizer()

    # 1. Low severity alert without MITRE mappings
    low_alert = SecurityAlert(
        id="test-001",
        timestamp=datetime.utcnow(),
        rule_id="500",
        rule_description="Successful login by user",
        rule_level=3,
        agent_name="web-01"
    )
    score, severity = prioritizer.score(low_alert)
    assert score < 30
    assert severity in (Severity.LOW, Severity.INFO)

    # 2. Critical/High alert with critical MITRE mappings and IPs
    high_alert = SecurityAlert(
        id="test-002",
        timestamp=datetime.utcnow(),
        rule_id="800",
        rule_description="Ransomware shadow copy deletion",
        rule_level=14,
        agent_name="db-01",
        source_ip="192.168.1.100",
        destination_ip="192.168.1.200"
    )
    mitre_mappings = [
        MitreMapping(
            technique_id="T1486",
            technique_name="Data Encrypted for Impact",
            tactic="Impact",
            confidence=0.9
        )
    ]
    score_high, severity_high = prioritizer.score(high_alert, mitre_mappings)
    assert score_high > score
    assert score_high >= 60
    assert severity_high in (Severity.HIGH, Severity.CRITICAL)


def test_rank_alerts():
    prioritizer = AlertPrioritizer()
    now = datetime.utcnow()
    
    alert_1 = SecurityAlert(id="a1", timestamp=now, rule_level=2, rule_description="Low level log")
    alert_2 = SecurityAlert(id="a2", timestamp=now, rule_level=15, rule_description="Critical log", source_ip="10.0.0.1")
    
    ranked = prioritizer.rank_alerts([alert_1, alert_2])
    assert len(ranked) == 2
    assert ranked[0][0].id == "a2"  # Higher rule level should rank first
    assert ranked[1][0].id == "a1"
