"""Unit tests for the Alert Correlation service."""

from datetime import datetime, timedelta

from soc_analyst.models.schemas import SecurityAlert, Severity
from soc_analyst.services.correlation import AlertCorrelator


def test_correlate_no_alerts():
    assert AlertCorrelator.correlate([]) == []


def test_correlate_by_source_ip():
    now = datetime.utcnow()
    alert1 = SecurityAlert(
        id="a1",
        timestamp=now,
        rule_description="SSH login failed",
        rule_level=5,
        source_ip="192.168.1.10",
        agent_name="server-a",
    )
    alert2 = SecurityAlert(
        id="a2",
        timestamp=now + timedelta(minutes=5),
        rule_description="Web exploitation attempt",
        rule_level=7,
        source_ip="192.168.1.10",
        agent_name="server-b",
    )
    # These share source IP and should correlate
    incidents = AlertCorrelator.correlate([alert1, alert2])
    assert len(incidents) == 1
    assert len(incidents[0].alerts) == 2
    assert incidents[0].common_ip == "192.168.1.10"
    assert incidents[0].severity == Severity.MEDIUM


def test_correlate_by_agent_time():
    now = datetime.utcnow()
    alert1 = SecurityAlert(
        id="a1",
        timestamp=now,
        rule_description="SSH login failed",
        rule_level=5,
        agent_name="server-a",
        username="user1",
    )
    alert2 = SecurityAlert(
        id="a2",
        timestamp=now + timedelta(minutes=30),
        rule_description="Privilege escalation",
        rule_level=12,
        agent_name="server-a",
        username="user2",
    )
    # These occur on the same agent within the 2 hour window
    incidents = AlertCorrelator.correlate([alert1, alert2])
    assert len(incidents) == 1
    assert len(incidents[0].alerts) == 2
    assert incidents[0].common_agent == "server-a"
    assert incidents[0].severity == Severity.CRITICAL


def test_correlate_independent():
    now = datetime.utcnow()
    alert1 = SecurityAlert(
        id="a1",
        timestamp=now,
        rule_description="SSH login failed",
        rule_level=5,
        source_ip="192.168.1.5",
        agent_name="server-a",
    )
    alert2 = SecurityAlert(
        id="a2",
        timestamp=now + timedelta(hours=3),
        rule_description="Malware download",
        rule_level=10,
        source_ip="10.0.0.5",
        agent_name="server-b",
    )
    # Different hosts, different IPs, time difference > 2 hours -> should not correlate
    incidents = AlertCorrelator.correlate([alert1, alert2])
    assert len(incidents) == 2


def test_live_alerts_not_correlated_with_demo_alerts():
    now = datetime.utcnow()
    alert1 = SecurityAlert(
        id="demo-001",
        timestamp=now,
        rule_description="SSH brute force attempt",
        rule_level=10,
        agent_name="web-server-01",
        source_ip="203.0.113.45",
        username="admin"
    )
    alert2 = SecurityAlert(
        id="live-100",
        timestamp=now + timedelta(minutes=5),
        rule_description="Successful SSH connection",
        rule_level=5,
        agent_name="web-server-01",
        source_ip="203.0.113.45",
        username="admin"
    )
    
    # Even though they share agent_name, source_ip, username, and time window,
    # because alert1 is a demo alert and alert2 is a live alert, they must not correlate.
    incidents = AlertCorrelator.correlate([alert1, alert2])
    assert len(incidents) == 2
    assert len(incidents[0].alerts) == 1
    assert len(incidents[1].alerts) == 1


def test_correlation_transitive_chain_split():
    now = datetime.utcnow()
    alerts = [
        SecurityAlert(id=f"live-{i}", timestamp=now + timedelta(hours=i), rule_description="Test alert", agent_name="host-1")
        for i in range(5)
    ]
    
    incidents = AlertCorrelator.correlate(alerts, time_window_seconds=7200)
    
    # Verify that the chain is broken down so no single incident spans > 2 hours
    for inc in incidents:
        timestamps = [a.timestamp for a in inc.alerts]
        duration = (max(timestamps) - min(timestamps)).total_seconds()
        assert duration <= 7200


def test_correlate_windows_openssh_bruteforce_no_ip():
    now = datetime.utcnow()
    alert1 = SecurityAlert(
        id="ssh-fail-1",
        timestamp=now,
        rule_id="100060",
        rule_description="Windows OpenSSH: Authentication failure",
        rule_level=5,
        agent_name="navu-pc",
        agent_ip="192.168.31.28",
        source_ip="",
        username="administrator",
    )
    alert2 = SecurityAlert(
        id="ssh-bf-1",
        timestamp=now + timedelta(seconds=30),
        rule_id="100061",
        rule_description="Windows OpenSSH: Multiple authentication failures (brute-force)",
        rule_level=10,
        agent_name="navu-pc",
        agent_ip="192.168.31.28",
        source_ip="",
        username="administrator",
    )
    incidents = AlertCorrelator.correlate([alert1, alert2])
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.common_agent == "navu-pc"
    assert inc.common_ip is None  # Ensures host IP is NOT treated as attacker IP
    assert inc.common_user == "administrator"
    assert inc.overall_severity == Severity.HIGH
    assert "T1110" in inc.combined_mitre_techniques



