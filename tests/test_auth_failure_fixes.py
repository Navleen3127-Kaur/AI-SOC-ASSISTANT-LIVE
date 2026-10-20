import json
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from soc_analyst.agents.soc_analyst import SOCAnalystAgent
from soc_analyst.models.schemas import SecurityAlert, Severity


@pytest.fixture
def mock_llm():
    with patch("soc_analyst.agents.soc_analyst.get_llm") as mock_get:
        mock_model = MagicMock()
        mock_get.return_value = mock_model
        yield mock_model


def test_single_failed_ssh_login_insufficient_context(mock_llm):
    """
    TEST 1: Single failed SSH login with insufficient context.
    Requirements:
    - Must NOT be classified as normal, benign, or harmless.
    - Must NOT assume brute force without supporting telemetry.
    - False positive likelihood must remain 'unknown'.
    - Described neutrally as an unsuccessful authentication attempt requiring contextual assessment.
    """
    raw_payload = {
        "win": {
            "system": {
                "eventID": "4625",
                "message": "An account failed to log on.",
                "processName": "C:\\Windows\\System32\\OpenSSH\\sshd.exe",
            },
            "eventdata": {
                "subjectUserName": "NAVLEEN$",
                "failureReason": "%%2313",
                "logonType": "8",
                "processName": "C:\\Windows\\System32\\OpenSSH\\sshd.exe",
            },
        }
    }
    alert = SecurityAlert(
        id="test-ssh-single",
        timestamp=datetime.now(timezone.utc),
        rule_id="100060",
        rule_description="Windows OpenSSH: Authentication failure",
        rule_level=5,
        agent_name="navu-pc",
        agent_ip="192.168.1.50",
        username="NAVLEEN$",
        full_log=json.dumps(raw_payload),
        raw=raw_payload,
    )

    # Even if LLM erroneously outputs "normal security event"
    mock_llm.invoke.return_value.content = json.dumps({
        "summary": "The alert indicates a failed SSH login attempt, which is a normal security event.",
        "threat_explanation": "This alert is likely a false positive due to a failed SSH login attempt, which is a common and expected security event.",
        "log_summary": "User NAVLEEN$ failed to log on via OpenSSH.",
        "root_cause": "Failed SSH login attempt.",
        "attack_impact": "No observed impact as this is a normal security event.",
        "severity_assessment": "Severity level 5.",
        "confidence_score": 80.0,
        "investigation_steps": ["Verify whether the user mistyped credentials"],
        "analyst_notes": "A normal security event.",
        "attack_narrative": "A user named NAVLEEN$ attempted to log in via SSH but failed due to an incorrect password. This is a normal security event and not indicative of a malicious activity.",
        "indicators": [],
        "affected_assets": ["navu-pc"],
        "remediation_steps": [],
        "false_positive_likelihood": "low",
        "recommended_next_steps": ["Check user credentials"],
        "suggested_mitre_techniques": ["T1110"],
    })

    agent = SOCAnalystAgent()
    analysis = agent.analyze_alert(alert)

    # Assertions
    assert "normal security event" not in analysis.summary.lower()
    assert "normal security event" not in analysis.threat_explanation.lower()
    assert "normal security event" not in analysis.attack_narrative.lower()
    assert "benign" not in analysis.summary.lower()
    assert "harmless" not in analysis.summary.lower()
    assert analysis.false_positive_likelihood == "unknown"
    assert "unsuccessful" in analysis.summary.lower() or "failed" in analysis.summary.lower()
    assert "inconclusive" in analysis.threat_explanation.lower() or "investigation" in analysis.threat_explanation.lower()


def test_multiple_failed_ssh_logins_brute_force(mock_llm):
    """
    TEST 2: Multiple failed SSH logins that may indicate brute force.
    Requirements:
    - Supporting telemetry indicates repeated failures / brute force.
    - Assessment reflects potential brute-force / credential guessing.
    - Does not declare normal or benign.
    """
    alert = SecurityAlert(
        id="test-ssh-multi",
        timestamp=datetime.now(timezone.utc),
        rule_id="100061",
        rule_description="Windows OpenSSH: Multiple authentication failures (brute-force)",
        rule_level=10,
        agent_name="navu-pc",
        agent_ip="192.168.1.50",
        source_ip="203.0.113.45",
        username="admin",
        full_log="Multiple failed SSH login attempts detected from 203.0.113.45 targeting user admin within 60 seconds.",
    )

    mock_llm.invoke.return_value.content = json.dumps({
        "summary": "Multiple failed SSH login attempts detected from external IP 203.0.113.45 targeting user admin.",
        "threat_explanation": "Rapid repeated authentication failures from an external source indicate potential brute force or credential guessing.",
        "log_summary": "Repeated failed logins for user admin from 203.0.113.45.",
        "root_cause": "Multiple failed SSH authentication attempts in a short timeframe.",
        "attack_impact": "Risk of unauthorized access if credentials are breached.",
        "severity_assessment": "High severity rule level 10 due to rapid frequency.",
        "confidence_score": 90.0,
        "investigation_steps": ["Inspect source IP reputation", "Check if any login succeeded"],
        "analyst_notes": "Repeated failures observed from external IP.",
        "attack_narrative": "Multiple failed logon events from 203.0.113.45 targeting admin indicate automated or brute force testing.",
        "indicators": ["203.0.113.45"],
        "affected_assets": ["navu-pc"],
        "remediation_steps": [{"priority": 1, "action": "Block 203.0.113.45 at firewall", "rationale": "Prevent further attempts"}],
        "false_positive_likelihood": "low",
        "recommended_next_steps": ["Monitor host"],
        "suggested_mitre_techniques": ["T1110"],
    })

    agent = SOCAnalystAgent()
    analysis = agent.analyze_alert(alert)

    assert "normal" not in analysis.summary.lower()
    assert "brute" in analysis.threat_explanation.lower() or "brute" in analysis.summary.lower()
    assert "203.0.113.45" in analysis.indicators or "203.0.113.45" in analysis.summary


def test_failed_login_followed_by_successful_login(mock_llm):
    """
    TEST 3: Failed login followed by a successful login when correlated evidence is available.
    Requirements:
    - Identifies the potential credential validation / unauthorized access risk.
    - Recommends immediate verification of post-logon activity.
    """
    alert = SecurityAlert(
        id="test-ssh-fail",
        timestamp=datetime.now(timezone.utc),
        rule_id="100060",
        rule_description="Windows OpenSSH: Authentication failure",
        rule_level=5,
        agent_name="navu-pc",
        username="admin",
        full_log="Failed password for admin via sshd from 192.168.1.105 port 55432.",
    )
    related_success = SecurityAlert(
        id="test-ssh-success",
        timestamp=datetime.now(timezone.utc),
        rule_id="100062",
        rule_description="Windows OpenSSH: Successful logon",
        rule_level=3,
        agent_name="navu-pc",
        username="admin",
        full_log="Accepted password for admin from 192.168.1.105 port 55432 ssh2. EventID 4624 status 0x0.",
    )

    mock_llm.invoke.return_value.content = json.dumps({
        "summary": "Failed authentication attempt followed by a successful login for user admin.",
        "threat_explanation": "An initial login failure was followed by an accepted password from the same source.",
        "log_summary": "Failed login followed by accepted password for admin.",
        "root_cause": "Authentication attempt followed by successful logon.",
        "attack_impact": "Potential system access established.",
        "severity_assessment": "Moderate severity due to successful post-failure logon.",
        "confidence_score": 85.0,
        "investigation_steps": ["Review commands executed after successful logon"],
        "analyst_notes": "Correlated success detected.",
        "attack_narrative": "A failed login was followed by a successful session for admin.",
        "indicators": [],
        "affected_assets": ["navu-pc"],
        "remediation_steps": [],
        "false_positive_likelihood": "unknown",
        "recommended_next_steps": ["Audit post-logon process activity"],
        "suggested_mitre_techniques": ["T1110"],
    })

    agent = SOCAnalystAgent()
    analysis = agent.analyze_alert(alert, related_events=[related_success])

    assert "normal" not in analysis.summary.lower()
    assert "successful" in analysis.threat_explanation.lower() or "successful" in analysis.summary.lower()
    assert "normal security event" not in analysis.attack_narrative.lower()


def test_verified_benign_event_with_supporting_evidence(mock_llm):
    """
    TEST 4: Known benign event with supporting evidence.
    Requirements:
    - If explicit verified benign context is present (e.g. authorized internal vulnerability scan),
      the assessment accurately explains the verified benign operational context without hallucinating attacks.
    """
    alert = SecurityAlert(
        id="test-ssh-scan",
        timestamp=datetime.now(timezone.utc),
        rule_id="100060",
        rule_description="Windows OpenSSH: Authentication failure",
        rule_level=5,
        agent_name="navu-pc",
        source_ip="192.168.1.200",
        username="scanner_service",
        full_log="Failed password for scanner_service from 192.168.1.200. Note: Scheduled authorized vulnerability scan in progress.",
    )

    mock_llm.invoke.return_value.content = json.dumps({
        "summary": "Authentication failure observed during scheduled authorized vulnerability scan.",
        "threat_explanation": "The failure originated from internal scanner 192.168.1.200 during an authorized vulnerability scan exercise.",
        "log_summary": "Failed login for scanner_service from authorized scanning appliance.",
        "root_cause": "Scheduled authorized vulnerability scan testing SSH authentication endpoints.",
        "attack_impact": "No malicious impact; planned operational test.",
        "severity_assessment": "Low risk due to documented testing authorization.",
        "confidence_score": 90.0,
        "investigation_steps": ["Confirm scanner schedule with security operations"],
        "analyst_notes": "Matches scheduled vulnerability assessment window.",
        "attack_narrative": "Failed login occurred in correlation with an approved internal vulnerability scan.",
        "indicators": ["192.168.1.200"],
        "affected_assets": ["navu-pc"],
        "remediation_steps": [],
        "false_positive_likelihood": "high",
        "recommended_next_steps": ["Verify scanning window closure"],
        "suggested_mitre_techniques": [],
    })

    agent = SOCAnalystAgent()
    analysis = agent.analyze_alert(alert)

    assert "authorized vulnerability scan" in analysis.threat_explanation.lower() or "authorized vulnerability scan" in analysis.summary.lower()
    assert "normal security event" not in analysis.summary.lower()


def test_insufficient_telemetry_inconclusive(mock_llm):
    """
    TEST 5: Alert with insufficient telemetry (missing source IP, workstation, username).
    Requirements:
    - Explicitly states that the activity is inconclusive and needs investigation.
    - Does NOT claim definitely benign or definitely malicious.
    - False-positive likelihood remains 'unknown'.
    """
    alert = SecurityAlert(
        id="test-ssh-missing-data",
        timestamp=datetime.now(timezone.utc),
        rule_id="100060",
        rule_description="Windows OpenSSH: Authentication failure",
        rule_level=5,
        agent_name="navu-pc",
        source_ip="",
        username="",
        full_log="An account failed to log on. Source IP: - Workstation: - User: - Failure Reason: Unknown.",
    )

    mock_llm.invoke.return_value.content = json.dumps({
        "summary": "A failed SSH authentication attempt was detected, which is a normal security event.",
        "threat_explanation": "Failed logins happen frequently and are normal.",
        "log_summary": "Logon failed with missing parameters.",
        "root_cause": "Failed logon.",
        "attack_impact": "None.",
        "severity_assessment": "Low severity.",
        "confidence_score": 50.0,
        "investigation_steps": ["Check security event logs for complete event 4625"],
        "analyst_notes": "Missing fields.",
        "attack_narrative": "Logon failed for unknown user. This is a normal security event.",
        "indicators": [],
        "affected_assets": ["navu-pc"],
        "remediation_steps": [],
        "false_positive_likelihood": "high",
        "recommended_next_steps": ["Inspect Windows Event log"],
        "suggested_mitre_techniques": [],
    })

    agent = SOCAnalystAgent()
    analysis = agent.analyze_alert(alert)

    # Must be corrected by the guardrail
    assert "normal security event" not in analysis.summary.lower()
    assert "normal security event" not in analysis.attack_narrative.lower()
    assert analysis.false_positive_likelihood == "unknown"
    assert "inconclusive" in analysis.threat_explanation.lower() or "investigation" in analysis.threat_explanation.lower()
