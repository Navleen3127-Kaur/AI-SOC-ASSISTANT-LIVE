"""Unit tests for the report generator."""

from datetime import datetime
from soc_analyst.services.report_generator import render_incident_report
from soc_analyst.models.schemas import (
    IncidentReport,
    AlertAnalysis,
    Severity,
    MitreMapping,
    RemediationStep
)


def test_render_incident_report():
    analysis = AlertAnalysis(
        alert_id="demo-001",
        summary="Brute force attack on web-server-01.",
        threat_explanation="Failed password attempts indicating password guessing.",
        attack_narrative="Failed logins from 203.0.113.45.",
        severity=Severity.HIGH,
        priority_score=75.0,
        mitre_mappings=[
            MitreMapping(
                technique_id="T1110",
                technique_name="Brute Force",
                tactic="Credential Access",
                confidence=0.9
            )
        ],
        indicators=["203.0.113.45"],
        affected_assets=["web-server-01"],
        remediation_steps=[
            RemediationStep(priority=1, action="Block IP", rationale="Prevent attack")
        ],
        false_positive_likelihood="low"
    )

    report = IncidentReport(
        incident_id="INC-2026-TEST",
        title="Test Security Incident",
        executive_summary="This is a test incident executive summary.",
        timeline=["2026-07-19 - Initial alerts"],
        alerts_analyzed=[analysis],
        mitre_tactics_observed=["Credential Access"],
        overall_severity=Severity.HIGH,
        containment_actions=["Isolate web-server-01"],
        eradication_actions=["Terminate rogue sessions"],
        recovery_actions=["Restore configuration"]
    )

    markdown = render_incident_report(report)
    
    assert "# AI SOC Analyst — Incident Report" in markdown
    assert "INC-2026-TEST" in markdown
    assert "Test Security Incident" in markdown
    assert "HIGH" in markdown
    assert "Credential Access" in markdown
    assert "Isolate web-server-01" in markdown
    assert "demo-001" in markdown
    assert "Brute Force" in markdown


def test_render_pdf_report():
    from soc_analyst.services.report_generator import render_pdf_report
    analysis = AlertAnalysis(
        alert_id="demo-001",
        summary="Brute force attack on web-server-01.",
        threat_explanation="Failed password attempts indicating password guessing.",
        attack_narrative="Failed logins from 203.0.113.45.",
        severity=Severity.HIGH,
        priority_score=75.0,
        mitre_mappings=[
            MitreMapping(
                technique_id="T1110",
                technique_name="Brute Force",
                tactic="Credential Access",
                confidence=0.9
            )
        ],
        indicators=["203.0.113.45"],
        affected_assets=["web-server-01"],
        remediation_steps=[
            RemediationStep(priority=1, action="Block IP", rationale="Prevent attack")
        ],
        false_positive_likelihood="low"
    )

    report = IncidentReport(
        incident_id="INC-2026-TEST-PDF",
        title="Test Security Incident PDF",
        executive_summary="This is a test incident executive summary.",
        timeline=["2026-07-19 - Initial alerts"],
        alerts_analyzed=[analysis],
        mitre_tactics_observed=["Credential Access"],
        overall_severity=Severity.HIGH,
        containment_actions=["Isolate web-server-01"],
        eradication_actions=["Terminate rogue sessions"],
        recovery_actions=["Restore configuration"]
    )

    pdf_bytes = render_pdf_report(report)
    assert len(pdf_bytes) > 0
    assert pdf_bytes.startswith(b"%PDF")
