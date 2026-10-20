from datetime import datetime, timezone, timedelta
from soc_analyst.agents.soc_analyst import SOCAnalystAgent
from soc_analyst.models.schemas import SecurityAlert, Severity, RemediationStep
from soc_analyst.services.report_generator import render_incident_report, render_pdf_report


def test_incident_pipeline_explainability_and_scoring():
    agent = SOCAnalystAgent()
    now = datetime.now(timezone.utc)

    # 1. Prepare multiple alerts with offset timestamps to represent a kill chain
    alert1 = SecurityAlert(
        id="demo-001",
        timestamp=now - timedelta(minutes=15),
        rule_id="5710",
        rule_description="Multiple authentication failures",
        rule_level=10,
        agent_name="web-server-01",
        agent_ip="10.0.1.15",
        source_ip="203.0.113.45",
        username="admin",
        full_log="Failed SSH login attempt count limit exceeded for user admin"
    )

    alert2 = SecurityAlert(
        id="demo-002",
        timestamp=now - timedelta(minutes=10),
        rule_id="92002",
        rule_description="Suspicious PowerShell command detected",
        rule_level=12,
        agent_name="web-server-01",
        agent_ip="10.0.1.15",
        source_ip="203.0.113.45",
        username="admin",
        full_log="powershell.exe -EncodedCommand SQBFAFgA"
    )

    alert3 = SecurityAlert(
        id="demo-003",
        timestamp=now - timedelta(minutes=5),
        rule_id="87105",
        rule_description="Possible ransomware activity - shadow copy deletion",
        rule_level=15,
        agent_name="web-server-01",
        agent_ip="10.0.1.15",
        source_ip="203.0.113.45",
        username="SYSTEM",
        full_log="vssadmin.exe Delete Shadows /All /Quiet"
    )

    # Analyze alerts separately
    a1 = agent.analyze_alert(alert1)
    a2 = agent.analyze_alert(alert2)
    a3 = agent.analyze_alert(alert3)

    # Generate correlated incident report
    report = agent.generate_incident_report([a1, a2, a3], "Multi-stage Ransomware Intrusion Campaign")

    print("DEBUG a1.summary:", repr(a1.summary))
    print("DEBUG a1.log_summary:", repr(a1.log_summary))
    print("DEBUG a2.summary:", repr(a2.summary))
    print("DEBUG a2.log_summary:", repr(a2.log_summary))
    print("DEBUG a3.summary:", repr(a3.summary))
    print("DEBUG a3.log_summary:", repr(a3.log_summary))
    print("DEBUG report.ai_decision_reasoning:", report.ai_decision_reasoning)
    print("DEBUG report.risk_score:", report.risk_score)
    print("DEBUG report.risk_breakdown:", report.risk_breakdown)

    # 2. Assert explainability and scoring engines
    # Confidence Score & Level
    assert report.confidence_score >= 80.0
    assert report.confidence_level in ["High", "Very High"]
    assert "Rule Severity Weight" in report.confidence_breakdown
    assert "IOC Reputation Weight" in report.confidence_breakdown

    # Risk Score & Breakdown
    assert report.risk_score >= 80.0
    assert "MITRE Impact" in report.risk_breakdown
    assert "Critical Asset" in report.risk_breakdown

    # Correlation Score & Breakdown
    assert report.correlation_score >= 80.0
    assert any("IP" in r or "host" in r.lower() for r in report.correlation_breakdown)

    # Decision Reasoning Checkboxes
    assert any("SSH" in r or "logins" in r for r in report.ai_decision_reasoning)
    assert any("PowerShell" in r or "EncodedCommand" in r for r in report.ai_decision_reasoning)
    assert any("copies" in r or "shadow" in r.lower() for r in report.ai_decision_reasoning)

    # Chronological Timeline Order check
    # Check that demo-001 is first, demo-002 second, demo-003 third
    assert len(report.timeline) == 3
    assert "demo-001" in report.timeline[0]
    assert "demo-002" in report.timeline[1]
    assert "demo-003" in report.timeline[2]

    # Threat Intelligence Summary formatting (No python raw list formatting like "['10.0.1.15']")
    assert "•" in report.threat_intel_summary or "-" in report.threat_intel_summary
    assert "['" not in report.threat_intel_summary
    assert "']" not in report.threat_intel_summary
    assert "External IP" in report.threat_intel_summary

    # Safe Internal IP Reputation
    assert "Internal asset involved in suspicious activity" in report.threat_intel_summary

    # MITRE ATT&CK Mappings check
    mapped_techniques = [m.technique_id for a in report.alerts_analyzed for m in a.mitre_mappings]
    assert "T1110" in mapped_techniques
    assert "T1059.001" in mapped_techniques
    assert "T1490" in mapped_techniques
    assert not any(t.startswith("TA") for t in mapped_techniques)

    # Recommendations and Conclusion
    assert len(report.executive_recommendations) > 0
    assert "high-confidence ransomware attack" in report.analyst_conclusion.lower()

    # Report Metadata
    assert report.report_version == "2.3"
    assert report.generated_by == "AI SOC Analyst"
    assert report.report_type == "Incident Investigation Summary"
    assert report.execution_mode in ["Offline Demo", "Live Production", "Replay Demo"]

    # Executive Metrics
    assert report.total_alerts_analyzed == 3
    assert report.correlated_alerts_count == 3
    assert report.affected_hosts_count in [1, 3]
    assert report.affected_users_count >= 1
    assert report.critical_assets_count in [1, 3]
    assert report.false_positive_probability == "Low"
    assert report.threat_intel_hits >= 1
    assert report.mitre_techniques_count == 4

    # Attack Progression Kill Chain
    assert len(report.attack_progression) >= 3
    assert "Credential Access" in report.attack_progression[0]

    # 3. Export formatting verification
    # Markdown Rendering
    md = render_incident_report(report)
    assert "# AI SOC Analyst — Incident Report" in md
    assert "Report Metadata" in md
    assert "Executive Report Metrics" in md
    assert "Cyber Kill Chain - Attack Progression" in md

    # PDF Rendering (Checks that no unicode / formatting crashes happen)
    pdf = render_pdf_report(report)
    assert len(pdf) > 0
    assert pdf.startswith(b"%PDF")


def test_incident_pipeline_reputation_scoring():
    from unittest.mock import patch
    from soc_analyst.services.ioc_extractor import IOCOxtractor
    
    agent = SOCAnalystAgent()
    now = datetime.now(timezone.utc)
    
    alert = SecurityAlert(
        id="test-rep-alert",
        timestamp=now,
        rule_id="5000",
        rule_description="Suspicious connection",
        rule_level=5,
        agent_name="test-server",
        agent_ip="10.0.1.15",
        source_ip="8.8.8.8",
        full_log="Connection from 8.8.8.8"
    )
    
    # 1. Test with clean/harmless reputation
    with patch.object(IOCOxtractor, "enrich_ioc") as mock_enrich:
        mock_enrich.return_value = {
            "value": "8.8.8.8",
            "type": "External IP",
            "source": "Mock",
            "reputation": "harmless",
            "confidence_score": 0.0,
            "categories": [],
            "detection_stats": "Clean",
            "details": "Clean IP"
        }
        
        analysis = agent.analyze_alert(alert)
        report_harmless = agent.generate_incident_report([analysis], "Incident with clean IP")
        
        # 2. Test with malicious reputation (on the exact same IP string "8.8.8.8")
        mock_enrich.return_value = {
            "value": "8.8.8.8",
            "type": "External IP",
            "source": "Mock",
            "reputation": "malicious",
            "confidence_score": 95.0,
            "categories": ["C2"],
            "detection_stats": "Malicious",
            "details": "C2 IP"
        }
        
        analysis = agent.analyze_alert(alert)
        report_malicious = agent.generate_incident_report([analysis], "Incident with malicious IP")
        
        # Verify that the malicious reputation contributes to confidence/risk scoring,
        # whereas the clean reputation does not, even though the IOC string ("8.8.8.8") is identical.
        assert report_malicious.confidence_score > report_harmless.confidence_score
        assert report_malicious.risk_score > report_harmless.risk_score
        # Check that the reasoning engine picked up the malicious reputation
        assert any("malicious reputation" in r.lower() for r in report_malicious.ai_decision_reasoning)
        assert not any("malicious reputation" in r.lower() for r in report_harmless.ai_decision_reasoning)


def test_live_incident_reports_mode():
    agent = SOCAnalystAgent()
    now = datetime.now(timezone.utc)
    
    alert = SecurityAlert(
        id="live-12345",
        timestamp=now,
        rule_id="5000",
        rule_description="Suspicious activity",
        rule_level=5,
        agent_name="live-server",
        agent_ip="10.0.1.15",
        source_ip="8.8.8.8",
        full_log="Live production alert log content"
    )
    
    analysis = agent.analyze_alert(alert)
    report = agent.generate_incident_report([analysis], "Live Security Incident")
    
    assert report.execution_mode == "Live"
    assert report.execution_mode != "Offline Demo"


def test_three_unique_techniques_count():
    agent = SOCAnalystAgent()
    now = datetime.now(timezone.utc)
    
    alert1 = SecurityAlert(
        id="demo-t1",
        timestamp=now - timedelta(minutes=15),
        rule_description="brute force SSH password guess",
        full_log="failed login attempts"
    )
    alert2 = SecurityAlert(
        id="demo-t2",
        timestamp=now - timedelta(minutes=10),
        rule_description="suspicious powershell command line executed",
        full_log="powershell.exe -encodedcommand"
    )
    alert3 = SecurityAlert(
        id="demo-t3",
        timestamp=now - timedelta(minutes=5),
        rule_description="mimikatz credentials dump lsass dump",
        full_log="mimikatz.exe sekurlsa"
    )
    
    a1 = agent.analyze_alert(alert1)
    a2 = agent.analyze_alert(alert2)
    a3 = agent.analyze_alert(alert3)
    
    report = agent.generate_incident_report([a1, a2, a3], "Test MITRE Count Incident")
    
    assert report.mitre_techniques_count == 3


def test_benign_vs_suspicious_powershell():
    agent = SOCAnalystAgent()
    now = datetime.now(timezone.utc)

    # 1. Benign PowerShell command
    benign_alert = SecurityAlert(
        id="demo-benign-ps",
        timestamp=now,
        rule_id="92001",
        rule_description="Legitimate system query via PowerShell",
        rule_level=4,
        agent_name="navu-pc",
        full_log="powershell.exe Get-Process"
    )
    a_benign = agent.analyze_alert(benign_alert)
    report_benign = agent.generate_incident_report([a_benign], "Benign PowerShell Query")

    # 2. Suspicious PowerShell command (e.g. EncodedCommand)
    suspicious_alert = SecurityAlert(
        id="demo-susp-ps",
        timestamp=now,
        rule_id="92002",
        rule_description="Suspicious encoded PowerShell command execution",
        rule_level=12,
        agent_name="web-server-01",
        full_log="powershell.exe -EncodedCommand SQBFAFgA"
    )
    a_susp = agent.analyze_alert(suspicious_alert)
    report_susp = agent.generate_incident_report([a_susp], "Suspicious PowerShell Execution")

    # Benign PowerShell must not receive a high malicious risk score simply because PowerShell was used
    assert report_benign.risk_score < report_susp.risk_score
    assert report_benign.risk_score <= 60.0
    assert report_susp.risk_score >= 70.0
    
    # Assert reasoning flags
    assert not any("PowerShell EncodedCommand" in r for r in report_benign.ai_decision_reasoning)
    assert any("PowerShell EncodedCommand" in r for r in report_susp.ai_decision_reasoning)


def test_missing_or_ambiguous_evidence():
    agent = SOCAnalystAgent()
    now = datetime.now(timezone.utc)

    ambiguous_alert = SecurityAlert(
        id="demo-ambiguous",
        timestamp=now,
        rule_id="100",
        rule_description="Generic system log activity",
        rule_level=3,
        agent_name="unknown-host",
        full_log="Some standard system informational log"
    )
    
    analysis = agent.analyze_alert(ambiguous_alert)
    report = agent.generate_incident_report([analysis], "Ambiguous activity report")
    
    assert report.risk_score <= 50.0
    assert report.overall_severity in (Severity.INFO, Severity.LOW)


def test_remediation_evidence_based():
    agent = SOCAnalystAgent()
    now = datetime.now(timezone.utc)

    # 1. Suspicious but unconfirmed file
    susp_alert = SecurityAlert(
        id="test-susp-file",
        timestamp=now,
        rule_id="92005",
        rule_description="File created in public directory",
        rule_level=5,
        agent_name="workstation-99",
        full_log="File created: C:\\Users\\Public\\Downloads\\update.exe"
    )
    analysis_susp = agent.analyze_alert(susp_alert)
    analysis_susp.remediation_steps = [
        RemediationStep(
            priority=1,
            action="Quarantine update.exe immediately.",
            rationale="The file update.exe is a malicious Trojan downloader."
        )
    ]
    filtered_susp = agent._filter_remediation_steps(analysis_susp.remediation_steps, susp_alert)
    assert len(filtered_susp) > 0
    assert "Investigate the file" in filtered_susp[0].action
    assert "quarantine the file and isolate the host" in filtered_susp[0].action
    assert "Ensure the file is truly malicious" in filtered_susp[0].rationale
    assert "Trojan" not in filtered_susp[0].rationale
    assert "is malicious" not in filtered_susp[0].action.lower()

    # 2. Confirmed malicious IOC (e.g., rule level >= 12 or high severity)
    mal_alert = SecurityAlert(
        id="test-mal-rule",
        timestamp=now,
        rule_id="92006",
        rule_description="Known ransomware activity",
        rule_level=13,
        agent_name="prod-web-01",
        full_log="vssadmin.exe Delete Shadows /All /Quiet"
    )
    analysis_mal = agent.analyze_alert(mal_alert)
    analysis_mal.remediation_steps = [
        RemediationStep(
            priority=1,
            action="Isolate prod-web-01 from network.",
            rationale="Prevent ransomware propagation."
        )
    ]
    filtered_mal = agent._filter_remediation_steps(analysis_mal.remediation_steps, mal_alert)
    assert "Isolate" in filtered_mal[0].action

    # 3. Benign activity (low rule level, benign command)
    benign_alert = SecurityAlert(
        id="test-benign-remediation",
        timestamp=now,
        rule_id="1001",
        rule_description="Administrative command execution",
        rule_level=3,
        agent_name="navu-pc",
        full_log="powershell.exe Get-Process"
    )
    analysis_benign = agent.analyze_alert(benign_alert)
    assert len(analysis_benign.remediation_steps) > 0
    assert "Investigate" in analysis_benign.remediation_steps[0].action
    assert "Perform thorough evidence-based analysis" in analysis_benign.remediation_steps[0].rationale

    # 4. Missing evidence (no logs, generic rule)
    missing_alert = SecurityAlert(
        id="test-missing-remediation",
        timestamp=now,
        rule_id="500",
        rule_description="Informational event",
        rule_level=2,
        agent_name="unknown-host",
        full_log=""
    )
    analysis_missing = agent.analyze_alert(missing_alert)
    assert len(analysis_missing.remediation_steps) > 0
    assert "Investigate" in analysis_missing.remediation_steps[0].action





