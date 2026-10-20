from datetime import datetime, timezone, timedelta
from soc_analyst.agents.soc_analyst import SOCAnalystAgent
from soc_analyst.models.schemas import SecurityAlert

agent = SOCAnalystAgent()
now = datetime.now(timezone.utc)

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

a1 = agent.analyze_alert(alert1)
a2 = agent.analyze_alert(alert2)
a3 = agent.analyze_alert(alert3)

print("A1 Indicators:", a1.indicators)
print("A2 Indicators:", a2.indicators)
print("A3 Indicators:", a3.indicators)

report = agent.generate_incident_report([a1, a2, a3], "Test Incident")
print("\n--- THREAT INTEL SUMMARY ---")
print(report.threat_intel_summary)
