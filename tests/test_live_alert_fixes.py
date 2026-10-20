import pytest
import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
from soc_analyst.agents.soc_analyst import SOCAnalystAgent
from soc_analyst.models.schemas import SecurityAlert, Severity

@pytest.fixture
def mock_llm_response():
    with patch("soc_analyst.agents.soc_analyst.get_llm") as mock_get:
        mock_model = MagicMock()
        mock_get.return_value = mock_model
        yield mock_model

def test_live_alert_fixes_a(mock_llm_response):
    """
    TEST A:
    Sysmon Event ID 11
    targetFilename: C:\\Users\\user\\AppData\\Local\\Temp\\test.exe
    Expected:
    - Summary mentions the Temp path accurately.
    - Must NOT say Windows root folder.
    - Must NOT claim execution.
    - Must not invent malware status.
    """
    raw_data = {"data":{"win":{"eventdata":{"image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","targetFilename":"C:\\Users\\user\\AppData\\Local\\Temp\\test.exe","processId":"4152","user":"NAVLEEN\\navle","ruleName":"EXE"},"system":{"eventID":"11"}}}}
    agent = SOCAnalystAgent()
    alert = SecurityAlert(
        id="test-a-alert",
        timestamp=datetime.now(timezone.utc),
        rule_id="92213",
        rule_description="Executable file dropped in folder commonly used by malware",
        rule_level=15,
        agent_name="navu-pc",
        agent_ip="192.168.31.28",
        full_log=json.dumps(raw_data),
        raw=raw_data
    )
    
    mock_llm_response.invoke.return_value.content = """{
        "summary": "PowerShell created an executable file named test.exe in the user's Temp directory.",
        "threat_explanation": "Wazuh rule 92213 classified this behavior as suspicious because executable files were created in a location commonly associated with malware activity. The alert alone does not prove that the executable is malicious.",
        "log_summary": "powershell.exe created C:\\\\Users\\\\user\\\\AppData\\\\Local\\\\Temp\\\\test.exe",
        "root_cause": "A PowerShell process initiated the file creation.",
        "attack_impact": "Unconfirmed threat presence.",
        "severity_assessment": "Detection severity is Critical because Wazuh rule 92213 is configured at level 15. This does not by itself establish that the file is malicious.",
        "confidence_score": 50.0,
        "investigation_steps": ["Verify the digital signature of the file", "Analyze the hash on VirusTotal"],
        "analyst_notes": "No execution observed from this event alone.",
        "attack_narrative": "A file was written to C:\\\\Users\\\\user\\\\AppData\\\\Local\\\\Temp\\\\test.exe by PowerShell.",
        "indicators": ["C:\\\\Users\\\\user\\\\AppData\\\\Local\\\\Temp\\\\test.exe"],
        "affected_assets": ["navu-pc"],
        "remediation_steps": [{"priority": 3, "action": "Analyze the unverified executable and verify its origin, hash, and execution context.", "rationale": "Verify files before containment."}],
        "false_positive_likelihood": "unknown",
        "recommended_next_steps": ["Investigate parent process"],
        "suggested_mitre_techniques": ["T1105"]
    }"""
    
    analysis = agent.analyze_alert(alert)
    
    assert "Temp" in analysis.summary
    assert "Windows root" not in analysis.summary
    assert "executed" not in analysis.summary.lower()
    assert "confirmed malware" not in analysis.threat_explanation.lower()
    assert analysis.false_positive_likelihood == "unknown"


def test_live_alert_fixes_b(mock_llm_response):
    """
    TEST B:
    Sysmon Event ID 1
    image: C:\\Users\\user\\AppData\\Local\\Temp\\test.exe
    Expected:
    - Process execution is described accurately.
    - Image path is preserved.
    """
    raw_data = {"data":{"win":{"eventdata":{"image":"C:\\Users\\user\\AppData\\Local\\Temp\\test.exe","processId":"4152","user":"NAVLEEN\\navle"},"system":{"eventID":"1"}}}}
    agent = SOCAnalystAgent()
    alert = SecurityAlert(
        id="test-b-alert",
        timestamp=datetime.now(timezone.utc),
        rule_id="60100",
        rule_description="Sysmon Event ID 1 Process creation",
        rule_level=5,
        agent_name="navu-pc",
        full_log=json.dumps(raw_data),
        raw=raw_data
    )
    
    mock_llm_response.invoke.return_value.content = """{
        "summary": "Process execution of C:\\\\Users\\\\user\\\\AppData\\\\Local\\\\Temp\\\\test.exe was observed.",
        "threat_explanation": "A process was created and executed from the Temp directory.",
        "log_summary": "Execution of C:\\\\Users\\\\user\\\\AppData\\\\Local\\\\Temp\\\\test.exe",
        "root_cause": "Process execution.",
        "attack_impact": "Process ran on the endpoint.",
        "severity_assessment": "Medium",
        "confidence_score": 75.0,
        "investigation_steps": ["Check command line arguments"],
        "analyst_notes": "Observed process creation.",
        "attack_narrative": "The process C:\\\\Users\\\\user\\\\AppData\\\\Local\\\\Temp\\\\test.exe was executed.",
        "indicators": [],
        "affected_assets": ["navu-pc"],
        "remediation_steps": [],
        "false_positive_likelihood": "unknown",
        "recommended_next_steps": [],
        "suggested_mitre_techniques": []
    }"""
    
    analysis = agent.analyze_alert(alert)
    assert "executed" in analysis.summary.lower() or "execution" in analysis.summary.lower()
    assert "C:\\Users\\user\\AppData\\Local\\Temp\\test.exe" in analysis.summary or "C:\\Users\\user\\AppData\\Local\\Temp\\test.exe" in analysis.attack_narrative


def test_live_alert_fixes_c(mock_llm_response):
    """
    TEST C:
    Missing targetFilename
    Expected:
    - AI does not invent a path.
    - Uses "not available" / "not observed".
    """
    raw_data = {"data":{"win":{"eventdata":{"image":"powershell.exe"},"system":{"eventID":"11"}}}}
    agent = SOCAnalystAgent()
    alert = SecurityAlert(
        id="test-c-alert",
        timestamp=datetime.now(timezone.utc),
        rule_id="92213",
        rule_description="Executable file dropped in folder commonly used by malware",
        rule_level=15,
        agent_name="navu-pc",
        full_log=json.dumps(raw_data),
        raw=raw_data
    )
    
    mock_llm_response.invoke.return_value.content = """{
        "summary": "PowerShell created a file. The target file path was not available in the provided evidence.",
        "threat_explanation": "A file creation event was observed, but the filename is not observed in the provided alert.",
        "log_summary": "powershell.exe created file",
        "root_cause": "File creation action.",
        "attack_impact": "Unknown",
        "severity_assessment": "High",
        "confidence_score": 50.0,
        "investigation_steps": [],
        "analyst_notes": "Missing targetFilename.",
        "attack_narrative": "File path not available in the provided evidence.",
        "indicators": [],
        "affected_assets": [],
        "remediation_steps": [],
        "false_positive_likelihood": "unknown",
        "recommended_next_steps": [],
        "suggested_mitre_techniques": []
    }"""
    
    analysis = agent.analyze_alert(alert)
    assert "not available" in analysis.summary.lower() or "not observed" in analysis.summary.lower() or "not available" in analysis.attack_narrative.lower()


def test_live_alert_fixes_d(mock_llm_response):
    """
    TEST D:
    Wazuh MITRE metadata present
    Expected:
    - T1105 / Ingress Tool Transfer remains directly mapped from Wazuh.
    - LLM does not replace it with a guessed technique.
    """
    raw_data = {"rule":{"mitre":{"id":["T1105"],"technique":["Ingress Tool Transfer"],"tactic":["Command and Control"]}}}
    agent = SOCAnalystAgent()
    alert = SecurityAlert(
        id="test-d-alert",
        timestamp=datetime.now(timezone.utc),
        rule_id="92213",
        rule_description="Executable file dropped in folder commonly used by malware",
        rule_level=15,
        agent_name="navu-pc",
        full_log=json.dumps(raw_data),
        raw=raw_data
    )
    
    # Even if LLM suggests a different technique
    mock_llm_response.invoke.return_value.content = """{
        "summary": "Summary",
        "threat_explanation": "Explanation",
        "log_summary": "Log summary",
        "root_cause": "Root cause",
        "attack_impact": "Impact",
        "severity_assessment": "High",
        "confidence_score": 85.0,
        "investigation_steps": [],
        "analyst_notes": "Notes",
        "attack_narrative": "Narrative",
        "indicators": [],
        "affected_assets": [],
        "remediation_steps": [],
        "false_positive_likelihood": "unknown",
        "recommended_next_steps": [],
        "suggested_mitre_techniques": ["T1059.001"]
    }"""
    
    analysis = agent.analyze_alert(alert)
    techniques = [m.technique_id for m in analysis.mitre_mappings]
    assert "T1105" in techniques
    assert "T1059.001" not in techniques  # ensure LLM suggestions are NOT added/mixed


def test_live_alert_fixes_e(mock_llm_response):
    """
    TEST E:
    High severity but ambiguous evidence
    Expected:
    - High severity is preserved.
    - Maliciousness is NOT automatically marked confirmed.
    - False-positive likelihood can remain UNKNOWN.
    - Response recommends investigation/verification.
    """
    raw_data = {"data":{"win":{"eventdata":{"image":"powershell.exe","targetFilename":"C:\\Users\\user\\AppData\\Local\\Temp\\test.exe"},"system":{"eventID":"11"}}}}
    agent = SOCAnalystAgent()
    alert = SecurityAlert(
        id="test-e-alert",
        timestamp=datetime.now(timezone.utc),
        rule_id="92213",
        rule_description="Executable file dropped in folder commonly used by malware",
        rule_level=15,
        agent_name="navu-pc",
        full_log=json.dumps(raw_data),
        raw=raw_data
    )
    
    mock_llm_response.invoke.return_value.content = """{
        "summary": "PowerShell created C:\\\\Users\\\\user\\\\AppData\\\\Local\\\\Temp\\\\test.exe.",
        "threat_explanation": "Ambiguous drop. Not confirmed malware.",
        "log_summary": "powershell.exe dropped test.exe",
        "root_cause": "PowerShell dropped file",
        "attack_impact": "Potential presence of unverified executable",
        "severity_assessment": "Critical severity based on Wazuh rule 92213 level 15, but maliciousness remains unconfirmed.",
        "confidence_score": 60.0,
        "investigation_steps": ["Verify origin", "Inspect file signature"],
        "analyst_notes": "The activity is ambiguous.",
        "attack_narrative": "Dropped test.exe.",
        "indicators": [],
        "affected_assets": [],
        "remediation_steps": [{"priority": 3, "action": "Analyze the unverified executable and verify its origin, hash, and execution context.", "rationale": "Determine if file is malicious before containment."}],
        "false_positive_likelihood": "unknown",
        "recommended_next_steps": [],
        "suggested_mitre_techniques": []
    }"""
    
    analysis = agent.analyze_alert(alert)
    assert analysis.severity in [Severity.HIGH, Severity.CRITICAL]
    assert "malicious" not in analysis.threat_explanation.lower() or "not confirmed" in analysis.threat_explanation.lower()
    assert analysis.false_positive_likelihood == "unknown"
    assert any("verify" in step.action.lower() or "investigate" in step.action.lower() for step in analysis.remediation_steps)


def test_live_alert_fixes_f(mock_llm_response):
    """
    TEST F:
    The exact current alert evidence
    Expected:
    - No statement about "Windows root folder".
    - Correctly identifies C:\\Users\\navle\\AppData\\Local\\Temp\\test-suspicious.exe
    - Correctly identifies PowerShell as the creating process.
    - Correctly identifies Event ID 11 as file creation.
    - Does not claim the file is confirmed malware.
    - Does not invent a PowerShell script.
    """
    raw_data = {"data":{"win":{"eventdata":{"image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","targetFilename":"C:\\Users\\navle\\AppData\\Local\\Temp\\test-suspicious.exe","processId":"4152","user":"NAVLEEN\\navle","ruleName":"EXE"},"system":{"eventID":"11"}}}}
    agent = SOCAnalystAgent()
    alert = SecurityAlert(
        id="test-f-alert",
        timestamp=datetime.now(timezone.utc),
        rule_id="92213",
        rule_description="Executable file dropped in folder commonly used by malware",
        rule_level=15,
        agent_name="navu-pc",
        agent_ip="192.168.31.28",
        full_log=json.dumps(raw_data),
        raw=raw_data
    )
    
    mock_llm_response.invoke.return_value.content = """{
        "summary": "PowerShell created an executable file named test-suspicious.exe in the user's Temp directory.",
        "threat_explanation": "Wazuh rule 92213 classified this behavior as suspicious because executable files were created in a location commonly associated with malware activity. The alert alone does not prove that the executable is malicious.",
        "log_summary": "powershell.exe created C:\\\\Users\\\\navle\\\\AppData\\\\Local\\\\Temp\\\\test-suspicious.exe",
        "root_cause": "A PowerShell process initiated the file creation.",
        "attack_impact": "Unconfirmed threat presence.",
        "severity_assessment": "Detection severity is Critical because Wazuh rule 92213 is configured at level 15. This does not by itself establish that the file is malicious.",
        "confidence_score": 50.0,
        "investigation_steps": ["Verify the digital signature of the file", "Analyze the hash on VirusTotal"],
        "analyst_notes": "No execution observed from this event alone.",
        "attack_narrative": "A file was written to C:\\\\Users\\\\navle\\\\AppData\\\\Local\\\\Temp\\\\test-suspicious.exe by PowerShell.",
        "indicators": ["C:\\\\Users\\\\navle\\\\AppData\\\\Local\\\\Temp\\\\test-suspicious.exe"],
        "affected_assets": ["navu-pc"],
        "remediation_steps": [{"priority": 3, "action": "Analyze the unverified executable and verify its origin, hash, and execution context.", "rationale": "Verify files before containment."}],
        "false_positive_likelihood": "unknown",
        "recommended_next_steps": ["Investigate parent process"],
        "suggested_mitre_techniques": ["T1105"]
    }"""
    
    analysis = agent.analyze_alert(alert)
    
    assert "Windows root" not in analysis.summary
    assert "C:\\Users\\navle\\AppData\\Local\\Temp\\test-suspicious.exe" in analysis.summary or "C:\\Users\\navle\\AppData\\Local\\Temp\\test-suspicious.exe" in analysis.attack_narrative
    assert "powershell" in analysis.summary.lower() or "powershell" in analysis.attack_narrative.lower()
    assert "creation" in analysis.summary.lower() or "created" in analysis.summary.lower() or "creation" in analysis.threat_explanation.lower() or "written" in analysis.attack_narrative.lower() or "created" in analysis.attack_narrative.lower()
    assert "confirmed malware" not in analysis.threat_explanation.lower()
    assert "script" not in analysis.summary.lower() and "script" not in analysis.threat_explanation.lower()
