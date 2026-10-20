"""MITRE ATT&CK framework mapping using attackcti."""

import logging
import re
from functools import lru_cache

from attackcti import attack_client

from soc_analyst.models.schemas import MitreMapping, SecurityAlert

logger = logging.getLogger(__name__)

# Common Wazuh rule keywords → MITRE technique IDs
RULE_KEYWORD_MAP: dict[str, tuple[str, str, str]] = {
    r"brute.?force|password.?guess|failed.?login|authentication.?failure": (
        "T1110",
        "Brute Force",
        "Credential Access",
    ),
    r"powershell|encoded.?command|downloadstring|invoke-expression": (
        "T1059.001",
        "PowerShell / Command and Scripting Interpreter",
        "Execution",
    ),
    r"mimikatz|lsass|credential.?dump|sekurlsa": (
        "T1003.001",
        "LSASS Memory",
        "Credential Access",
    ),
    r"lateral.?movement|psexec|wmiexec|remote.?service": (
        "T1021",
        "Remote Services",
        "Lateral Movement",
    ),
    r"ransomware|encrypt|\.locked": (
        "T1486",
        "Data Encrypted for Impact",
        "Impact",
    ),
    r"shadow.?copy.?delete|vssadmin": (
        "T1490",
        "Inhibit System Recovery",
        "Impact",
    ),
    r"port.?scan|nmap|reconnaissance|network.?scan": (
        "T1046",
        "Network Service Discovery",
        "Discovery",
    ),
    r"phishing|malicious.?email|spear.?phish": (
        "T1566",
        "Phishing",
        "Initial Access",
    ),
    r"command.?and.?control|c2|beacon|dns.?tunnel": (
        "T1071",
        "Application Layer Protocol",
        "Command and Control",
    ),
    r"persistence|registry.?run|scheduled.?task|startup": (
        "T1547",
        "Boot or Logon Autostart Execution",
        "Persistence",
    ),
    r"privilege.?escalation|uac.?bypass|token.?manipulation": (
        "T1548",
        "Abuse Elevation Control Mechanism",
        "Privilege Escalation",
    ),
    r"exfiltration|data.?transfer|upload.?external": (
        "T1041",
        "Exfiltration Over C2 Channel",
        "Exfiltration",
    ),
    r"defense.?evasion|disable.?av|tamper.?protection|log.?clear": (
        "T1562",
        "Impair Defenses",
        "Defense Evasion",
    ),
}

# Local authoritative MITRE database for offline validation
OFFLINE_MITRE_DB: dict[str, tuple[str, str, str]] = {
    "T1110": (
        "Brute Force",
        "Credential Access",
        "Adversaries may use brute force access techniques.",
    ),
    "T1059.001": (
        "PowerShell / Command and Scripting Interpreter",
        "Execution",
        "Command and Scripting Interpreter: PowerShell.",
    ),
    "T1003.001": (
        "LSASS Memory",
        "Credential Access",
        "Adversaries may attempt to access credential material from the LSASS process.",
    ),
    "T1021": (
        "Remote Services",
        "Lateral Movement",
        "Adversaries may use Remote Services to move laterally.",
    ),
    "T1486": (
        "Data Encrypted for Impact",
        "Impact",
        "Adversaries may encrypt data on victim systems to interrupt availability.",
    ),
    "T1490": (
        "Inhibit System Recovery",
        "Impact",
        "Adversaries may delete shadow copies to inhibit system recovery.",
    ),
    "T1046": (
        "Network Service Discovery",
        "Discovery",
        "Adversaries may scan for service discovery.",
    ),
    "T1566": (
        "Phishing",
        "Initial Access",
        "Adversaries may send phishing emails to gain initial access.",
    ),
    "T1071": (
        "Application Layer Protocol",
        "Command and Control",
        "Adversaries may use application layer protocols for C2.",
    ),
    "T1547": (
        "Boot or Logon Autostart Execution",
        "Persistence",
        "Adversaries may configure autostart execution for persistence.",
    ),
    "T1548": (
        "Abuse Elevation Control Mechanism",
        "Privilege Escalation",
        "Adversaries may bypass UAC or manipulate tokens.",
    ),
    "T1041": (
        "Exfiltration Over C2 Channel",
        "Exfiltration",
        "Adversaries may exfiltrate data over the C2 channel.",
    ),
    "T1562": (
        "Impair Defenses",
        "Defense Evasion",
        "Adversaries may impair defenses to evade detection.",
    ),
    "T1105": (
        "Ingress Tool Transfer",
        "Command and Control",
        "Adversaries may transfer tools into the environment.",
    ),
}


@lru_cache
def _get_attack_client():
    from soc_analyst.config import get_settings
    if get_settings().disable_mitre_online_lookup:
        logger.info("MITRE ATT&CK online lookup is disabled (offline mode).")
        return None
    try:
        return attack_client()
    except Exception as exc:
        logger.warning("Failed to load MITRE ATT&CK data: %s", exc)
        return None


class MitreAttackMapper:
    def __init__(self) -> None:
        self._client = _get_attack_client()

    def map_alert(self, alert: SecurityAlert) -> list[MitreMapping]:
        rule_mitre_id = ""
        if isinstance(alert.raw.get("rule"), dict):
            mitre_data = alert.raw.get("rule", {}).get("mitre", {}) or {}
            if isinstance(mitre_data, dict):
                rule_mitre_id = mitre_data.get("id", "")
                if isinstance(rule_mitre_id, list):
                    rule_mitre_id = " ".join(rule_mitre_id)

        text = " ".join(
            filter(
                None,
                [
                    alert.rule_description,
                    alert.full_log,
                    rule_mitre_id,
                ],
            )
        ).lower()

        mappings: list[MitreMapping] = []
        seen: set[str] = set()

        # Wazuh may embed MITRE IDs, techniques, and tactics directly in rule metadata under rule.mitre
        rule_mitre = (alert.raw.get("rule") or {}).get("mitre") or {}
        if isinstance(rule_mitre, dict):
            ids = rule_mitre.get("id", [])
            techniques = rule_mitre.get("technique", [])
            tactics = rule_mitre.get("tactic", [])

            # Normalize to lists
            if isinstance(ids, str):
                ids = [ids]
            elif not isinstance(ids, list):
                ids = []

            if isinstance(techniques, str):
                techniques = [techniques]
            elif not isinstance(techniques, list):
                techniques = []

            if isinstance(tactics, str):
                tactics = [tactics]
            elif not isinstance(tactics, list):
                tactics = []

            for idx, tid in enumerate(ids):
                if isinstance(tid, str) and tid.upper().startswith("T") and not tid.upper().startswith("TA"):
                    tech_name = techniques[idx] if idx < len(techniques) and techniques[idx] else tid
                    tactic_name = tactics[idx] if idx < len(tactics) and tactics[idx] else ""

                    mapping = self._lookup_technique(tid)
                    if mapping:
                        if tech_name and tech_name != tid:
                            mapping.technique_name = tech_name
                        if tactic_name:
                            mapping.tactic = tactic_name
                    else:
                        # Validate the raw metadata ID exists in local db or online
                        mapping = self._lookup_technique(tid)
                        if not mapping:
                            # Skip invalid/non-existent IDs
                            continue

                    if tid not in seen:
                        seen.add(tid)
                        mappings.append(mapping)

        # Keyword-based fallback mapping
        for pattern, (tech_id, tech_name, tactic) in RULE_KEYWORD_MAP.items():
            if re.search(pattern, text, re.IGNORECASE) and tech_id not in seen:
                # Safeguard for PowerShell T1059.001
                if tech_id == "T1059.001":
                    win_data = alert.raw.get("data", {}).get("win", {}) or {}
                    event_id = str(win_data.get("system", {}).get("eventID", ""))
                    
                    # If this is a FileCreated (ID 11) event or lacks commandLine,
                    # make sure there are explicit powershell execution flags
                    is_file_drop = (event_id == "11" or "targetFilename" in text)
                    command_line = win_data.get("eventdata", {}).get("commandLine", "")
                    has_cmd = bool(command_line and command_line.strip())
                    
                    exec_indicators = [
                        r"encoded.?command",
                        r"downloadstring",
                        r"invoke-expression",
                        r"\biex\b",
                        r"-enc\b",
                        r"-command\b"
                    ]
                    has_exec_indicator = any(re.search(ind_pat, text, re.IGNORECASE) for ind_pat in exec_indicators)
                    
                    if (is_file_drop or not has_cmd) and not has_exec_indicator:
                        continue

                detail = self._lookup_technique(tech_id)
                if detail:
                    seen.add(tech_id)
                    mappings.append(detail)

        return mappings

    def search_techniques(self, query: str, limit: int = 5) -> list[MitreMapping]:
        if not self._client:
            return []

        results: list[MitreMapping] = []
        query_lower = query.lower()

        try:
            techniques = self._client.get_enterprise_techniques()
            for tech in techniques:
                name = tech.get("name", "")
                desc = tech.get("description", "")
                if query_lower in name.lower() or query_lower in desc.lower():
                    tactics = [
                        p.get("phase_name", "")
                        for p in tech.get("kill_chain_phases", [])
                    ]
                    external_refs = tech.get("external_references", [])
                    tech_id = next(
                        (
                            ref.get("external_id", "")
                            for ref in external_refs
                            if ref.get("source_name") == "mitre-attack"
                        ),
                        "",
                    )
                    if tech_id:
                        results.append(
                            MitreMapping(
                                technique_id=tech_id,
                                technique_name=name,
                                tactic=", ".join(tactics),
                                description=desc[:300],
                                confidence=0.9,
                            )
                        )
                if len(results) >= limit:
                    break
        except Exception as exc:
            logger.warning("MITRE search failed: %s", exc)

        return results

    def _lookup_technique(self, technique_id: str) -> MitreMapping | None:
        if not technique_id or not technique_id.upper().startswith("T") or technique_id.upper().startswith("TA"):
            return None

        tid = technique_id.strip().upper()

        if self._client:
            try:
                tech = self._client.get_technique_by_id(tid)
                if tech:
                    tactics = [
                        p.get("phase_name", "")
                        for p in tech.get("kill_chain_phases", [])
                    ]
                    tactic_str = ", ".join(t.replace("-", " ").title() for t in tactics if t)
                    return MitreMapping(
                        technique_id=tid,
                        technique_name=tech.get("name", tid),
                        tactic=tactic_str,
                        description=(tech.get("description") or "")[:400],
                        confidence=0.95,
                    )
            except Exception as e:
                logger.warning("Online lookup failed for %s: %s", tid, e)

        # Local validation fallback
        if tid in OFFLINE_MITRE_DB:
            name, tactic, desc = OFFLINE_MITRE_DB[tid]
            return MitreMapping(
                technique_id=tid,
                technique_name=name,
                tactic=tactic,
                description=desc,
                confidence=0.95,
            )

        return None

    def get_tactic_summary(self, mappings: list[MitreMapping]) -> list[str]:
        tactics = sorted({m.tactic for m in mappings if m.tactic})
        return tactics
