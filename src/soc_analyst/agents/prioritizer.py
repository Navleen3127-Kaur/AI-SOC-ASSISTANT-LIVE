"""Alert prioritization engine."""

from soc_analyst.config import get_yaml_config
from soc_analyst.models.schemas import AlertAnalysis, MitreMapping, SecurityAlert, Severity


class AlertPrioritizer:
    def __init__(self) -> None:
        config = get_yaml_config().get("prioritization", {})
        self.severity_weights = config.get(
            "severity_weights",
            {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1},
        )
        self.rule_boost = config.get("rule_level_boost", {})

    def score(
        self,
        alert: SecurityAlert,
        mitre_mappings: list[MitreMapping] | None = None,
    ) -> tuple[float, Severity]:
        mitre_mappings = mitre_mappings or []
        base = self.severity_weights.get(alert.severity_hint.value, 1)

        rule_level = alert.rule_level
        boost_cfg = self.rule_boost
        if boost_cfg.get("min", 0) <= rule_level <= boost_cfg.get("max", 99):
            base += boost_cfg.get("boost", 0)

        # More MITRE techniques = higher confidence of real attack
        base += min(len(mitre_mappings) * 2, 10)

        # Critical techniques bump priority
        critical_tactics = {"Impact", "Credential Access", "Command and Control"}
        for mapping in mitre_mappings:
            if any(t in mapping.tactic for t in critical_tactics):
                base += 3

        # Network indicators present
        if alert.source_ip or alert.destination_ip:
            base += 1

        score = min(base * 5, 100.0)

        if score >= 80:
            severity = Severity.CRITICAL
        elif score >= 60:
            severity = Severity.HIGH
        elif score >= 40:
            severity = Severity.MEDIUM
        elif score >= 20:
            severity = Severity.LOW
        else:
            severity = Severity.INFO

        return score, severity

    def rank_alerts(
        self,
        alerts: list[SecurityAlert],
        mitre_by_alert: dict[str, list[MitreMapping]] | None = None,
    ) -> list[tuple[SecurityAlert, float, Severity]]:
        mitre_by_alert = mitre_by_alert or {}
        ranked = [
            (
                alert,
                *self.score(alert, mitre_by_alert.get(alert.id, [])),
            )
            for alert in alerts
        ]
        return sorted(ranked, key=lambda item: item[1], reverse=True)

    def apply_to_analysis(
        self,
        alert: SecurityAlert,
        analysis: AlertAnalysis,
        mitre_mappings: list[MitreMapping],
    ) -> AlertAnalysis:
        score, severity = self.score(alert, mitre_mappings)
        analysis.priority_score = score
        analysis.severity = severity
        return analysis
