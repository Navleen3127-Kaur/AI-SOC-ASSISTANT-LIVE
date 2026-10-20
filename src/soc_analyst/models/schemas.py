"""Pydantic models for alerts, analysis, and incident reports."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class MitreMapping(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    description: str = ""
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)


class RemediationStep(BaseModel):
    priority: int = Field(ge=1, le=5)
    action: str
    rationale: str


class AlertAnalysis(BaseModel):
    alert_id: str
    summary: str
    threat_explanation: str
    log_summary: str = ""
    full_log: str = ""
    rule_description: str = ""
    root_cause: str = ""
    attack_impact: str = ""
    severity_assessment: str = ""
    confidence_score: float = Field(ge=0.0, le=100.0, default=85.0)
    investigation_steps: list[str] = Field(default_factory=list)
    analyst_notes: str = ""
    attack_narrative: str
    severity: Severity
    priority_score: float = Field(ge=0.0, le=100.0)
    mitre_mappings: list[MitreMapping] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    remediation_steps: list[RemediationStep] = Field(default_factory=list)
    false_positive_likelihood: str = "unknown"
    recommended_next_steps: list[str] = Field(default_factory=list)
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IncidentReport(BaseModel):
    incident_id: str
    title: str
    executive_summary: str
    incident_overview: str = ""
    timeline: list[str] = Field(default_factory=list)
    alerts_analyzed: list[AlertAnalysis] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    indicators_of_compromise: list[str] = Field(default_factory=list)
    threat_intel_summary: str = ""
    mitre_tactics_observed: list[str] = Field(default_factory=list)
    mitre_techniques_observed: list[str] = Field(default_factory=list)
    overall_severity: Severity
    risk_score: float = 0.0
    risk_breakdown: dict[str, float] = Field(default_factory=dict)
    threat_explanation: str = ""
    investigation_findings: str = ""
    containment_actions: list[str] = Field(default_factory=list)
    eradication_actions: list[str] = Field(default_factory=list)
    recovery_actions: list[str] = Field(default_factory=list)
    lessons_learned: list[str] = Field(default_factory=list)
    ai_decision_reasoning: list[str] = Field(default_factory=list)
    confidence_score: float = 0.0
    confidence_level: str = "Medium"
    confidence_breakdown: dict[str, float] = Field(default_factory=dict)
    correlation_score: float = 0.0
    correlation_breakdown: list[str] = Field(default_factory=list)
    executive_recommendations: list[str] = Field(default_factory=list)
    analyst_conclusion: str = ""
    # Report Metadata
    report_version: str = "2.3"
    generated_by: str = "AI SOC Analyst"
    llm_provider: str = "Ollama"
    llm_model: str = "Qwen2.5:3B"
    execution_mode: str = "Offline Demo"
    report_type: str = "Incident Investigation Summary"
    # Executive Report Metrics
    total_alerts_analyzed: int = 0
    correlated_alerts_count: int = 0
    affected_hosts_count: int = 0
    affected_users_count: int = 0
    critical_assets_count: int = 0
    false_positive_probability: str = "Low"
    threat_intel_hits: int = 0
    mitre_techniques_count: int = 0
    attack_progression: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SecurityAlert(BaseModel):
    id: str
    timestamp: datetime
    rule_id: str = ""
    rule_description: str = ""
    rule_level: int = 0
    agent_name: str = ""
    agent_ip: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    username: str = ""
    user: str = ""
    full_log: str = ""
    raw_log: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)


    @property
    def severity_hint(self) -> Severity:
        if self.rule_level >= 12:
            return Severity.CRITICAL
        if self.rule_level >= 10:
            return Severity.HIGH
        if self.rule_level >= 7:
            return Severity.MEDIUM
        if self.rule_level >= 4:
            return Severity.LOW
        return Severity.INFO


class AnalyzeAlertRequest(BaseModel):
    alert: SecurityAlert | None = None
    alert_id: str | None = None
    include_mitre: bool = True


class SearchAlertsRequest(BaseModel):
    query: str = "*"
    severity_min: int = 0
    hours_back: int = 24
    limit: int = 20


class ChatRequest(BaseModel):
    message: str
    alert_id: str | None = None
    incident_id: str | None = None
    context_hours: int = 24
