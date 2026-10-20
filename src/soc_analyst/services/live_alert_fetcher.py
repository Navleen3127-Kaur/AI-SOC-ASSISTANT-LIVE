"""Live alert fetcher for Wazuh Indexer."""

import logging
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Any

from opensearchpy import OpenSearch
from opensearchpy.exceptions import ConnectionError, ConnectionTimeout, AuthenticationException
from soc_analyst.config import get_settings
from soc_analyst.models.schemas import SecurityAlert
from soc_analyst.connectors.elasticsearch_client import ElasticsearchClient

from pathlib import Path
import json
from soc_analyst.config import PROJECT_ROOT

logger = logging.getLogger(__name__)


class LiveAlertFetcher:
    """Fetches new alerts directly from the Wazuh Indexer (OpenSearch/Elasticsearch)."""

    def __init__(self, checkpoint_path: Path | None = None) -> None:
        settings = get_settings()
        self.url = settings.wazuh_indexer_url
        self.username = settings.wazuh_username
        self.password = settings.wazuh_password
        self.index_pattern = settings.wazuh_index_pattern
        self.verify_ssl = settings.verify_ssl
        self.polling_interval = settings.polling_interval
        self.min_alert_level = settings.min_alert_level
        self.startup_lookback_minutes = settings.live_alert_startup_lookback_minutes

        self.indexer: ElasticsearchClient | None = None
        self.client: Any | None = None
        self._last_processed_timestamp: datetime | None = None
        self._processed_ids: set[str] = set()
        self.checkpoint_file = checkpoint_path or (PROJECT_ROOT / "config" / "fetcher_checkpoint.json")

        self._load_checkpoint()

        logger.info("Initializing LiveAlertFetcher with shared IndexerClient index pattern: %s", self.index_pattern)
        self._init_client()

    def _load_checkpoint(self) -> None:
        """Loads persistent checkpoint if available."""
        try:
            if self.checkpoint_file.exists():
                data = json.loads(self.checkpoint_file.read_text(encoding="utf-8"))
                ts_str = data.get("last_processed_timestamp")
                if ts_str:
                    self._last_processed_timestamp = datetime.fromisoformat(ts_str)
                ids = data.get("processed_ids", [])
                self._processed_ids = set(ids)
                logger.info(
                    "Loaded fetcher checkpoint: timestamp=%s, %d processed IDs",
                    self._last_processed_timestamp,
                    len(self._processed_ids),
                )
        except Exception as e:
            logger.warning("Failed to load fetcher checkpoint from %s: %s", self.checkpoint_file, e)

    def _save_checkpoint(self) -> None:
        """Saves current checkpoint to file."""
        try:
            self.checkpoint_file.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "last_processed_timestamp": (
                    self._last_processed_timestamp.isoformat()
                    if self._last_processed_timestamp
                    else None
                ),
                "processed_ids": list(self._processed_ids)[-5000:],
            }
            self.checkpoint_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as e:
            logger.warning("Failed to save fetcher checkpoint to %s: %s", self.checkpoint_file, e)

    def _init_client(self) -> None:
        """Initializes the shared indexer client."""
        try:
            self.indexer = ElasticsearchClient()
            self.client = self.indexer.client
        except Exception as exc:
            logger.error("Unexpected error initializing Wazuh Indexer client: %s", exc)
            self.client = None

    def _parse_hit(self, hit: dict[str, Any]) -> SecurityAlert | None:
        """Parses a search hit into a SecurityAlert schema, logging any formatting issues."""
        doc_id = hit.get("_id", "unknown")
        logger.info("Starting parsing for document _id: %s", doc_id)
        try:
            source = hit.get("_source", {})
            data = source.get("data", {}) or {}
            win = data.get("win", {}) or {}
            eventdata = win.get("eventdata", {}) or {}

            timestamp_raw = source.get("timestamp") or source.get("@timestamp")
            logger.info("Timestamp field raw value read: %s", timestamp_raw)
            if isinstance(timestamp_raw, str):
                # Standardize UTC format parsing
                timestamp = datetime.fromisoformat(timestamp_raw.replace("Z", "+00:00"))
            else:
                timestamp = datetime.now(timezone.utc)

            rule = source.get("rule", {}) or {}
            agent = source.get("agent", {}) or {}

            logger.info("Rule metadata read — rule.id: %s, rule.level: %s", rule.get("id"), rule.get("level"))
            logger.info("Agent metadata read — agent.name: %s", agent.get("name"))

            from soc_analyst.services.forensic_extractor import extract_forensics
            import json
            evidence = extract_forensics(source)

            raw_src_ip = data.get("srcip", data.get("src_ip", "")) or eventdata.get("ipAddress", "")
            cleaned_src_ip = "" if raw_src_ip in ("-", "") else raw_src_ip

            raw_user = (
                eventdata.get("targetUserName")
                or eventdata.get("user")
                or eventdata.get("subjectUserName")
                or data.get("dstuser", "")
            )
            cleaned_user = "" if raw_user in ("-", "") else raw_user

            alert = SecurityAlert(
                id=hit.get("_id", source.get("id", "")),
                timestamp=timestamp,
                rule_id=str(rule.get("id", "")),
                rule_description=rule.get("description", ""),
                rule_level=int(rule.get("level", 0) or 0),
                agent_name=agent.get("name", ""),
                agent_ip=agent.get("ip", ""),
                source_ip=cleaned_src_ip,
                destination_ip=data.get("dstip", data.get("dst_ip", "")),
                username=cleaned_user,
                user=cleaned_user,
                full_log=source.get("full_log", ""),
                raw_log=json.dumps(evidence, indent=2),
                raw=source,
            )
            logger.info("SecurityAlert object successfully created for _id: %s", doc_id)
            return alert
        except Exception as e:
            logger.exception("Failed to parse hit ID %s: %s", doc_id, e)
            return None

    async def fetch_new_alerts(self, limit: int = 100) -> list[SecurityAlert]:
        """Queries the indexer for new alerts, avoiding duplicate processing."""
        if not self.client:
            logger.warning("Wazuh Indexer client not connected. Re-attempting connection...")
            self._init_client()
            if not self.client:
                logger.error("Wazuh Indexer is still unavailable. Skipping poll.")
                return []

        # Initialize start timestamp on the first poll
        if self._last_processed_timestamp is None:
            self._last_processed_timestamp = datetime.now(timezone.utc) - timedelta(minutes=self.startup_lookback_minutes)
            logger.info("Initializing startup lookup window to %d minutes ago: %s", self.startup_lookback_minutes, self._last_processed_timestamp)

        body = {
            "size": limit,
            "sort": [{"timestamp": {"order": "asc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                "timestamp": {
                                    "gte": self._last_processed_timestamp.isoformat()
                                }
                            }
                        },
                        {
                            "range": {
                                "rule.level": {
                                    "gte": self.min_alert_level
                                }
                            }
                        }
                    ]
                }
            }
        }

        logger.info("[POLL] Poll started | Index: %s | Since: %s", self.index_pattern, self._last_processed_timestamp)
        try:
            response = self.client.search(index=self.index_pattern, body=body)
            hits = response.get("hits", {}).get("hits", [])
        except AuthenticationException as auth_exc:
            logger.error("[POLL] Authentication failure during query: %s", auth_exc)
            return []
        except ConnectionTimeout as timeout_exc:
            logger.error("[POLL] Connection timeout querying alerts: %s", timeout_exc)
            return []
        except ConnectionError as conn_exc:
            logger.error("[POLL] Connection error querying alerts: %s", conn_exc)
            return []
        except Exception as exc:
            logger.error("[POLL] Unexpected error querying alerts: %s", exc)
            return []

        hits_count = len(hits)
        if not hits:
            logger.info("[POLL] Poll completed: 0 OpenSearch hits | 0 new unique events | 0 duplicates skipped.")
            return []

        new_alerts: list[SecurityAlert] = []
        parsed_timestamps: list[datetime] = []
        skipped_count = 0

        for hit in hits:
            doc_id = hit.get("_id", "unknown")
            alert = self._parse_hit(hit)
            if not alert:
                continue

            parsed_timestamps.append(alert.timestamp)

            if alert.id in self._processed_ids:
                skipped_count += 1
                logger.info(
                    "[SKIP] Alert ID: %s | Rule: %s | Time: %s | Reason: already processed in checkpoint/session cache (skipped)",
                    alert.id,
                    alert.rule_id,
                    alert.timestamp.isoformat(),
                )
                continue

            new_alerts.append(alert)
            self._processed_ids.add(alert.id)

            # Detailed per-event telemetry logging for genuinely new alert
            raw_source = hit.get("_source", {})
            eventdata = raw_source.get("data", {}).get("win", {}).get("eventdata", {})
            proc_img = eventdata.get("image") or eventdata.get("processName") or ""
            parent_img = eventdata.get("parentImage") or ""
            cmd_line = eventdata.get("commandLine") or ""

            logger.info(
                "[NEW LIVE ALERT] Alert ID: %s | Event Time: %s | Rule ID: %s | Severity: %s (Level %d) | Agent: %s | Description: %s",
                alert.id,
                alert.timestamp.isoformat(),
                alert.rule_id,
                alert.severity_hint.value.upper(),
                alert.rule_level,
                alert.agent_name or "N/A",
                alert.rule_description or "N/A",
            )

            # Specific attack / activity signatures
            if alert.rule_id == "100060":
                target_user = alert.username or "unknown"
                logger.warning(
                    "  -> [AUTH FAILURE] Windows OpenSSH authentication failure detected for user: '%s' (Process: %s)",
                    target_user,
                    proc_img or "sshd.exe",
                )
            elif alert.rule_id == "100061":
                logger.critical(
                    "  -> [BRUTE FORCE] Configured OpenSSH brute-force detection rule fired! (Rule 100061, Level 10)",
                )
            elif "powershell" in (proc_img + parent_img + alert.rule_description).lower():
                logger.info(
                    "  -> [POWERSHELL ACTIVITY] Image: %s | Parent: %s | Cmd: %s",
                    proc_img,
                    parent_img,
                    cmd_line[:120] if cmd_line else "[no command line in event]",
                )
            elif "tasklist" in cmd_line.lower() and "bluestacks" in (parent_img + cmd_line).lower():
                logger.info(
                    "  -> [BENIGN TELEMETRY] BlueStacks emulator background tasklist check detected.",
                )

        logger.info(
            "[POLL] Poll completed: %d OpenSearch hits | %d new unique events | %d duplicates skipped.",
            hits_count,
            len(new_alerts),
            skipped_count,
        )

        # Advance cursor to max timestamp of all parsed hits in batch to prevent cursor freeze
        if parsed_timestamps:
            max_hit_ts = max(parsed_timestamps)
            if self._last_processed_timestamp is None or max_hit_ts > self._last_processed_timestamp:
                self._last_processed_timestamp = max_hit_ts

        # Maintain bounded in-memory cache size for IDs
        if len(self._processed_ids) > 10000:
            self._processed_ids = set(list(self._processed_ids)[-5000:])

        self._save_checkpoint()
        return new_alerts
