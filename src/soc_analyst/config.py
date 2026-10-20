"""AI SOC Analyst - Configuration."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    llm_provider: Literal["openai", "ollama"] = "openai"
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"

    elasticsearch_host: str = "http://localhost:9200"
    elasticsearch_user: str = "elastic"
    elasticsearch_password: str = "changeme"
    elasticsearch_verify_certs: bool = False
    wazuh_alerts_index: str = "wazuh-alerts-*"
    disable_mitre_online_lookup: bool = True
    enable_offline_mode: bool = False
    incident_time_window: int = 7200
    poll_interval: int = 10

    wazuh_indexer_url: str = Field(default="https://localhost:9200", validation_alias="WAZUH_INDEXER_URL")
    wazuh_username: str = Field(default="admin", validation_alias="WAZUH_USERNAME")
    wazuh_password: str = Field(default="changeme", validation_alias="WAZUH_PASSWORD")
    wazuh_index_pattern: str = Field(default="wazuh-alerts-*", validation_alias="WAZUH_INDEX_PATTERN")
    verify_ssl: bool = Field(default=False, validation_alias="VERIFY_SSL")
    polling_interval: int = Field(default=5, validation_alias="POLLING_INTERVAL")
    min_alert_level: int = Field(default=4, validation_alias="MIN_ALERT_LEVEL")
    live_alert_startup_lookback_minutes: int = Field(default=30, validation_alias="LIVE_ALERT_STARTUP_LOOKBACK_MINUTES")

    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""

    api_host: str = "0.0.0.0"
    api_port: int = 8000
    alert_poll_interval_seconds: int = 10
    max_alerts_per_batch: int = 50


@lru_cache
def get_settings() -> Settings:
    return Settings()


def save_settings(new_settings: dict) -> None:
    """Updates settings and writes them back to the .env file, clearing caches."""
    env_path = PROJECT_ROOT / ".env"
    
    # Read current lines
    lines = []
    if env_path.exists():
        lines = env_path.read_text(encoding="utf-8").splitlines()
        
    # Map of UPPERCASE keys to line index
    key_line_map = {}
    for i, line in enumerate(lines):
        line_stripped = line.strip()
        if line_stripped and not line_stripped.startswith("#") and "=" in line:
            parts = line.split("=", 1)
            key = parts[0].strip().upper()
            key_line_map[key] = i
            
    # Update lines
    for key, val in new_settings.items():
        env_key = key.upper()
        # Convert boolean or numbers to string format for env
        if isinstance(val, bool):
            val_str = "true" if val else "false"
        else:
            val_str = str(val)
            
        line_str = f"{env_key}={val_str}"
        if env_key in key_line_map:
            idx = key_line_map[env_key]
            lines[idx] = line_str
        else:
            lines.append(line_str)
            
    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    get_settings.cache_clear()


@lru_cache
def get_yaml_config() -> dict:
    config_path = CONFIG_DIR / "settings.yaml"
    if not config_path.exists():
        return {}
    with config_path.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

