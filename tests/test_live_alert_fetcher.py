"""Unit tests for LiveAlertFetcher."""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone, timedelta
from opensearchpy.exceptions import AuthenticationException, ConnectionError, ConnectionTimeout

from soc_analyst.services.live_alert_fetcher import LiveAlertFetcher
from soc_analyst.models.schemas import SecurityAlert


@pytest.fixture
def mock_settings():
    with patch("soc_analyst.services.live_alert_fetcher.get_settings") as mock_get:
        settings_mock = MagicMock()
        settings_mock.wazuh_indexer_url = "http://localhost:9200"
        settings_mock.wazuh_username = "elastic"
        settings_mock.wazuh_password = "password"
        settings_mock.wazuh_index_pattern = "wazuh-alerts-*"
        settings_mock.verify_ssl = False
        settings_mock.polling_interval = 5
        settings_mock.min_alert_level = 4
        settings_mock.live_alert_startup_lookback_minutes = 30
        mock_get.return_value = settings_mock
        yield settings_mock


@pytest.fixture
def mock_es_client():
    with patch("soc_analyst.connectors.elasticsearch_client.OpenSearch") as mock_es:
        client_mock = MagicMock()
        client_mock.info.return_value = {"cluster_name": "test-cluster"}
        mock_es.return_value = client_mock
        yield client_mock


def test_live_alert_fetcher_init_success(mock_settings, mock_es_client):
    fetcher = LiveAlertFetcher()
    assert fetcher.client is not None
    assert fetcher.url == "http://localhost:9200"
    assert fetcher.index_pattern == "wazuh-alerts-*"


def test_live_alert_fetcher_init_auth_failure(mock_settings):
    with patch("soc_analyst.connectors.elasticsearch_client.OpenSearch") as mock_es:
        mock_es.side_effect = AuthenticationException("Authentication failed", MagicMock(), {})
        fetcher = LiveAlertFetcher()
        assert fetcher.client is None


def test_live_alert_fetcher_init_timeout(mock_settings):
    with patch("soc_analyst.connectors.elasticsearch_client.OpenSearch") as mock_es:
        mock_es.side_effect = ConnectionTimeout("Timeout connecting", "Timeout connecting", "Timeout connecting")
        fetcher = LiveAlertFetcher()
        assert fetcher.client is None


@pytest.mark.asyncio
async def test_fetch_new_alerts_success(mock_settings, mock_es_client, tmp_path):
    checkpoint_file = tmp_path / "fetcher_checkpoint.json"
    fetcher = LiveAlertFetcher(checkpoint_path=checkpoint_file)
    
    # Mock indexer returning alerts
    now = datetime.now(timezone.utc)
    mock_es_client.search.return_value = {
        "hits": {
            "hits": [
                {
                    "_id": "alert-1",
                    "_source": {
                        "timestamp": (now - timedelta(seconds=10)).isoformat(),
                        "rule": {"id": "1001", "description": "SSH Login Failed", "level": 5},
                        "agent": {"name": "agent-1", "ip": "192.168.1.1"},
                        "data": {"srcip": "8.8.8.8"},
                        "full_log": "Failed password for root"
                    }
                },
                {
                    "_id": "alert-2",
                    "_source": {
                        "timestamp": now.isoformat(),
                        "rule": {"id": "1002", "description": "Web shell detected", "level": 12},
                        "agent": {"name": "agent-1", "ip": "192.168.1.1"},
                        "data": {"srcip": "8.8.8.8"},
                        "full_log": "cmd.exe executed"
                    }
                }
            ]
        }
    }
    
    # First fetch setting initial timestamp to latest (alert-2)
    # Subsequent calls will filter by the updated last_processed_timestamp
    fetcher._last_processed_timestamp = now - timedelta(seconds=20)
    
    alerts = await fetcher.fetch_new_alerts()
    assert len(alerts) == 2
    assert alerts[0].id == "alert-1"
    assert alerts[1].id == "alert-2"
    assert fetcher._last_processed_timestamp == alerts[1].timestamp

    # Check duplicate prevention
    mock_es_client.search.return_value = {
        "hits": {
            "hits": [
                {
                    "_id": "alert-1",
                    "_source": {
                        "timestamp": (now - timedelta(seconds=10)).isoformat(),
                        "rule": {"id": "1001", "description": "SSH Login Failed", "level": 5},
                        "agent": {"name": "agent-1", "ip": "192.168.1.1"},
                        "data": {"srcip": "8.8.8.8"},
                        "full_log": "Failed password for root"
                    }
                },
                {
                    "_id": "alert-3",
                    "_source": {
                        "timestamp": (now + timedelta(seconds=10)).isoformat(),
                        "rule": {"id": "1003", "description": "Malicious activity", "level": 15},
                        "agent": {"name": "agent-1", "ip": "192.168.1.1"},
                        "data": {"srcip": "8.8.8.8"},
                        "full_log": "rm -rf executed"
                    }
                }
            ]
        }
    }
    
    alerts2 = await fetcher.fetch_new_alerts()
    assert len(alerts2) == 1
    assert alerts2[0].id == "alert-3"


def test_live_alert_fetcher_username_mapping(mock_settings, mock_es_client):
    fetcher = LiveAlertFetcher()
    
    hit = {
        "_id": "alert-user-test",
        "_source": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "rule": {"id": "1001", "description": "Windows logon event", "level": 5},
            "agent": {"name": "win-agent", "ip": "192.168.1.5"},
            "data": {
                "win": {
                    "eventdata": {
                        "user": "NAVLEEN\\navle"
                    }
                }
            },
            "full_log": "User NAVLEEN\\navle logged in successfully"
        }
    }
    
    alert = fetcher._parse_hit(hit)
    assert alert is not None
    assert alert.username == "NAVLEEN\\navle"
    assert alert.user == "NAVLEEN\\navle"

    hit_no_user = {
        "_id": "alert-no-user-test",
        "_source": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "rule": {"id": "1001", "description": "System event", "level": 5},
            "agent": {"name": "win-agent", "ip": "192.168.1.5"},
            "data": {},
            "full_log": "System rebooted"
        }
    }
    alert_no_user = fetcher._parse_hit(hit_no_user)
    assert alert_no_user is not None
    assert alert_no_user.username == ""
    assert alert_no_user.user == ""


def test_live_alert_fetcher_raw_log_field(mock_settings, mock_es_client):
    fetcher = LiveAlertFetcher()
    
    hit = {
        "_id": "alert-raw-log-test",
        "_source": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "rule": {"id": "1001", "description": "Sysmon event", "level": 5},
            "agent": {"name": "win-agent", "ip": "192.168.1.5"},
            "data": {
                "win": {
                    "eventdata": {
                        "image": "C:\\Windows\\System32\\cmd.exe",
                        "user": "NAVLEEN\\navle"
                    }
                }
            },
            "full_log": "Original wazuh event description log"
        }
    }
    
    alert = fetcher._parse_hit(hit)
    assert alert is not None
    assert alert.raw_log != ""
    assert "C:\\Windows\\System32\\cmd.exe" in alert.raw_log or "cmd.exe" in alert.raw_log
    assert "NAVLEEN\\navle" in alert.raw_log or "navle" in alert.raw_log
    assert "Original wazuh event description log" in alert.raw_log


def test_forensic_evidence_extraction_rich():
    from soc_analyst.services.forensic_extractor import extract_forensics
    
    source = {
        "timestamp": "2026-08-12T14:57:19.123Z",
        "rule": {
            "id": "92200",
            "level": 7,
            "description": "File created in system directory",
            "groups": ["sysmon", "windows"],
            "mitre": {
                "id": ["T1105"],
                "technique": ["Ingress Tool Transfer"],
                "tactic": ["Command and Control"]
            }
        },
        "agent": {
            "id": "002",
            "name": "win-agent-02",
            "ip": "10.0.0.12"
        },
        "data": {
            "win": {
                "system": {
                    "eventID": "11",
                    "computer": "win-agent-02.domain.local"
                },
                "eventdata": {
                    "image": "C:\\Windows\\System32\\svchost.exe",
                    "processId": "1234",
                    "processGuid": "{A1B2C3D4-E5F6-7A8B-9C0D-E1F2A3B4C5D6}",
                    "user": "NT AUTHORITY\\SYSTEM",
                    "targetFilename": "C:\\Windows\\System32\\drivers\\malware.sys",
                    "creationUtcTime": "2026-08-12 14:56:00.000",
                    "commandLine": "svchost.exe -k netsvcs",
                    "parentImage": "C:\\Windows\\System32\\services.exe",
                    "parentCommandLine": "services.exe"
                }
            },
            "srcip": "192.168.10.5",
            "dstip": "10.0.0.12",
            "srcport": "443",
            "dstport": "54321"
        },
        "decoder": {"name": "json"},
        "location": "C:\\logs\\sysmon.log"
    }
    
    evidence = extract_forensics(source)
    assert evidence["sysmon_event_id"] == "11"
    assert evidence["image"] == "C:\\Windows\\System32\\svchost.exe"
    assert evidence["process_id"] == "1234"
    assert evidence["process_guid"] == "{A1B2C3D4-E5F6-7A8B-9C0D-E1F2A3B4C5D6}"
    assert evidence["user"] == "NT AUTHORITY\\SYSTEM"
    assert evidence["target_filename"] == "C:\\Windows\\System32\\drivers\\malware.sys"
    assert evidence["creation_time"] == "2026-08-12 14:56:00.000"
    assert evidence["computer"] == "win-agent-02.domain.local"
    assert evidence["command_line"] == "svchost.exe -k netsvcs"
    assert evidence["parent_process_image"] == "C:\\Windows\\System32\\services.exe"
    assert evidence["parent_process_command_line"] == "services.exe"
    
    assert evidence["rule_id"] == "92200"
    assert evidence["rule_level"] == 7
    assert evidence["rule_description"] == "File created in system directory"
    assert evidence["rule_groups"] == ["sysmon", "windows"]
    assert evidence["rule_mitre"] == {
        "id": ["T1105"],
        "technique": ["Ingress Tool Transfer"],
        "tactic": ["Command and Control"]
    }
    
    assert evidence["agent_id"] == "002"
    assert evidence["agent_name"] == "win-agent-02"
    assert evidence["agent_ip"] == "10.0.0.12"
    
    assert evidence["source_ip"] == "192.168.10.5"
    assert evidence["destination_ip"] == "10.0.0.12"
    assert evidence["source_port"] == "443"
    assert evidence["destination_port"] == "54321"
    assert evidence["decoder"] == "json"
    assert evidence["location"] == "C:\\logs\\sysmon.log"
    assert evidence["timestamp"] == "2026-08-12T14:57:19.123Z"


def test_forensic_evidence_extraction_missing():
    from soc_analyst.services.forensic_extractor import extract_forensics
    
    source = {
        "rule": {
            "id": "500"
        }
    }
    
    evidence = extract_forensics(source)
    assert evidence["sysmon_event_id"] == "Not available"
    assert evidence["image"] == "Not available"
    assert evidence["process_id"] == "Not available"
    assert evidence["process_guid"] == "Not available"
    assert evidence["user"] == "Not available"
    assert evidence["target_filename"] == "Not available"
    assert evidence["creation_time"] == "Not available"
    assert evidence["computer"] == "Not available"
    assert evidence["command_line"] == "Not available"
    assert evidence["parent_process_image"] == "Not available"
    assert evidence["parent_process_command_line"] == "Not available"
    
    assert evidence["rule_id"] == "500"
    assert evidence["rule_level"] == "Not available"
    assert evidence["rule_description"] == "Not available"
    assert evidence["rule_groups"] == "Not available"
    assert evidence["rule_mitre"] == "Not available"
    
    assert evidence["agent_id"] == "Not available"
    assert evidence["agent_name"] == "Not available"
    assert evidence["agent_ip"] == "Not available"
    
    assert evidence["source_ip"] == "Not available"
    assert evidence["destination_ip"] == "Not available"
    assert evidence["decoder"] == "Not available"
    assert evidence["location"] == "Not available"
    assert evidence["timestamp"] == "Not available"


def test_parse_hit_windows_openssh_bruteforce(mock_settings, mock_es_client):
    fetcher = LiveAlertFetcher()
    hit = {
        "_id": "doc-ssh-100061",
        "_source": {
            "timestamp": "2026-10-18T10:00:00.000Z",
            "rule": {
                "id": "100061",
                "level": 10,
                "description": "Windows OpenSSH: Multiple authentication failures (brute-force)",
                "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]},
                "groups": ["authentication_failures", "sshd", "windows_sshd"]
            },
            "agent": {"id": "001", "name": "navu-pc", "ip": "192.168.31.28"},
            "data": {
                "win": {
                    "system": {"eventID": "4625", "channel": "Security"},
                    "eventdata": {
                        "logonType": "8",
                        "processName": "C:\\Windows\\System32\\OpenSSH\\sshd.exe",
                        "targetUserName": "administrator",
                        "ipAddress": "-"
                    }
                }
            },
            "full_log": "An account failed to log on. Caller: sshd.exe"
        }
    }
    alert = fetcher._parse_hit(hit)
    assert alert is not None
    assert alert.rule_id == "100061"
    assert alert.rule_level == 10
    assert alert.agent_name == "navu-pc"
    assert alert.agent_ip == "192.168.31.28"
    assert alert.source_ip == ""  # Hyphen stripped, no fabricated attacker IP
    assert alert.username == "administrator"




