import json
from collections import Counter
from opensearchpy import OpenSearch
from soc_analyst.config import get_settings
from urllib.parse import urlparse

settings = get_settings()
parsed_url = urlparse(settings.wazuh_indexer_url)
host = parsed_url.hostname or "localhost"
port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
use_ssl = parsed_url.scheme == "https"

client = OpenSearch(
    hosts=[{"host": host, "port": port}],
    http_auth=(settings.wazuh_username, settings.wazuh_password),
    use_ssl=use_ssl,
    verify_certs=settings.verify_ssl,
    ssl_show_warn=False,
    timeout=30,
)

# 1. Total count
count_res = client.count(index=settings.wazuh_index_pattern)
print(f"Total documents in {settings.wazuh_index_pattern}: {count_res.get('count')}")

# 2. Get top 100 most recent alerts
search_res = client.search(
    index=settings.wazuh_index_pattern,
    body={
        "size": 100,
        "sort": [{"timestamp": {"order": "desc"}}],
    }
)

hits = search_res.get("hits", {}).get("hits", [])
print(f"Retrieved hits: {len(hits)}")

rule_counts = Counter()
timestamps = []
abnormal_cmd_alerts = []
rule_100060_hits = []
rule_100061_hits = []

for hit in hits:
    src = hit.get("_source", {})
    rule = src.get("rule", {})
    rid = str(rule.get("id"))
    rdesc = rule.get("description", "")
    ts = src.get("timestamp") or src.get("@timestamp")
    rule_counts[(rid, rdesc)] += 1
    timestamps.append(ts)
    
    if "abnormal" in rdesc.lower() or "command prompt" in rdesc.lower():
        abnormal_cmd_alerts.append(hit)
    if rid == "100060":
        rule_100060_hits.append(hit)
    if rid == "100061":
        rule_100061_hits.append(hit)

print("\n--- Rule Distribution in Top Hits ---")
for (rid, rdesc), cnt in rule_counts.most_common(15):
    print(f"Rule {rid} ({cnt}x): {rdesc}")

if timestamps:
    print(f"\nMost recent alert timestamp: {timestamps[0]}")
    print(f"Oldest alert timestamp in sample: {timestamps[-1]}")

print(f"\nAbnormal command prompt alerts found: {len(abnormal_cmd_alerts)}")
for h in abnormal_cmd_alerts[:3]:
    print("\n--- Abnormal Command Alert Details ---")
    print(f"ID: {h.get('_id')}")
    src = h.get("_source", {})
    print(f"Timestamp: {src.get('timestamp')}")
    print(f"Rule: {src.get('rule')}")
    data = src.get("data", {})
    print(f"Data: {json.dumps(data, indent=2)}")

print(f"\nRule 100060 hits: {len(rule_100060_hits)}")
print(f"Rule 100061 hits: {len(rule_100061_hits)}")
