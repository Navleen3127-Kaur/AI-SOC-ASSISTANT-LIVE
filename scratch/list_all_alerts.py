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

res = client.search(
    index=settings.wazuh_index_pattern,
    body={
        "size": 100,
        "sort": [{"timestamp": {"order": "desc"}}],
    }
)

hits = res.get("hits", {}).get("hits", [])
print(f"Total hits returned: {len(hits)}")
print(f"{'#':<3} | {'Timestamp':<28} | {'Rule ID':<8} | {'Level':<5} | {'Description'}")
print("-" * 90)
for idx, hit in enumerate(hits):
    src = hit.get("_source", {})
    rule = src.get("rule", {})
    ts = src.get("timestamp") or src.get("@timestamp")
    rid = rule.get("id")
    lvl = rule.get("level")
    desc = rule.get("description")
    print(f"{idx+1:<3} | {ts:<28} | {rid:<8} | {lvl:<5} | {desc}")
