# AI SOC Analyst

An AI-powered Security Operations Center (SOC) analyst that investigates Wazuh/Elasticsearch alerts in real time — explaining threats in plain language, mapping to MITRE ATT&CK, prioritizing critical alerts, and generating incident reports with remediation steps.

## Features

- **Automatic alert analysis** — Pulls alerts from Wazuh indices in Elasticsearch and analyzes them with LangChain + LLM
- **Plain-language threat explanations** — Translates technical SIEM events into actionable narratives
- **MITRE ATT&CK mapping** — Maps alerts to techniques via Wazuh rule metadata, keyword rules, and the `attackcti` database
- **Alert prioritization** — Scores alerts by severity, rule level, MITRE tactics, and indicators
- **Incident reports** — Generates markdown reports with timeline, containment, eradication, and recovery steps
- **Real-time streaming** — SSE endpoint and CLI watch mode for live alert processing
- **Interactive chat** — Ask follow-up questions about specific alerts
- **Web dashboard** — Browser UI at `http://localhost:8000`

## Architecture

```
Wazuh Agents → Wazuh Manager → Elasticsearch (wazuh-alerts-*)
                                        ↓
                              AI SOC Analyst (FastAPI)
                                        ↓
                    ┌───────────────────┼───────────────────┐
                    ↓                   ↓                   ↓
            LangChain Agent      MITRE ATT&CK Mapper    Prioritizer
            (OpenAI/Ollama)      (attackcti)            (scoring)
```

## Quick Start

### 1. Install

```bash
cd soc
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -e .
cp .env.example .env            # Edit with your keys
```

### 2. Configure LLM

**OpenAI** (default in `.env`):
```
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-your-key
OPENAI_MODEL=gpt-4o-mini
```

**Ollama** (open source, local):
```
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2
```

### 3. Run Demo (no Elasticsearch required)

```bash
soc-analyst analyze --demo
soc-analyst report --demo -o reports/incident.md
```

### 4. Start API + Dashboard

```bash
soc-analyst serve
```

Open [http://localhost:8000](http://localhost:8000) for the dashboard, or [http://localhost:8000/docs](http://localhost:8000/docs) for the API.

## CLI Commands

| Command | Description |
|---------|-------------|
| `soc-analyst serve` | Start FastAPI server |
| `soc-analyst analyze --demo` | Analyze sample alerts |
| `soc-analyst analyze --alert-id <id>` | Analyze a specific alert |
| `soc-analyst prioritize` | Show prioritized alert queue |
| `soc-analyst watch` | Real-time alert monitoring |
| `soc-analyst report --demo -o report.md` | Generate incident report |

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/alerts/search` | Search Wazuh alerts |
| `GET` | `/alerts/prioritized` | Prioritized alert queue |
| `POST` | `/alerts/analyze` | Analyze an alert |
| `GET` | `/stream/alerts` | SSE real-time alert stream |
| `GET` | `/incidents/correlated` | Get correlated incidents cache |
| `POST` | `/api/incidents/{incident_id}/status` | Update incident status |
| `GET` | `/api/iocs/enrich` | Enrich threat intelligence for IOC |
| `POST` | `/incidents/report/download` | Download incident report (markdown, json, pdf) |
| `POST` | `/api/reports/download` | Download report (alias) |
| `POST` | `/chat` | Chat with SOC analyst (supports incident context) |
| `GET` | `/mitre/search?q=` | Search MITRE techniques |
| `POST` | `/demo/analyze` | Demo mode |

## Elasticsearch / Wazuh Setup

Point the app at your Wazuh alerts index:

```env
ELASTICSEARCH_HOST=http://localhost:9200
ELASTICSEARCH_USER=elastic
ELASTICSEARCH_PASSWORD=changeme
WAZUH_ALERTS_INDEX=wazuh-alerts-*
```

Use the included `docker-compose.yml` to spin up ELK + Wazuh locally:

```bash
docker compose up -d elasticsearch kibana wazuh-indexer wazuh-manager
docker compose --profile ollama up -d ollama   # optional local LLM
docker compose --profile app up -d soc-analyst # run the analyst in Docker
```

## Project Structure

```
soc/
├── src/soc_analyst/
│   ├── agents/          # LangChain SOC agent, prioritizer, LLM factory
│   ├── api/             # FastAPI routes
│   ├── connectors/      # Elasticsearch + Wazuh clients
│   ├── mitre/           # MITRE ATT&CK mapper
│   ├── models/          # Pydantic schemas
│   ├── services/        # Alert processor, report generator
│   └── templates/       # Incident report Jinja2 template
├── static/              # Web dashboard
├── config/              # YAML settings
├── docker-compose.yml
└── requirements.txt
```

## Example Output

For a PowerShell execution alert, the analyst produces:

- **Summary**: Suspicious encoded PowerShell command detected on workstation-42
- **MITRE**: T1059.001 (PowerShell) — Execution
- **Priority**: 85/100 — HIGH
- **Remediation**: Isolate host, collect memory dump, block C2 domain
- **False positive likelihood**: Low — encoded download cradle pattern

## License

MIT
