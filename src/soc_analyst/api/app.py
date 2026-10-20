"""FastAPI application for AI SOC Analyst."""

import asyncio
import json
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Response, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sse_starlette.sse import EventSourceResponse

from soc_analyst.agents.soc_analyst import SOCAnalystAgent
from soc_analyst.config import PROJECT_ROOT, get_settings
from soc_analyst.connectors.elasticsearch_client import ElasticsearchClient
from soc_analyst.mitre.attack_mapper import MitreAttackMapper
from soc_analyst.models.schemas import (
    AnalyzeAlertRequest,
    ChatRequest,
    SearchAlertsRequest,
)
from soc_analyst.services.alert_processor import AlertProcessor
from soc_analyst.services.report_generator import render_incident_report

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

processor: AlertProcessor | None = None
soc_agent: SOCAnalystAgent | None = None
mitre_mapper: MitreAttackMapper | None = None
es_client: ElasticsearchClient | None = None


def _get_processor() -> AlertProcessor:
    global processor
    if processor is None:
        processor = AlertProcessor()
    return processor


def _get_soc_agent() -> SOCAnalystAgent:
    global soc_agent
    if soc_agent is None:
        soc_agent = SOCAnalystAgent()
    return soc_agent


def _get_mitre_mapper() -> MitreAttackMapper:
    global mitre_mapper
    if mitre_mapper is None:
        mitre_mapper = MitreAttackMapper()
    return mitre_mapper


def _get_es_client() -> ElasticsearchClient:
    global es_client
    if es_client is None:
        es_client = ElasticsearchClient()
    return es_client


background_poll_task = None


async def continuous_alert_poller():
    """Runs a continuous background loop to fetch new alerts and analyze them."""
    settings = get_settings()
    logger.info("Starting background alert poller background loop...")
    
    # We wait a couple of seconds on startup to let everything initialize
    await asyncio.sleep(2.0)
    
    while True:
        try:
            proc = _get_processor()
            
            # Fetch new alerts directly from LiveAlertFetcher
            new_alerts = await proc.live_fetcher.fetch_new_alerts()
            
            if new_alerts:
                logger.info("[POLL] Processing %d new alerts in background pipeline...", len(new_alerts))
                for alert in new_alerts:
                    proc.record_live_alert(alert)
                    already_analyzed = alert.id in proc._analysis_cache
                    analysis = await proc.analyze_single(alert)
                    
                    status_log = "AI analysis invoked (new event)" if not already_analyzed else "AI analysis skipped (cached deduplication)"
                    inc_match = any(alert.id in [a.get("id") if isinstance(a, dict) else a.id for a in inc.get("alerts", [])] for inc in proc._incident_cache)
                    inc_str = "Associated with incident" if inc_match else "Standalone alert"
                    
                    logger.info(
                        "[ALERT PROCESSED] ID: %s | Severity: %s | Classification: %s | %s | %s",
                        alert.id,
                        analysis.severity.value.upper(),
                        analysis.category or "Security Alert",
                        status_log,
                        inc_str,
                    )
            
        except Exception as exc:
            logger.error("Error in background alert poller loop: %s", exc)
            
        await asyncio.sleep(settings.polling_interval)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global background_poll_task
    logger.info("AI SOC Analyst starting up...")
    
    # Spawn the background poller task
    background_poll_task = asyncio.create_task(continuous_alert_poller())
    
    yield
    
    # Cancel the background task on shutdown
    if background_poll_task:
        background_poll_task.cancel()
        try:
            await background_poll_task
        except asyncio.CancelledError:
            pass
            
    if processor is not None:
        processor.stop()
    logger.info("AI SOC Analyst shut down.")


app = FastAPI(
    title="AI SOC Analyst",
    description=(
        "AI-powered Security Operations Center analyst for Wazuh/Elasticsearch. "
        "Investigates alerts, maps MITRE ATT&CK, generates incident reports."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

static_dir = PROJECT_ROOT / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/")
async def dashboard():
    index = static_dir / "index.html"
    if index.exists():
        return FileResponse(index)
    return {"message": "AI SOC Analyst API", "docs": "/docs"}


@app.get("/health")
async def health():
    es_health = _get_es_client().health_check()
    settings = get_settings()
    proc = _get_processor()
    return {
        "status": "ok",
        "llm_provider": settings.llm_provider,
        "elasticsearch": es_health,
        "cached_analyses": len(proc.cache),
    }


from pydantic import BaseModel

class SettingsUpdateRequest(BaseModel):
    llm_provider: str | None = None
    openai_api_key: str | None = None
    openai_model: str | None = None
    ollama_base_url: str | None = None
    ollama_model: str | None = None
    elasticsearch_host: str | None = None
    elasticsearch_user: str | None = None
    elasticsearch_password: str | None = None
    elasticsearch_verify_certs: bool | None = None
    wazuh_alerts_index: str | None = None
    alert_poll_interval_seconds: int | None = None
    max_alerts_per_batch: int | None = None
    virustotal_api_key: str | None = None
    abuseipdb_api_key: str | None = None


@app.get("/api/settings")
async def get_current_settings():
    settings = get_settings()
    
    def mask_key(k: str) -> str:
        if not k: return ""
        return f"{k[:4]}...{k[-4:]}" if len(k) > 8 else "********"

    return {
        "llm_provider": settings.llm_provider,
        "openai_api_key_masked": mask_key(settings.openai_api_key),
        "openai_api_key_set": bool(settings.openai_api_key),
        "openai_model": settings.openai_model,
        "ollama_base_url": settings.ollama_base_url,
        "ollama_model": settings.ollama_model,
        "elasticsearch_host": settings.elasticsearch_host,
        "elasticsearch_user": settings.elasticsearch_user,
        "elasticsearch_verify_certs": settings.elasticsearch_verify_certs,
        "wazuh_alerts_index": settings.wazuh_alerts_index,
        "alert_poll_interval_seconds": settings.alert_poll_interval_seconds,
        "max_alerts_per_batch": settings.max_alerts_per_batch,
        "virustotal_api_key_masked": mask_key(settings.virustotal_api_key),
        "virustotal_api_key_set": bool(settings.virustotal_api_key),
        "abuseipdb_api_key_masked": mask_key(settings.abuseipdb_api_key),
        "abuseipdb_api_key_set": bool(settings.abuseipdb_api_key),
    }


@app.post("/api/settings")
async def update_settings(request: SettingsUpdateRequest):
    update_data = {}
    
    for field, value in request.model_dump(exclude_unset=True).items():
        if field in ["openai_api_key", "virustotal_api_key", "abuseipdb_api_key"]:
            if value is not None:
                if "..." in value or value == "********":
                    continue
                update_data[field] = value
        elif value is not None:
            update_data[field] = value
            
    if update_data:
        from soc_analyst.config import save_settings
        save_settings(update_data)
        
        # Flush cached agent and connection instances
        global processor, soc_agent, mitre_mapper, es_client
        if processor is not None:
            processor.stop()
            processor = None
        soc_agent = None
        mitre_mapper = None
        es_client = None
        
    return {"status": "success", "message": "Settings updated and services reloaded."}



@app.post("/alerts/search")
async def search_alerts(request: SearchAlertsRequest):
    try:
        alerts = _get_es_client().search_alerts(
            query=request.query,
            hours_back=request.hours_back,
            min_rule_level=request.severity_min,
            limit=request.limit,
        )
        return {"count": len(alerts), "alerts": [a.model_dump() for a in alerts]}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Elasticsearch error: {exc}")


@app.get("/alerts/prioritized")
async def prioritized_alerts(
    hours_back: int = Query(24, ge=1, le=168),
    limit: int = Query(50, ge=1, le=200),
    mode: str = Query("live", pattern="^(live|demo|history)$"),
):
    try:
        queue = await _get_processor().get_prioritized_queue(hours_back, limit, mode=mode)
        return {"count": len(queue), "alerts": queue}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@app.post("/alerts/analyze")
async def analyze_alert(request: AnalyzeAlertRequest):
    alert = request.alert

    if not alert and request.alert_id:
        if request.alert_id.startswith("demo-"):
            alert = next((a for a in _get_processor().seed_demo_alerts() if a.id == request.alert_id), None)
        else:
            try:
                alert = _get_es_client().get_alert_by_id(request.alert_id)
            except Exception:
                alert = None

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    analysis = await _get_processor().analyze_single(alert)
    return analysis.model_dump()


@app.get("/alerts/{alert_id}/analysis")
async def get_analysis(alert_id: str):
    proc = _get_processor()
    cached = proc.get_cached_analysis(alert_id)
    if cached:
        return cached.model_dump()

    analysis = await proc.analyze_by_id(alert_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Alert not found")
    return analysis.model_dump()


@app.get("/stream/alerts")
async def stream_alerts():
    """Server-Sent Events stream of real-time alert analyses."""

    async def event_generator():
        async for analysis in _get_processor().stream_new_alerts():
            yield {
                "event": "alert_analysis",
                "data": json.dumps(analysis.model_dump(), default=str),
            }

    return EventSourceResponse(event_generator())


@app.post("/incidents/report")
async def generate_incident_report(
    alert_ids: list[str] = Body(...),
    title: str = "Security Incident",
):
    proc = _get_processor()
    analyses = []
    for aid in alert_ids:
        cached = proc.get_cached_analysis(aid)
        if cached:
            analyses.append(cached)
            continue
        result = await proc.analyze_by_id(aid)
        if result:
            analyses.append(result)

    if not analyses:
        raise HTTPException(status_code=404, detail="No alerts found to analyze")

    report = _get_soc_agent().generate_incident_report(analyses, title)
    markdown = render_incident_report(report)
    return {
        "report": report.model_dump(),
        "markdown": markdown,
    }

@app.post("/incidents/report/download")
@app.post("/api/reports/download")
async def download_incident_report(
    alert_ids: list[str] = Body(...),
    title: str = "Security Incident",
    format: str = Query("markdown", pattern="^(markdown|json|pdf)$"),
):
    proc = _get_processor()
    analyses = []
    for aid in alert_ids:
        cached = proc.get_cached_analysis(aid)
        if cached:
            analyses.append(cached)
            continue
        result = await proc.analyze_by_id(aid)
        if result:
            analyses.append(result)

    if not analyses:
        raise HTTPException(status_code=404, detail="No alerts found to analyze")

    report = _get_soc_agent().generate_incident_report(analyses, title)
    
    if format == "json":
        json_content = report.model_dump_json(indent=2)
        return Response(
            content=json_content,
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={report.incident_id}.json"},
        )
    elif format == "pdf":
        from soc_analyst.services.report_generator import render_pdf_report
        try:
            pdf_bytes = render_pdf_report(report)
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename={report.incident_id}.pdf"},
            )
        except Exception as e:
            logger.error("Failed to generate PDF: %s", e)
            raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")
    else:  # markdown
        markdown = render_incident_report(report)
        return Response(
            content=markdown,
            media_type="text/markdown",
            headers={"Content-Disposition": f"attachment; filename={report.incident_id}.md"},
        )


@app.get("/incidents/correlated")
async def correlated_incidents(
    hours_back: int = Query(24, ge=1, le=168),
    limit: int = Query(100, ge=1, le=500),
    mode: str = Query("live", pattern="^(live|demo|history)$"),
):
    proc = _get_processor()
    # In live mode, if incident cache is already populated, return it; otherwise calculate
    if mode == "live" and proc._incident_cache:
        incidents = proc._incident_cache
    else:
        incidents = proc.get_correlated_incidents(mode=mode, hours_back=hours_back, limit=limit)
        if not incidents and proc._incident_cache:
            incidents = proc._incident_cache
    return {
        "count": len(incidents),
        "incidents": incidents
    }


@app.post("/chat")
async def chat_with_analyst(request: ChatRequest):
    alert = None
    related = []

    proc = _get_processor()
    if request.incident_id:
        incident = next((inc for inc in proc._incident_cache if inc["incident_id"] == request.incident_id), None)
        if incident:
            alerts_in_inc = []
            for alert_dict in incident.get("alerts", []):
                if isinstance(alert_dict, dict):
                    alerts_in_inc.append(SecurityAlert(**alert_dict))
                else:
                    alerts_in_inc.append(alert_dict)
            if alerts_in_inc:
                alert = alerts_in_inc[0]
                related = alerts_in_inc[1:]
    elif request.alert_id:
        if request.alert_id.startswith("demo-"):
            alert = next((a for a in proc.seed_demo_alerts() if a.id == request.alert_id), None)
            related = []
        else:
            try:
                alert = _get_es_client().get_alert_by_id(request.alert_id)
                if alert:
                    related = _get_es_client().get_related_events(
                        alert, hours_back=request.context_hours
                    )
            except Exception:
                related = []

    # Check if offline mode is active or fallback is needed
    settings = get_settings()
    if settings.enable_offline_mode:
        msg_lower = request.message.lower()
        if "remediate" in msg_lower or "mitigate" in msg_lower or "contain" in msg_lower:
            response = (
                "**Recommended Triage Response Playbook Actions:**\n\n"
                "1. **Host Isolation**: Disconnect `web-server-01` (`10.0.1.15`) from the network immediately to prevent lateral movement.\n"
                "2. **Process Termination**: Terminate active `vssadmin.exe` and `powershell.exe` execution trees.\n"
                "3. **Credential Revocation**: Disable the compromised `admin` user account, expire active sessions, and mandate a password reset.\n"
                "4. **IP Blacklisting**: Block malicious source IP `203.0.113.45` on edge firewalls and load balancers."
            )
        elif "threat" in msg_lower or "explain" in msg_lower or "what is" in msg_lower:
            response = (
                "**Threat Vector Analysis:**\n\n"
                "This incident represents a multi-stage intrusion target targeting `web-server-01`:\n"
                "- **Stage 1 (Access)**: External brute force attempts from `203.0.113.45` trying to guess the `admin` password.\n"
                "- **Stage 2 (Execution)**: A suspicious encoded PowerShell command executing downloading cradles (`http://malicious.example/payload`).\n"
                "- **Stage 3 (Impact)**: Removal of local volume shadow copies using `vssadmin.exe` to inhibit backup restoration before encryption."
            )
        elif "mitre" in msg_lower or "attack" in msg_lower:
            response = (
                "**MITRE ATT&CK Mapping Summary:**\n\n"
                "- **T1110 (Brute Force)**: Credential Access tactic (SSH attempts).\n"
                "- **T1059.001 (PowerShell)**: Execution tactic (encoded download command).\n"
                "- **T1486 (Data Encrypted for Impact)**: Impact tactic (volume shadow copy deletion)."
            )
        else:
            response = (
                "I am your AI SOC Assistant in offline mode. I have analyzed the correlated alerts on `web-server-01` showing brute-forcing, defense evasion, and shadow deletion. "
                "Ask me about: **explain threat**, **recommend remediation**, or **explain MITRE mappings**."
            )
        return {"response": response}

    try:
        response = _get_soc_agent().chat(request.message, alert, related)
    except Exception as exc:
        logger.warning("Live LLM chat failed: %s. Falling back to offline response.", exc)
        msg_lower = request.message.lower()
        if "remediate" in msg_lower or "mitigate" in msg_lower:
            response = "Live LLM offline. **Remediation Suggestion:** Isolate `web-server-01` and terminate all suspicious `powershell.exe` / `vssadmin.exe` processes."
        else:
            response = "Live LLM offline. Correlated alerts indicate potential credential access followed by encoded execution and shadow copy deletion."
            
    return {"response": response}


@app.get("/mitre/search")
async def search_mitre(q: str = Query(..., min_length=2), limit: int = 5):
    results = _get_mitre_mapper().search_techniques(q, limit)
    return {"count": len(results), "techniques": [r.model_dump() for r in results]}


@app.get("/mitre/map/{alert_id}")
async def map_alert_to_mitre(alert_id: str):
    if alert_id.startswith("demo-"):
        alert = next((a for a in _get_processor().seed_demo_alerts() if a.id == alert_id), None)
    else:
        try:
            alert = _get_es_client().get_alert_by_id(alert_id)
        except Exception:
            alert = None

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    mapper = _get_mitre_mapper()
    mappings = mapper.map_alert(alert)
    return {
        "alert_id": alert_id,
        "mappings": [m.model_dump() for m in mappings],
        "tactics": mapper.get_tactic_summary(mappings),
    }


@app.get("/api/iocs/enrich")
async def enrich_ioc_api(value: str = Query(..., min_length=1)):
    from soc_analyst.services.ioc_extractor import IOCOxtractor
    try:
        enriched = IOCOxtractor.enrich_ioc(value)
        return enriched
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


class IncidentStatusUpdate(BaseModel):
    status: str


@app.post("/api/incidents/{incident_id}/status")
async def update_incident_status(incident_id: str, request: IncidentStatusUpdate):
    proc = _get_processor()
    status = request.status
    if status not in ["Open", "Investigating", "Resolved", "Closed"]:
        raise HTTPException(status_code=400, detail="Invalid incident status. Must be Open, Investigating, Resolved, or Closed.")
    
    # Store status
    proc._incident_statuses[incident_id] = status
    
    # Update cache
    for inc in proc._incident_cache:
        if inc["incident_id"] == incident_id:
            inc["status"] = status
            
    return {"status": "success", "message": f"Incident {incident_id} status updated to {status}."}


@app.post("/demo/analyze")
async def demo_analyze():
    """Analyze sample alerts without Elasticsearch connection."""
    proc = _get_processor()
    demo_alerts = proc.seed_demo_alerts()
    results = []
    for alert in demo_alerts:
        analysis = await proc.analyze_single(alert)
        results.append(analysis.model_dump())

    report = _get_soc_agent().generate_incident_report(
        [proc.cache[a.id] for a in demo_alerts if a.id in proc.cache],
        incident_title="Demo Security Incident",
    )

    return {
        "analyses": results,
        "incident_report_markdown": render_incident_report(report),
        "alerts": [a.model_dump() for a in demo_alerts],
    }


@app.post("/demo/reset")
async def demo_reset():
    """Reset the demo state: clear seen IDs, clear analysis cache, clear incident cache, clear statuses."""
    proc = _get_processor()
    proc._analysis_cache.clear()
    proc._incident_cache.clear()
    proc._incident_statuses.clear()
    proc._seen_ids.clear()
    
    # Delete seen_ids file if exists
    if proc.seen_ids_file.exists():
        try:
            proc.seen_ids_file.unlink()
        except Exception:
            pass
            
    return {"status": "success", "message": "Demo state reset successfully."}
