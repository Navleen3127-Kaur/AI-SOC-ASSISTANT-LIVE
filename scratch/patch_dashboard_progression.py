file_path = "c:/Users/navle/Desktop/soc/static/index.html"
with open(file_path, "r", encoding="utf-8") as f:
    html = f.read()

old_render_triage = """    async function renderIncidentTriage(inc) {
      const summaryEl = document.getElementById('work-summary');
      const narrativeEl = document.getElementById('work-narrative');
      const indicatorsEl = document.getElementById('work-indicators');

      const risk = inc.risk_score !== undefined ? inc.risk_score : (inc.severity === 'critical' ? 90.0 : 75.0);
      const conf = inc.confidence_score !== undefined ? inc.confidence_score : 90.0;
      const confLevel = inc.confidence_level !== undefined ? inc.confidence_level : 'Very High';
      const corr = inc.correlation_score !== undefined ? inc.correlation_score : (inc.alert_count > 1 ? 90.0 : 0.0);

      summaryEl.innerHTML = `
        <div style="background:var(--bg-dark); border:1px solid var(--border-color); padding:1rem; border-radius:8px; margin-bottom:1rem; font-size:0.8rem;">
          <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap:1rem; text-align:center;">
            <div style="border-right: 1px solid var(--border-color);">
              <div style="font-size:0.65rem; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.05em;">Risk Score</div>
              <div style="font-size:1.1rem; font-weight:bold; color:var(--critical); margin-top:0.25rem;">${risk}/100</div>
            </div>
            <div style="border-right: 1px solid var(--border-color);">
              <div style="font-size:0.65rem; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.05em;">Confidence</div>
              <div style="font-size:1.1rem; font-weight:bold; color:var(--low); margin-top:0.25rem;">${conf}%</div>
              <div style="font-size:0.65rem; color:var(--text-muted); font-weight:500; margin-top:0.1rem;">${confLevel}</div>
            </div>
            <div>
              <div style="font-size:0.65rem; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.05em;">Correlation</div>
              <div style="font-size:1.1rem; font-weight:bold; color:var(--accent-cyan); margin-top:0.25rem;">${corr}%</div>
            </div>
          </div>
        </div>
        
        <p><strong>Correlated Incident</strong> containing ${inc.alert_count} security alerts. Overall severity is <strong>${inc.severity.toUpperCase()}</strong>.</p>
        <div class="incident-report-controls" style="margin-top: 1rem; display: flex; gap: 0.5rem;">
          <button class="btn btn-accent" onclick="downloadIncidentReportFile(event, '${inc.incident_id}', 'markdown')"><i class="fa-solid fa-file-markdown"></i> Markdown</button>
          <button class="btn btn-accent" onclick="downloadIncidentReportFile(event, '${inc.incident_id}', 'pdf')"><i class="fa-solid fa-file-pdf"></i> PDF</button>
          <button class="btn btn-accent" onclick="downloadIncidentReportFile(event, '${inc.incident_id}', 'json')"><i class="fa-solid fa-file-code"></i> JSON</button>
        </div>
      `;"""

new_render_triage = """    async function renderIncidentTriage(inc) {
      const summaryEl = document.getElementById('work-summary');
      const narrativeEl = document.getElementById('work-narrative');
      const indicatorsEl = document.getElementById('work-indicators');

      const risk = inc.risk_score !== undefined ? inc.risk_score : (inc.severity === 'critical' ? 90.0 : 75.0);
      const conf = inc.confidence_score !== undefined ? inc.confidence_score : 90.0;
      const confLevel = inc.confidence_level !== undefined ? inc.confidence_level : 'Very High';
      const corr = inc.correlation_score !== undefined ? inc.correlation_score : (inc.alert_count > 1 ? 90.0 : 0.0);

      let flowHtml = '';
      if (inc.attack_progression && inc.attack_progression.length > 0) {
        flowHtml = `
          <div style="background:var(--bg-dark); border:1px solid var(--border-color); padding:1rem; border-radius:8px; margin-bottom:1rem;">
            <div style="font-size:0.65rem; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.05em; margin-bottom:0.5rem;">Cyber Kill Chain Attack Progression</div>
            <div style="display:flex; flex-wrap:wrap; align-items:center; gap:0.4rem; font-size:0.75rem;">
              ${inc.attack_progression.map((step, idx) => `
                <span style="background:rgba(6,182,212,0.1); color:var(--accent-cyan); border:1px solid rgba(6,182,212,0.3); padding:0.2rem 0.5rem; border-radius:4px; font-weight:600;">${step}</span>
                ${idx < inc.attack_progression.length - 1 ? '<i class="fa-solid fa-arrow-right" style="color:var(--text-muted); font-size:0.7rem;"></i>' : ''}
              `).join('')}
            </div>
          </div>
        `;
      }

      const metadataHtml = `
        <div style="background:var(--bg-dark); border:1px solid var(--border-color); padding:1rem; border-radius:8px; margin-bottom:1rem; font-size:0.75rem;">
          <div style="font-size:0.65rem; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.05em; margin-bottom:0.5rem;">Report Metadata</div>
          <div style="display:grid; grid-template-columns: 1fr 1fr; gap:0.5rem 1rem;">
            <div><span style="color:var(--text-muted)">Version:</span> <strong>${inc.report_version || '2.3'}</strong></div>
            <div><span style="color:var(--text-muted)">Author:</span> <strong>${inc.generated_by || 'AI SOC Analyst'}</strong></div>
            <div><span style="color:var(--text-muted)">Model:</span> <strong>${inc.llm_model || 'Qwen2.5:3B'}</strong></div>
            <div><span style="color:var(--text-muted)">Mode:</span> <strong>${inc.execution_mode || 'Offline Demo'}</strong></div>
          </div>
        </div>
      `;

      summaryEl.innerHTML = `
        <div style="background:var(--bg-dark); border:1px solid var(--border-color); padding:1rem; border-radius:8px; margin-bottom:1rem; font-size:0.8rem;">
          <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap:1rem; text-align:center;">
            <div style="border-right: 1px solid var(--border-color);">
              <div style="font-size:0.65rem; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.05em;">Risk Score</div>
              <div style="font-size:1.1rem; font-weight:bold; color:var(--critical); margin-top:0.25rem;">${risk}/100</div>
            </div>
            <div style="border-right: 1px solid var(--border-color);">
              <div style="font-size:0.65rem; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.05em;">Confidence</div>
              <div style="font-size:1.1rem; font-weight:bold; color:var(--low); margin-top:0.25rem;">${conf}%</div>
              <div style="font-size:0.65rem; color:var(--text-muted); font-weight:500; margin-top:0.1rem;">${confLevel}</div>
            </div>
            <div>
              <div style="font-size:0.65rem; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.05em;">Correlation</div>
              <div style="font-size:1.1rem; font-weight:bold; color:var(--accent-cyan); margin-top:0.25rem;">${corr}%</div>
            </div>
          </div>
        </div>
        
        ${flowHtml}
        ${metadataHtml}
        
        <p><strong>Correlated Incident</strong> containing ${inc.alert_count} security alerts. Overall severity is <strong>${inc.severity.toUpperCase()}</strong>.</p>
        <div class="incident-report-controls" style="margin-top: 1rem; display: flex; gap: 0.5rem;">
          <button class="btn btn-accent" onclick="downloadIncidentReportFile(event, '${inc.incident_id}', 'markdown')"><i class="fa-solid fa-file-markdown"></i> Markdown</button>
          <button class="btn btn-accent" onclick="downloadIncidentReportFile(event, '${inc.incident_id}', 'pdf')"><i class="fa-solid fa-file-pdf"></i> PDF</button>
          <button class="btn btn-accent" onclick="downloadIncidentReportFile(event, '${inc.incident_id}', 'json')"><i class="fa-solid fa-file-code"></i> JSON</button>
        </div>
      `;"""

html = html.replace(old_render_triage, new_render_triage)

with open(file_path, "w", encoding="utf-8") as f:
    f.write(html)

print("Dashboard progression UI patched successfully.")
