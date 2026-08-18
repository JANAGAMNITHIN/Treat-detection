/**
 * ThreatScope Dashboard Application Script
 */

const appState = {
  currentScan: null,
  activeNav: 'dashboard',
  recentScans: [],
  kpiStats: {
    total: 42587,
    malicious: 3481,
    suspicious: 6214,
    clean: 32892,
    avgScore: 76,
  },
};

document.addEventListener('DOMContentLoaded', () => {
  initIcons();
  initSidebarNavigation();
  initScanForms();
  initFileDropZone();
  initSupportedPills();
  initRecentScansActions();
  initBulkView();
  initHistoryView();
  initApiIntegrations();
  loadInitialHistory();
});

function initIcons() {
  if (window.lucide) {
    window.lucide.createIcons();
  }
}

/* ================= 1. SIDEBAR NAVIGATION ================= */
function initSidebarNavigation() {
  const navItems = document.querySelectorAll('.nav-item');
  
  navItems.forEach(item => {
    item.addEventListener('click', () => {
      const navTarget = item.getAttribute('data-nav');
      switchView(navTarget);
    });
  });

  // Action links inside cards
  document.getElementById('btn-view-full-report').addEventListener('click', () => switchView('scan'));
  document.getElementById('btn-view-all-sources').addEventListener('click', () => switchView('intel'));
  document.getElementById('btn-view-all-history').addEventListener('click', () => switchView('history'));
}

function switchView(viewName) {
  appState.activeNav = viewName;

  // Update sidebar active buttons
  document.querySelectorAll('.nav-item').forEach(btn => {
    if (btn.getAttribute('data-nav') === viewName) {
      btn.classList.add('active');
    } else {
      btn.classList.remove('active');
    }
  });

  // Update views
  document.querySelectorAll('.app-view').forEach(view => {
    view.classList.remove('active');
  });

  let targetViewId = 'view-dashboard';
  if (viewName === 'scan') targetViewId = 'view-scan';
  else if (viewName === 'bulk-scan') targetViewId = 'view-bulk-scan';
  else if (viewName === 'history') {
    targetViewId = 'view-history';
    loadHistoryPage();
  }
  else if (viewName === 'intel') {
    targetViewId = 'view-intel';
    loadIntelPage();
  }
  else if (viewName === 'whitelist') targetViewId = 'view-whitelist';
  else if (viewName === 'api-keys' || viewName === 'settings') {
    targetViewId = 'view-api-keys';
    loadApiKeysStatus();
  }

  const targetEl = document.getElementById(targetViewId);
  if (targetEl) {
    targetEl.classList.add('active');
  }

  window.scrollTo({ top: 0, behavior: 'smooth' });
  initIcons();
}

/* ================= 2. SCAN FORMS & SUBMISSION ================= */
function initScanForms() {
  const dashboardForm = document.getElementById('dashboard-scan-form');
  const dashboardInput = document.getElementById('dashboard-ioc-input');
  const btnDashboardScan = document.getElementById('btn-dashboard-scan');

  const topSearchBtn = document.getElementById('top-search-btn');
  const topSearchInput = document.getElementById('top-ioc-search');

  // Main Dashboard Form
  dashboardForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const indicator = dashboardInput.value.trim();
    if (!indicator) return;
    executeScan(indicator);
  });

  // Top Search Bar
  topSearchBtn.addEventListener('click', () => {
    const indicator = topSearchInput.value.trim();
    if (!indicator) return;
    executeScan(indicator);
  });

  topSearchInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      const indicator = topSearchInput.value.trim();
      if (!indicator) return;
      executeScan(indicator);
    }
  });

  // Paste from clipboard helper
  document.getElementById('btn-input-paste').addEventListener('click', async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        dashboardInput.value = text;
        showToast('Pasted from clipboard', 'success');
      }
    } catch (err) {
      showToast('Clipboard permission needed', 'error');
    }
  });

  // Upload trigger inside input bar
  document.getElementById('btn-input-upload').addEventListener('click', () => {
    document.getElementById('dashboard-file-input').click();
  });

  // Copy latest indicator button
  document.getElementById('btn-copy-latest-ioc').addEventListener('click', () => {
    const text = document.getElementById('latest-ioc-text').textContent;
    navigator.clipboard.writeText(text).then(() => {
      showToast('Indicator copied to clipboard', 'success');
    });
  });

  // Raw JSON Modal Close
  document.getElementById('btn-close-modal-json').addEventListener('click', () => {
    document.getElementById('dashboard-raw-json-modal').classList.add('hidden');
  });
}

async function executeScan(indicator) {
  const btnScan = document.getElementById('btn-dashboard-scan');
  btnScan.disabled = true;
  btnScan.innerHTML = `<span>Scanning...</span>`;

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ indicator: indicator, force_refresh: false }),
    });

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.detail || `Scan failed (HTTP ${res.status})`);
    }

    const scanData = await res.json();
    appState.currentScan = scanData;

    // Switch to Dashboard view and update all panels
    switchView('dashboard');
    updateDashboardPanels(scanData);
    prependRecentScanRow(scanData);
    incrementKPICounters(scanData.verdict);
    renderFullScanReport(scanData);

    showToast(`Scan complete for ${scanData.defanged_indicator}`, 'success');
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    btnScan.disabled = false;
    btnScan.innerHTML = `<span>Scan Now</span>`;
    initIcons();
  }
}

/* ================= 3. UPDATE DASHBOARD PANELS ================= */
function updateDashboardPanels(data) {
  // 1. Latest Scan Result Header
  const verdictTag = document.getElementById('latest-verdict-tag');
  const iocText = document.getElementById('latest-ioc-text');
  const iocMeta = document.getElementById('latest-ioc-sub');
  const scoreNum = document.getElementById('latest-score-number');
  const ringCircle = document.getElementById('latest-ring-circle');

  const verdictUpper = data.verdict.toUpperCase();
  verdictTag.textContent = verdictUpper;
  verdictTag.className = `verdict-tag-pill ${getVerdictClass(data.verdict)}`;

  iocText.textContent = data.defanged_indicator || data.indicator;
  iocMeta.textContent = `${data.type.toUpperCase()} • Scanned just now`;

  const scoreVal = Math.round(data.confidence_score);
  scoreNum.textContent = scoreVal;
  scoreNum.className = `dial-main-num ${getScoreColorClass(data.verdict, scoreVal)}`;

  ringCircle.setAttribute('stroke-dasharray', `${scoreVal}, 100`);

  // Summary Text
  const summaryEl = document.getElementById('latest-summary-text');
  if (data.verdict === 'malicious') {
    summaryEl.textContent = `This ${data.type.toUpperCase()} is detected as malicious by multiple security intelligence feeds. It represents an elevated security hazard.`;
  } else if (data.verdict === 'suspicious') {
    summaryEl.textContent = `This ${data.type.toUpperCase()} exhibits suspicious heuristic indicators or newly registered characteristics. Further monitoring recommended.`;
  } else if (data.verdict === 'clean') {
    summaryEl.textContent = `This ${data.type.toUpperCase()} was evaluated against active security datasets and verified clean with 0 malicious signals.`;
  } else {
    summaryEl.textContent = `No active threat reputation or malicious records observed for this indicator.`;
  }

  // 4 Stats Badges
  document.getElementById('latest-stat-date').textContent = new Date(data.scanned_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const validSources = data.sources.filter(s => s.status !== 'skipped');
  const maliciousSources = data.sources.filter(s => s.verdict === 'malicious');
  
  document.getElementById('latest-stat-sources').textContent = `${validSources.length} / 18`;
  document.getElementById('latest-stat-detections').textContent = `${maliciousSources.length}`;
  document.getElementById('latest-stat-verdict').textContent = verdictUpper;
  document.getElementById('latest-stat-verdict').className = `stat-val ${getVerdictColorClass(data.verdict)}`;

  // Risk Factors & Tags
  const factorsList = document.getElementById('latest-factors-list');
  factorsList.innerHTML = '';
  if (data.scoring_breakdown && data.scoring_breakdown.length > 0) {
    data.scoring_breakdown.slice(0, 4).forEach(f => {
      const li = document.createElement('li');
      li.textContent = `• ${f.reason}`;
      factorsList.appendChild(li);
    });
  } else {
    factorsList.innerHTML = `<li>• No adverse risk factors recorded</li><li>• Benign profile verified</li>`;
  }

  const tagsList = document.getElementById('latest-tags-list');
  tagsList.innerHTML = '';
  const tags = [`type-${data.type}`];
  if (data.verdict === 'malicious') tags.push('threat-flagged', 'reputation-penalty');
  if (data.verdict === 'suspicious') tags.push('elevated-risk');
  if (data.verdict === 'clean') tags.push('verified-clean', 'whitelisted');

  tags.forEach(t => {
    const span = document.createElement('span');
    span.className = 'pill-tag';
    span.textContent = t;
    tagsList.appendChild(span);
  });

  // 2. Source Breakdown List
  const sourcesContainer = document.getElementById('dashboard-sources-list');
  if (data.sources && data.sources.length > 0) {
    sourcesContainer.innerHTML = '';
    data.sources.forEach(src => {
      const row = document.createElement('div');
      row.className = 'source-row';
      const vClass = getVerdictClass(src.verdict);
      row.innerHTML = `
        <div class="source-info">
          <div class="source-icon-box">
            <i data-lucide="${getSourceIcon(src.name)}"></i>
          </div>
          <span class="source-name">${escapeHtml(src.name)}</span>
        </div>
        <div class="source-verdict-right">
          <span class="badge-source-verdict ${vClass}">${src.verdict}</span>
          <i data-lucide="chevron-right"></i>
        </div>
      `;
      sourcesContainer.appendChild(row);
    });
  }

  // 3. Risk Score Donut Gauge & Legend
  document.getElementById('donut-score-val').textContent = scoreVal;
  const donutRisk = document.getElementById('donut-risk-label');
  donutRisk.textContent = `${data.risk_level} RISK`;
  donutRisk.style.color = getScoreHexColor(data.verdict, scoreVal);

  initIcons();
}

function getVerdictClass(verdict) {
  if (verdict === 'malicious') return 'tag-malicious';
  if (verdict === 'suspicious') return 'tag-suspicious';
  if (verdict === 'clean') return 'tag-clean';
  return 'tag-clean';
}

function getVerdictColorClass(verdict) {
  if (verdict === 'malicious') return 'text-red';
  if (verdict === 'suspicious') return 'text-orange';
  if (verdict === 'clean') return 'text-green';
  return 'text-muted';
}

function getScoreColorClass(verdict, score) {
  if (verdict === 'malicious' || score >= 65) return 'score-red';
  if (verdict === 'suspicious' || score >= 30) return 'score-orange';
  if (verdict === 'clean') return 'score-green';
  return 'score-orange';
}

function getScoreHexColor(verdict, score) {
  if (verdict === 'malicious' || score >= 65) return '#ef4444';
  if (verdict === 'suspicious' || score >= 30) return '#f97316';
  if (verdict === 'clean') return '#10b981';
  return '#94a3b8';
}

function getSourceIcon(name) {
  if (name.includes('VirusTotal')) return 'shield';
  if (name.includes('Safe Browsing')) return 'globe';
  if (name.includes('URLScan')) return 'external-link';
  if (name.includes('MalwareBazaar')) return 'anchor';
  if (name.includes('AbuseIPDB')) return 'database';
  if (name.includes('WHOIS')) return 'info';
  return 'shield-check';
}

/* ================= 4. FILE DRAG & DROP ================= */
function initFileDropZone() {
  const dropZone = document.getElementById('dashboard-file-dropzone');
  const fileInput = document.getElementById('dashboard-file-input');

  dropZone.addEventListener('click', () => fileInput.click());

  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
  });

  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
  });

  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
      handleFileUpload(fileInput.files[0]);
    }
  });
}

async function handleFileUpload(file) {
  showToast(`Uploading and hashing ${file.name}...`, 'success');

  try {
    const formData = new FormData();
    formData.append('file', file);

    const res = await fetch('/api/scan/file', {
      method: 'POST',
      body: formData,
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'File scan failed');
    }

    const scanData = await res.json();
    appState.currentScan = scanData;

    switchView('dashboard');
    updateDashboardPanels(scanData);
    prependRecentScanRow(scanData);
    incrementKPICounters(scanData.verdict);
    renderFullScanReport(scanData);

    showToast(`File scan complete: SHA-256 ${scanData.defanged_indicator.slice(0, 16)}...`, 'success');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

/* ================= 5. SUPPORTED SAMPLE PILLS ================= */
function initSupportedPills() {
  document.querySelectorAll('.type-pill').forEach(pill => {
    if (pill.id === 'pill-file-trigger') {
      pill.addEventListener('click', () => {
        document.getElementById('dashboard-file-input').click();
      });
      return;
    }

    pill.addEventListener('click', () => {
      const sample = pill.getAttribute('data-sample');
      if (sample) {
        document.getElementById('dashboard-ioc-input').value = sample;
        executeScan(sample);
      }
    });
  });
}

/* ================= 6. RECENT SCANS TABLE & LOG ================= */
function prependRecentScanRow(data) {
  const tbody = document.getElementById('recent-scans-tbody');
  const tr = document.createElement('tr');
  const vClass = getVerdictClass(data.verdict);
  const sClass = getScoreColorClass(data.verdict, data.confidence_score);

  tr.innerHTML = `
    <td><code>${escapeHtml(data.defanged_indicator || data.indicator)}</code></td>
    <td><span class="type-cell-tag">${data.type.toUpperCase()}</span></td>
    <td><span class="badge-source-verdict ${vClass}">${data.verdict}</span></td>
    <td><strong class="score-num-cell ${sClass}">${Math.round(data.confidence_score)}</strong></td>
    <td><span class="sources-count-cell">${data.sources.length} / 18</span></td>
    <td><span class="time-cell">Just now</span></td>
    <td class="text-right actions-cell">
      <button class="btn-table-action btn-inspect" data-id="${data.id}" title="Inspect Scan Details"><i data-lucide="eye"></i></button>
      <button class="btn-table-action btn-export-raw" title="View Raw JSON"><i data-lucide="file-text"></i></button>
    </td>
  `;

  tbody.insertBefore(tr, tbody.firstChild);

  // Wire new inspect button
  tr.querySelector('.btn-inspect').addEventListener('click', () => {
    renderFullScanReport(data);
    switchView('scan');
  });

  tr.querySelector('.btn-export-raw').addEventListener('click', () => {
    document.getElementById('modal-json-pre').textContent = JSON.stringify(data, null, 2);
    document.getElementById('dashboard-raw-json-modal').classList.remove('hidden');
  });

  initIcons();
}

function initRecentScansActions() {
  document.querySelectorAll('#recent-scans-tbody tr').forEach(row => {
    const inspectBtn = row.querySelector('.actions-cell button:first-child');
    const rawBtn = row.querySelector('.actions-cell button:last-child');
    const iocCode = row.querySelector('td:first-child code');

    if (inspectBtn && iocCode) {
      inspectBtn.addEventListener('click', () => {
        executeScan(iocCode.textContent.trim());
      });
    }

    if (rawBtn && iocCode) {
      rawBtn.addEventListener('click', () => {
        executeScan(iocCode.textContent.trim());
      });
    }
  });
}

async function loadInitialHistory() {
  try {
    const res = await fetch('/api/history?limit=5');
    if (res.ok) {
      const data = await res.json();
      if (data.records && data.records.length > 0) {
        const tbody = document.getElementById('recent-scans-tbody');
        tbody.innerHTML = '';
        data.records.forEach(rec => {
          const tr = document.createElement('tr');
          const vClass = getVerdictClass(rec.verdict);
          const sClass = getScoreColorClass(rec.verdict, rec.confidence_score);

          tr.innerHTML = `
            <td><code>${escapeHtml(rec.defanged_indicator || rec.indicator)}</code></td>
            <td><span class="type-cell-tag">${rec.ioc_type ? rec.ioc_type.toUpperCase() : 'URL'}</span></td>
            <td><span class="badge-source-verdict ${vClass}">${rec.verdict}</span></td>
            <td><strong class="score-num-cell ${sClass}">${Math.round(rec.confidence_score)}</strong></td>
            <td><span class="sources-count-cell">12 / 18</span></td>
            <td><span class="time-cell">${new Date(rec.scanned_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span></td>
            <td class="text-right actions-cell">
              <button class="btn-table-action btn-inspect" data-ioc="${escapeHtml(rec.indicator)}" title="Inspect Scan Details"><i data-lucide="eye"></i></button>
              <button class="btn-table-action btn-raw" title="View Raw Details"><i data-lucide="file-text"></i></button>
            </td>
          `;
          tbody.appendChild(tr);

          tr.querySelector('.btn-inspect').addEventListener('click', () => {
            executeScan(rec.indicator);
          });
        });
        initIcons();
      }
    }
  } catch (err) {}
}

function incrementKPICounters(verdict) {
  appState.kpiStats.total += 1;
  if (verdict === 'malicious') appState.kpiStats.malicious += 1;
  else if (verdict === 'suspicious') appState.kpiStats.suspicious += 1;
  else if (verdict === 'clean') appState.kpiStats.clean += 1;

  document.getElementById('kpi-total-scans').textContent = appState.kpiStats.total.toLocaleString();
  document.getElementById('kpi-malicious-scans').textContent = appState.kpiStats.malicious.toLocaleString();
  document.getElementById('kpi-suspicious-scans').textContent = appState.kpiStats.suspicious.toLocaleString();
  document.getElementById('kpi-clean-scans').textContent = appState.kpiStats.clean.toLocaleString();
}

/* ================= 7. FULL SCAN REPORT VIEW ================= */
function renderFullScanReport(data) {
  const container = document.getElementById('full-scan-report-container');
  const vClass = getVerdictClass(data.verdict);
  const scoreVal = Math.round(data.confidence_score);

  container.innerHTML = `
    <div class="glass-card" style="margin-bottom: 1.5rem;">
      <div class="panel-header-row">
        <div style="display:flex;align-items:center;gap:0.75rem;">
          <span class="badge-source-verdict ${vClass}" style="font-size:1rem;padding:0.4rem 1rem;">${data.verdict.toUpperCase()}</span>
          <strong style="font-family:var(--font-mono);font-size:1.1rem;">${escapeHtml(data.defanged_indicator || data.indicator)}</strong>
        </div>
        <button class="btn-secondary btn-sm" id="btn-report-raw-json">
          <i data-lucide="code"></i> Raw JSON
        </button>
      </div>

      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin:1.5rem 0;">
        <div class="kpi-mini"><span>Type:</span> <strong>${data.type.toUpperCase()}</strong></div>
        <div class="kpi-mini"><span>Risk Level:</span> <strong>${data.risk_level}</strong></div>
        <div class="kpi-mini"><span>Confidence Score:</span> <strong class="${getScoreColorClass(data.verdict, scoreVal)}">${scoreVal} / 100</strong></div>
        <div class="kpi-mini"><span>Cached:</span> <strong>${data.is_cached ? 'Yes (24h)' : 'Fresh Scan'}</strong></div>
      </div>

      <div class="recommendations-box">
        <span class="section-label">Detection Scoring Breakdown</span>
        <ul class="bullet-list" style="margin-top:0.5rem;">
          ${data.scoring_breakdown && data.scoring_breakdown.length > 0 
            ? data.scoring_breakdown.map(f => `<li>• <strong>${escapeHtml(f.source)}:</strong> ${escapeHtml(f.reason)} (+${f.points_contributed} pts)</li>`).join('')
            : '<li>• No penalty points allocated. Indicator verified clean.</li>'}
        </ul>
      </div>
    </div>

    <!-- Provider Breakdown Cards -->
    <div class="panel-header-row" style="margin-top:1.5rem;">
      <h2>Intelligence Feeds Evaluated (${data.sources.length})</h2>
    </div>
    <div style="display:grid;grid-template-columns:repeat(auto-fill, minmax(320px, 1fr));gap:1rem;">
      ${data.sources.map(s => `
        <div class="glass-card" style="padding:1.25rem;">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem;">
            <strong>${escapeHtml(s.name)}</strong>
            <span class="badge-source-verdict ${getVerdictClass(s.verdict)}">${s.verdict}</span>
          </div>
          <p style="font-size:0.85rem;color:var(--text-secondary);margin-bottom:0.75rem;">${escapeHtml(s.summary)}</p>
          <div style="display:flex;justify-content:space-between;align-items:center;border-top:1px solid var(--border-subtle);padding-top:0.5rem;font-size:0.75rem;color:var(--text-muted);">
            <span>Latency: ${s.duration_ms}ms</span>
            ${s.detail_url ? `<a href="${s.detail_url}" target="_blank" style="color:#60a5fa;text-decoration:none;">View Feed Intelligence →</a>` : '<span>Internal Lookup</span>'}
          </div>
        </div>
      `).join('')}
    </div>
  `;

  const rawBtn = document.getElementById('btn-report-raw-json');
  if (rawBtn) {
    rawBtn.addEventListener('click', () => {
      document.getElementById('modal-json-pre').textContent = JSON.stringify(data, null, 2);
      document.getElementById('dashboard-raw-json-modal').classList.remove('hidden');
    });
  }

  initIcons();
}

/* ================= 8. BULK SCAN VIEW ================= */
function initBulkView() {
  const textarea = document.getElementById('bulk-view-textarea');
  const countIndicator = document.getElementById('bulk-view-count');
  const btnExecute = document.getElementById('btn-bulk-view-execute');
  const btnImportCsv = document.getElementById('btn-bulk-import-csv');
  const fileInput = document.getElementById('bulk-view-csv-file');
  const resultsCard = document.getElementById('bulk-view-results');
  const tbody = document.getElementById('bulk-view-tbody');
  const btnExport = document.getElementById('btn-bulk-view-export');

  let bulkItems = [];

  textarea.addEventListener('input', () => {
    const count = textarea.value.split(/[\r\n,;\t]+/).filter(l => l.trim().length > 0).length;
    countIndicator.textContent = `${count} IOCs detected`;
  });

  btnImportCsv.addEventListener('click', () => fileInput.click());

  fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
      const file = fileInput.files[0];
      const reader = new FileReader();
      reader.onload = (e) => {
        textarea.value = e.target.result;
        const count = textarea.value.split(/[\r\n,;\t]+/).filter(l => l.trim().length > 0).length;
        countIndicator.textContent = `${count} IOCs imported from ${file.name}`;
      };
      reader.readAsText(file);
    }
  });

  btnExecute.addEventListener('click', async () => {
    const content = textarea.value.trim();
    if (!content) {
      showToast('Please enter at least one IOC', 'error');
      return;
    }

    btnExecute.disabled = true;
    btnExecute.innerHTML = `<i data-lucide="loader"></i> <span>Scanning Batch...</span>`;

    try {
      const res = await fetch('/api/scan/bulk', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: content, force_refresh: false }),
      });

      if (!res.ok) throw new Error('Bulk scan request failed');
      const data = await res.json();
      bulkItems = data.results;

      // Update KPI counters
      document.getElementById('bulk-kpi-total').textContent = data.total;
      document.getElementById('bulk-kpi-mal').textContent = data.malicious_count;
      document.getElementById('bulk-kpi-susp').textContent = data.suspicious_count;
      document.getElementById('bulk-kpi-clean').textContent = data.clean_count;

      tbody.innerHTML = '';
      data.results.forEach(row => {
        const tr = document.createElement('tr');
        const vClass = getVerdictClass(row.verdict);
        tr.innerHTML = `
          <td>${row.index + 1}</td>
          <td><code>${escapeHtml(row.defanged || row.indicator)}</code></td>
          <td><span class="type-cell-tag">${row.ioc_type.toUpperCase()}</span></td>
          <td><span class="badge-source-verdict ${vClass}">${row.verdict}</span></td>
          <td><strong class="score-num-cell ${getScoreColorClass(row.verdict, row.confidence_score)}">${Math.round(row.confidence_score)}</strong></td>
          <td>${row.risk_level}</td>
          <td>
            <button class="btn-secondary btn-sm btn-inspect-batch" data-ioc="${escapeHtml(row.indicator)}">
              Inspect
            </button>
          </td>
        `;
        tbody.appendChild(tr);
      });

      document.querySelectorAll('.btn-inspect-batch').forEach(b => {
        b.addEventListener('click', (e) => {
          const ioc = e.currentTarget.getAttribute('data-ioc');
          executeScan(ioc);
        });
      });

      resultsCard.classList.remove('hidden');
      showToast(`Batch completed: ${data.total} indicators processed in ${data.duration_seconds}s`, 'success');
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      btnExecute.disabled = false;
      btnExecute.innerHTML = `<i data-lucide="play"></i> <span>Execute Batch Scan</span>`;
      initIcons();
    }
  });

  btnExport.addEventListener('click', () => {
    if (!bulkItems || bulkItems.length === 0) return;
    let csv = 'Index,Indicator,Defanged,Type,Verdict,Score,RiskLevel\n';
    bulkItems.forEach(r => {
      csv += `${r.index + 1},"${r.indicator}","${r.defanged}",${r.ioc_type},${r.verdict},${r.confidence_score},${r.risk_level}\n`;
    });
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `threatscope_batch_${Date.now()}.csv`;
    link.click();
  });
}

/* ================= 9. HISTORY FULL PAGE ================= */
function initHistoryView() {
  const typeFilter = document.getElementById('history-page-type');
  const verdictFilter = document.getElementById('history-page-verdict');
  const searchInput = document.getElementById('history-page-search');
  const btnClearAll = document.getElementById('btn-history-clear-all');

  typeFilter.addEventListener('change', loadHistoryPage);
  verdictFilter.addEventListener('change', loadHistoryPage);

  let timeout = null;
  searchInput.addEventListener('input', () => {
    clearTimeout(timeout);
    timeout = setTimeout(loadHistoryPage, 300);
  });

  btnClearAll.addEventListener('click', async () => {
    if (confirm('Clear all historical scan logs?')) {
      await fetch('/api/history', { method: 'DELETE' });
      showToast('Scan history deleted', 'success');
      loadHistoryPage();
    }
  });
}

async function loadHistoryPage() {
  const type = document.getElementById('history-page-type').value;
  const verdict = document.getElementById('history-page-verdict').value;
  const search = document.getElementById('history-page-search').value.trim();
  const tbody = document.getElementById('history-full-tbody');

  try {
    let url = `/api/history?limit=100&ioc_type=${type}&verdict=${verdict}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;

    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to load history');
    const data = await res.json();

    tbody.innerHTML = '';
    if (data.records && data.records.length > 0) {
      data.records.forEach(r => {
        const tr = document.createElement('tr');
        const vClass = getVerdictClass(r.verdict);
        tr.innerHTML = `
          <td><code>${escapeHtml(r.defanged_indicator || r.indicator)}</code></td>
          <td><span class="type-cell-tag">${r.ioc_type.toUpperCase()}</span></td>
          <td><span class="badge-source-verdict ${vClass}">${r.verdict}</span></td>
          <td><strong class="score-num-cell ${getScoreColorClass(r.verdict, r.confidence_score)}">${Math.round(r.confidence_score)}</strong></td>
          <td>${new Date(r.scanned_at).toLocaleString()}</td>
          <td class="text-right actions-cell">
            <button class="btn-secondary btn-sm btn-rescan-row" data-ioc="${escapeHtml(r.indicator)}">Re-Scan</button>
          </td>
        `;
        tbody.appendChild(tr);
      });

      document.querySelectorAll('.btn-rescan-row').forEach(b => {
        b.addEventListener('click', (e) => {
          executeScan(e.currentTarget.getAttribute('data-ioc'));
        });
      });
    } else {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:2rem;">No historical scans found.</td></tr>`;
    }
    initIcons();
  } catch (err) {}
}

/* ================= 10. THREAT INTEL & API INTEGRATIONS ================= */
async function loadIntelPage() {
  const grid = document.getElementById('intel-feeds-grid');
  try {
    const res = await fetch('/api/settings');
    if (res.ok) {
      const data = await res.json();
      grid.innerHTML = `
        <div style="display:grid;grid-template-columns:repeat(auto-fill, minmax(320px, 1fr));gap:1.25rem;">
          ${data.keys.map(k => `
            <div class="glass-card">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem;">
                <strong>${escapeHtml(k.name)}</strong>
                <span class="enterprise-tag">${k.configured ? 'Active Key' : 'Simulated / Mock'}</span>
              </div>
              <p style="font-size:0.85rem;color:var(--text-secondary);margin-bottom:0.75rem;">${escapeHtml(k.description)}</p>
              <div style="font-size:0.75rem;color:var(--text-muted);border-top:1px solid var(--border-subtle);padding-top:0.5rem;">
                ${escapeHtml(k.free_tier_info)}
              </div>
            </div>
          `).join('')}
        </div>
      `;
    }
  } catch (err) {}
}

function initApiIntegrations() {
  const form = document.getElementById('api-integrations-form');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = {};
    const vt = document.getElementById('page-key-vt').value.trim();
    const abuse = document.getElementById('page-key-abuse').value.trim();
    const urlscan = document.getElementById('page-key-urlscan').value.trim();
    const gsb = document.getElementById('page-key-gsb').value.trim();
    const mb = document.getElementById('page-key-mb').value.trim();

    if (vt) payload.virustotal = vt;
    if (abuse) payload.abuseipdb = abuse;
    if (urlscan) payload.urlscan = urlscan;
    if (gsb) payload.safebrowsing = gsb;
    if (mb) payload.malwarebazaar = mb;

    try {
      const res = await fetch('/api/settings/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        showToast('API Configuration saved', 'success');
        loadApiKeysStatus();
      }
    } catch (err) {
      showToast('Failed to save API keys', 'error');
    }
  });
}

async function loadApiKeysStatus() {
  try {
    const res = await fetch('/api/settings');
    if (res.ok) {
      const data = await res.json();
      data.keys.forEach(k => {
        let tagId = '';
        if (k.name.includes('VirusTotal')) tagId = 'page-tag-vt';
        else if (k.name.includes('AbuseIPDB')) tagId = 'page-tag-abuse';
        else if (k.name.includes('URLScan')) tagId = 'page-tag-urlscan';
        else if (k.name.includes('Safe Browsing')) tagId = 'page-tag-gsb';
        else if (k.name.includes('MalwareBazaar')) tagId = 'page-tag-mb';

        if (tagId) {
          const el = document.getElementById(tagId);
          if (el) {
            el.textContent = k.configured ? 'Configured (Active Key)' : 'Simulated / Active';
          }
        }
      });
    }
  } catch (err) {}
}

/* ================= 11. TOAST HELPER ================= */
function showToast(msg, type = 'success') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = msg;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
