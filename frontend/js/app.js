/**
 * ThreatScope Dashboard Application Script
 */

const appState = {
  currentScan: null,
  activeNav: 'dashboard',
  recentScans: [],
  kpiStats: {
    total: 0,
    malicious: 0,
    suspicious: 0,
    clean: 0,
    avgScore: 0,
    trendScores: [],
  },
};

document.addEventListener('DOMContentLoaded', () => {
  initIcons();
  initSidebarNavigation();
  initScanForms();
  initFileDropZone();
  initSupportedPills();
  initRecentScansActions();
  initReportsView();
  initBulkView();
  initHistoryView();
  initApiIntegrations();
  
  // Load real stats and history from backend
  fetchDashboardStats();
  loadInitialHistory();
});

function initIcons() {
  if (window.lucide) {
    try {
      window.lucide.createIcons();
    } catch (e) {
      console.warn('Lucide icon rendering warning:', e);
    }
  }
}

/* ================= 1. SIDEBAR NAVIGATION ================= */
function initSidebarNavigation() {
  const navItems = document.querySelectorAll('.nav-item');
  
  navItems.forEach(item => {
    item.addEventListener('click', () => {
      const navTarget = item.getAttribute('data-nav');
      if (navTarget) switchView(navTarget);
    });
  });

  const btnFullReport = document.getElementById('btn-view-full-report');
  if (btnFullReport) btnFullReport.addEventListener('click', () => switchView('scan'));

  const btnAllSources = document.getElementById('btn-view-all-sources');
  if (btnAllSources) btnAllSources.addEventListener('click', () => switchView('intel'));

  const btnAllHistory = document.getElementById('btn-view-all-history');
  if (btnAllHistory) btnAllHistory.addEventListener('click', () => switchView('history'));
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
  else if (viewName === 'reports') {
    targetViewId = 'view-reports';
    refreshReportsDropdown();
  }
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

/* ================= 2. REAL-TIME STATS & SPARKLINES ================= */
async function fetchDashboardStats() {
  try {
    const res = await fetch('/api/stats');
    if (res.ok) {
      const data = await res.json();
      appState.kpiStats = {
        total: data.total || 0,
        malicious: data.malicious || 0,
        suspicious: data.suspicious || 0,
        clean: data.clean || 0,
        avgScore: data.avg_score || 0,
        trendScores: data.trend_scores || [],
      };
      renderKPICounters();
    }
  } catch (err) {
    renderKPICounters();
  }
}

function renderKPICounters() {
  const { total, malicious, suspicious, clean, avgScore, trendScores } = appState.kpiStats;

  const elTotal = document.getElementById('kpi-total-scans');
  const elMal = document.getElementById('kpi-malicious-scans');
  const elSusp = document.getElementById('kpi-suspicious-scans');
  const elClean = document.getElementById('kpi-clean-scans');
  const elScore = document.getElementById('kpi-avg-score');

  if (elTotal) elTotal.textContent = total.toLocaleString();
  if (elMal) elMal.textContent = malicious.toLocaleString();
  if (elSusp) elSusp.textContent = suspicious.toLocaleString();
  if (elClean) elClean.textContent = clean.toLocaleString();
  if (elScore) elScore.innerHTML = `${Math.round(avgScore)} <span class="kpi-sub">/100</span>`;

  // Draw dynamic SVG sparklines based on real data points
  drawSparkline('sparkline-path-total', trendScores.length > 0 ? trendScores : [0, 0]);
  drawSparkline('sparkline-path-mal', trendScores.map(s => s >= 65 ? s : 0));
  drawSparkline('sparkline-path-susp', trendScores.map(s => (s >= 30 && s < 65) ? s : 0));
  drawSparkline('sparkline-path-clean', trendScores.map(s => s < 30 ? 100 - s : 0));
  drawSparkline('sparkline-path-score', trendScores.length > 0 ? trendScores : [0, 0]);
}

function drawSparkline(elementId, values) {
  const path = document.getElementById(elementId);
  if (!path) return;

  if (!values || values.length === 0) {
    path.setAttribute('d', 'M0,35 L100,35');
    return;
  }

  const width = 100;
  const height = 35;
  const maxVal = Math.max(...values, 100);
  const minVal = 0;
  const range = maxVal - minVal || 1;

  const points = values.map((val, idx) => {
    const x = values.length === 1 ? 50 : (idx / (values.length - 1)) * width;
    const y = height - ((val - minVal) / range) * (height - 5);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });

  if (points.length === 1) {
    path.setAttribute('d', `M0,${points[0].split(',')[1]} L100,${points[0].split(',')[1]}`);
  } else {
    let d = `M${points[0]}`;
    for (let i = 1; i < points.length; i++) {
      d += ` L${points[i]}`;
    }
    path.setAttribute('d', d);
  }
}

function incrementRealtimeScan(scanData) {
  appState.kpiStats.total += 1;
  const verdict = scanData.verdict;
  const score = scanData.confidence_score || 0;

  if (verdict === 'malicious') appState.kpiStats.malicious += 1;
  else if (verdict === 'suspicious') appState.kpiStats.suspicious += 1;
  else if (verdict === 'clean') appState.kpiStats.clean += 1;

  // Add score to trend points
  appState.kpiStats.trendScores.push(score);
  if (appState.kpiStats.trendScores.length > 20) {
    appState.kpiStats.trendScores.shift();
  }

  // Recalculate average
  const totalScore = appState.kpiStats.trendScores.reduce((a, b) => a + b, 0);
  appState.kpiStats.avgScore = totalScore / appState.kpiStats.trendScores.length;

  renderKPICounters();
}

/* ================= 3. SCAN FORMS & EXECUTION ================= */
function initScanForms() {
  const dashboardForm = document.getElementById('dashboard-scan-form');
  const dashboardInput = document.getElementById('dashboard-ioc-input');
  const topSearchBtn = document.getElementById('top-search-btn');
  const topSearchInput = document.getElementById('top-ioc-search');

  if (dashboardForm && dashboardInput) {
    dashboardForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const indicator = dashboardInput.value.trim();
      if (!indicator) return;
      executeScan(indicator);
    });
  }

  if (topSearchBtn && topSearchInput) {
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
  }

  const btnPaste = document.getElementById('btn-input-paste');
  if (btnPaste && dashboardInput) {
    btnPaste.addEventListener('click', async () => {
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
  }

  const btnUpload = document.getElementById('btn-input-upload');
  const fileInput = document.getElementById('dashboard-file-input');
  if (btnUpload && fileInput) {
    btnUpload.addEventListener('click', () => fileInput.click());
  }

  const btnCopy = document.getElementById('btn-copy-latest-ioc');
  if (btnCopy) {
    btnCopy.addEventListener('click', () => {
      const el = document.getElementById('latest-ioc-text');
      const text = el ? el.textContent : '';
      if (text && text !== 'No scans performed yet') {
        navigator.clipboard.writeText(text).then(() => {
          showToast('Indicator copied to clipboard', 'success');
        });
      }
    });
  }

  const btnDownloadLatestReport = document.getElementById('btn-latest-download-report');
  if (btnDownloadLatestReport) {
    btnDownloadLatestReport.addEventListener('click', () => {
      if (appState.currentScan && appState.currentScan.id) {
        window.open(`/api/reports/${appState.currentScan.id}/download`, '_blank');
      } else {
        showToast('Please perform a scan first to download a report', 'error');
      }
    });
  }

  const btnCloseModal = document.getElementById('btn-close-modal-json');
  const rawModal = document.getElementById('dashboard-raw-json-modal');
  if (btnCloseModal && rawModal) {
    btnCloseModal.addEventListener('click', () => {
      rawModal.classList.add('hidden');
    });
  }
}

async function executeScan(indicator) {
  const btnScan = document.getElementById('btn-dashboard-scan');
  if (btnScan) {
    btnScan.disabled = true;
    btnScan.innerHTML = `<span>Scanning...</span>`;
  }

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
    appState.recentScans.unshift(scanData);

    // Switch to Dashboard view and update all panels
    switchView('dashboard');
    updateDashboardPanels(scanData);
    prependRecentScanRow(scanData);
    incrementRealtimeScan(scanData);
    renderFullScanReport(scanData);

    showToast(`Scan complete for ${scanData.defanged_indicator}`, 'success');
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    if (btnScan) {
      btnScan.disabled = false;
      btnScan.innerHTML = `<span>Scan Now</span>`;
    }
    initIcons();
  }
}

/* ================= 4. UPDATE DASHBOARD PANELS ================= */
function updateDashboardPanels(data) {
  const verdictTag = document.getElementById('latest-verdict-tag');
  const iocText = document.getElementById('latest-ioc-text');
  const iocMeta = document.getElementById('latest-ioc-sub');
  const scoreNum = document.getElementById('latest-score-number');
  const ringCircle = document.getElementById('latest-ring-circle');

  const verdictUpper = data.verdict.toUpperCase();
  if (verdictTag) {
    verdictTag.textContent = verdictUpper;
    verdictTag.className = `verdict-tag-pill ${getVerdictClass(data.verdict)}`;
  }

  if (iocText) iocText.textContent = data.defanged_indicator || data.indicator;
  if (iocMeta) iocMeta.textContent = `${data.type.toUpperCase()} • Scanned just now`;

  const scoreVal = Math.round(data.confidence_score);
  if (scoreNum) {
    scoreNum.textContent = scoreVal;
    scoreNum.className = `dial-main-num ${getScoreColorClass(data.verdict, scoreVal)}`;
  }

  if (ringCircle) ringCircle.setAttribute('stroke-dasharray', `${scoreVal}, 100`);

  const summaryEl = document.getElementById('latest-summary-text');
  if (summaryEl) {
    if (data.verdict === 'malicious') {
      summaryEl.textContent = `This ${data.type.toUpperCase()} is detected as malicious by multiple security intelligence feeds. It represents an elevated security hazard.`;
    } else if (data.verdict === 'suspicious') {
      summaryEl.textContent = `This ${data.type.toUpperCase()} exhibits suspicious heuristic indicators or newly registered characteristics. Further monitoring recommended.`;
    } else if (data.verdict === 'clean') {
      summaryEl.textContent = `This ${data.type.toUpperCase()} was evaluated against active security datasets and verified clean with 0 malicious signals.`;
    } else {
      summaryEl.textContent = `No active threat reputation or malicious records observed for this indicator.`;
    }
  }

  const statDate = document.getElementById('latest-stat-date');
  if (statDate) statDate.textContent = new Date(data.scanned_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  
  const validSources = data.sources.filter(s => s.status !== 'skipped');
  const maliciousSources = data.sources.filter(s => s.verdict === 'malicious');
  
  const statSources = document.getElementById('latest-stat-sources');
  if (statSources) statSources.textContent = `${validSources.length} / 6`;

  const statDetections = document.getElementById('latest-stat-detections');
  if (statDetections) {
    statDetections.textContent = `${maliciousSources.length}`;
    statDetections.className = `stat-val ${maliciousSources.length > 0 ? 'text-red' : 'text-green'}`;
  }

  const statVerdict = document.getElementById('latest-stat-verdict');
  if (statVerdict) {
    statVerdict.textContent = verdictUpper;
    statVerdict.className = `stat-val ${getVerdictColorClass(data.verdict)}`;
  }

  // Risk Factors & Tags
  const factorsList = document.getElementById('latest-factors-list');
  if (factorsList) {
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
  }

  const tagsList = document.getElementById('latest-tags-list');
  if (tagsList) {
    tagsList.innerHTML = '';
    const tags = [`type-${data.type}`];
    if (data.verdict === 'malicious') tags.push('threat-flagged', 'reputation-penalty');
    if (data.verdict === 'suspicious') tags.push('elevated-risk');
    if (data.verdict === 'clean') tags.push('verified-clean', 'benign');

    tags.forEach(t => {
      const span = document.createElement('span');
      span.className = 'pill-tag';
      span.textContent = t;
      tagsList.appendChild(span);
    });
  }

  // Source Breakdown List
  const sourcesContainer = document.getElementById('dashboard-sources-list');
  if (sourcesContainer && data.sources && data.sources.length > 0) {
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

  // Donut Gauge & Breakdown Percentages
  const donutScore = document.getElementById('donut-score-val');
  if (donutScore) donutScore.textContent = scoreVal;

  const donutRisk = document.getElementById('donut-risk-label');
  if (donutRisk) {
    donutRisk.textContent = `${data.risk_level} RISK`;
    donutRisk.style.color = getScoreHexColor(data.verdict, scoreVal);
  }

  // Update dynamic percentages
  const pctVendor = document.getElementById('donut-pct-vendor');
  const pctContent = document.getElementById('donut-pct-content');
  const pctRep = document.getElementById('donut-pct-rep');
  const pctDomain = document.getElementById('donut-pct-domain');

  if (pctVendor) pctVendor.textContent = data.verdict === 'malicious' ? '45%' : '0%';
  if (pctContent) pctContent.textContent = data.verdict === 'malicious' ? '25%' : '0%';
  if (pctRep) pctRep.textContent = data.verdict === 'suspicious' ? '35%' : (data.verdict === 'malicious' ? '15%' : '0%');
  if (pctDomain) pctDomain.textContent = data.type === 'domain' || data.type === 'url' ? '10%' : '0%';

  // Recommendations
  const recsList = document.getElementById('latest-recs-list');
  if (recsList) {
    if (data.verdict === 'malicious') {
      recsList.innerHTML = `
        <li>• Block ${escapeHtml(data.defanged_indicator)} across perimeter firewalls & proxies.</li>
        <li>• Isolate endpoints that connected to this target.</li>
        <li>• Check SIEM logs for historical connections in the last 30 days.</li>
      `;
    } else if (data.verdict === 'suspicious') {
      recsList.innerHTML = `
        <li>• Monitor traffic directed to ${escapeHtml(data.defanged_indicator)}.</li>
        <li>• Add to suspicious telemetry watchlist.</li>
      `;
    } else {
      recsList.innerHTML = `
        <li>• Indicator verified benign. No block action required.</li>
        <li>• Standard monitoring policy applies.</li>
      `;
    }
  }

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

/* ================= 5. FILE DRAG & DROP ================= */
function initFileDropZone() {
  const dropZone = document.getElementById('dashboard-file-dropzone');
  const fileInput = document.getElementById('dashboard-file-input');

  if (!dropZone || !fileInput) return;

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
    appState.recentScans.unshift(scanData);

    switchView('dashboard');
    updateDashboardPanels(scanData);
    prependRecentScanRow(scanData);
    incrementRealtimeScan(scanData);
    renderFullScanReport(scanData);

    showToast(`File scan complete: SHA-256 ${scanData.defanged_indicator.slice(0, 16)}...`, 'success');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

/* ================= 6. SUPPORTED SAMPLE PILLS ================= */
function initSupportedPills() {
  document.querySelectorAll('.type-pill').forEach(pill => {
    if (pill.id === 'pill-file-trigger') {
      pill.addEventListener('click', () => {
        const fileInput = document.getElementById('dashboard-file-input');
        if (fileInput) fileInput.click();
      });
      return;
    }

    pill.addEventListener('click', () => {
      const sample = pill.getAttribute('data-sample');
      if (sample) {
        const dashInput = document.getElementById('dashboard-ioc-input');
        if (dashInput) dashInput.value = sample;
        executeScan(sample);
      }
    });
  });
}

/* ================= 7. RECENT SCANS TABLE ================= */
function prependRecentScanRow(data) {
  const tbody = document.getElementById('recent-scans-tbody');
  if (!tbody) return;

  // Clear "No scans recorded" placeholder if present
  if (tbody.children.length === 1 && tbody.children[0].children.length === 1) {
    tbody.innerHTML = '';
  }

  const tr = document.createElement('tr');
  const vClass = getVerdictClass(data.verdict);
  const sClass = getScoreColorClass(data.verdict, data.confidence_score);

  tr.innerHTML = `
    <td><code>${escapeHtml(data.defanged_indicator || data.indicator)}</code></td>
    <td><span class="type-cell-tag">${data.type.toUpperCase()}</span></td>
    <td><span class="badge-source-verdict ${vClass}">${data.verdict}</span></td>
    <td><strong class="score-num-cell ${sClass}">${Math.round(data.confidence_score)}</strong></td>
    <td><span class="sources-count-cell">${data.sources.length} / 6</span></td>
    <td><span class="time-cell">Just now</span></td>
    <td class="text-right actions-cell">
      <button class="btn-table-action btn-inspect" data-id="${data.id}" title="Inspect Scan Details"><i data-lucide="eye"></i></button>
      <button class="btn-table-action btn-download-row-report" data-id="${data.id}" title="Download Report"><i data-lucide="download"></i></button>
    </td>
  `;

  tbody.insertBefore(tr, tbody.firstChild);

  const inspectBtn = tr.querySelector('.btn-inspect');
  if (inspectBtn) {
    inspectBtn.addEventListener('click', () => {
      renderFullScanReport(data);
      switchView('scan');
    });
  }

  const reportBtn = tr.querySelector('.btn-download-row-report');
  if (reportBtn) {
    reportBtn.addEventListener('click', () => {
      window.open(`/api/reports/${data.id}/download`, '_blank');
    });
  }

  initIcons();
}

function initRecentScansActions() {
  document.querySelectorAll('#recent-scans-tbody tr').forEach(row => {
    const inspectBtn = row.querySelector('.actions-cell .btn-inspect');
    const iocCode = row.querySelector('td:first-child code');

    if (inspectBtn && iocCode) {
      inspectBtn.addEventListener('click', () => {
        executeScan(iocCode.textContent.trim());
      });
    }
  });
}

async function loadInitialHistory() {
  try {
    const res = await fetch('/api/history?limit=10');
    if (res.ok) {
      const data = await res.json();
      if (data.records && data.records.length > 0) {
        appState.recentScans = data.records;
        const tbody = document.getElementById('recent-scans-tbody');
        if (!tbody) return;
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
            <td><span class="sources-count-cell">6 / 6</span></td>
            <td><span class="time-cell">${new Date(rec.scanned_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span></td>
            <td class="text-right actions-cell">
              <button class="btn-table-action btn-inspect" data-ioc="${escapeHtml(rec.indicator)}" title="Inspect Scan Details"><i data-lucide="eye"></i></button>
              <button class="btn-table-action btn-row-rep" data-id="${rec.id}" title="Download Report"><i data-lucide="download"></i></button>
            </td>
          `;
          tbody.appendChild(tr);

          const btnInsp = tr.querySelector('.btn-inspect');
          if (btnInsp) {
            btnInsp.addEventListener('click', () => {
              executeScan(rec.indicator);
            });
          }

          const btnRep = tr.querySelector('.btn-row-rep');
          if (btnRep) {
            btnRep.addEventListener('click', () => {
              window.open(`/api/reports/${rec.id}/download`, '_blank');
            });
          }
        });
        initIcons();
      }
    }
  } catch (err) {}
}

/* ================= 8. REPORT GENERATOR VIEW ================= */
function initReportsView() {
  const selectScan = document.getElementById('report-select-scan');
  const btnDownloadPdf = document.getElementById('btn-download-pdf-report');
  const btnExportJson = document.getElementById('btn-export-json-report');

  if (selectScan) {
    selectScan.addEventListener('change', () => {
      const selectedId = selectScan.value;
      if (selectedId) {
        const found = appState.recentScans.find(s => s.id === selectedId);
        if (found) {
          renderReportPreview(found);
        }
      }
    });
  }

  if (btnDownloadPdf) {
    btnDownloadPdf.addEventListener('click', () => {
      const selectedId = selectScan ? selectScan.value : (appState.currentScan ? appState.currentScan.id : null);
      if (selectedId) {
        window.open(`/api/reports/${selectedId}/download`, '_blank');
      } else {
        showToast('Please select a scan record to generate a report', 'error');
      }
    });
  }

  if (btnExportJson) {
    btnExportJson.addEventListener('click', () => {
      const selectedId = selectScan ? selectScan.value : (appState.currentScan ? appState.currentScan.id : null);
      const found = appState.recentScans.find(s => s.id === selectedId) || appState.currentScan;
      if (found) {
        const jsonStr = JSON.stringify(found, null, 2);
        const blob = new Blob([jsonStr], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `threatscope_report_${found.id}.json`;
        a.click();
      } else {
        showToast('Please select a scan record to export JSON', 'error');
      }
    });
  }
}

function refreshReportsDropdown() {
  const selectScan = document.getElementById('report-select-scan');
  if (!selectScan) return;

  selectScan.innerHTML = '<option value="">-- Select a completed scan --</option>';
  appState.recentScans.forEach(s => {
    const opt = document.createElement('option');
    opt.value = s.id;
    opt.textContent = `${s.defanged_indicator || s.indicator} (${s.verdict.toUpperCase()} - Score ${Math.round(s.confidence_score)})`;
    selectScan.appendChild(opt);
  });

  if (appState.currentScan && appState.currentScan.id) {
    selectScan.value = appState.currentScan.id;
    renderReportPreview(appState.currentScan);
  }
}

function renderReportPreview(data) {
  const preview = document.getElementById('report-preview-container');
  if (!preview) return;

  const vClass = getVerdictClass(data.verdict);
  const scoreVal = Math.round(data.confidence_score);

  preview.innerHTML = `
    <div class="report-document">
      <div class="report-doc-header">
        <div>
          <h3>THREATSCOPE INTELLIGENCE REPORT</h3>
          <span style="font-size:0.75rem;color:var(--text-muted);">Ref ID: ${data.id} • Generated UTC</span>
        </div>
        <span class="badge-source-verdict ${vClass}" style="font-size:1rem;padding:0.4rem 1rem;">${data.verdict.toUpperCase()}</span>
      </div>

      <div style="display:grid;grid-template-columns:2fr 1fr;gap:1.5rem;margin-bottom:1.5rem;">
        <div>
          <span class="section-label">Target Indicator</span>
          <p style="font-family:var(--font-mono);font-size:1.1rem;color:#ffffff;word-break:break-all;">${escapeHtml(data.defanged_indicator || data.indicator)}</p>
          <span style="font-size:0.8rem;color:var(--text-muted);display:block;margin-top:0.35rem;">Type: ${data.type ? data.type.toUpperCase() : (data.ioc_type ? data.ioc_type.toUpperCase() : 'URL')} | Risk Level: ${data.risk_level}</span>
        </div>
        <div style="text-align:right;">
          <span class="section-label">Confidence Score</span>
          <strong class="${getScoreColorClass(data.verdict, scoreVal)}" style="font-size:2rem;font-family:var(--font-mono);">${scoreVal} / 100</strong>
        </div>
      </div>

      <div style="margin-bottom:1.5rem;">
        <span class="section-label">Risk Rationale & Detection Breakdown</span>
        <ul class="bullet-list" style="margin-top:0.5rem;">
          ${data.scoring_breakdown && data.scoring_breakdown.length > 0 
            ? data.scoring_breakdown.map(f => `<li>• <strong>${escapeHtml(f.source)}:</strong> ${escapeHtml(f.reason)} (+${f.points_contributed} pts)</li>`).join('')
            : '<li>• Clean profile verified across all threat intelligence databases.</li>'}
        </ul>
      </div>

      <div>
        <span class="section-label">Actionable Recommendations</span>
        <ul class="bullet-list-red" style="margin-top:0.5rem;">
          ${data.verdict === 'malicious' 
            ? `<li>• Block communication with ${escapeHtml(data.defanged_indicator || data.indicator)} in perimeter firewalls.</li><li>• Isolate any internal hosts that initiated connections.</li>` 
            : `<li>• Indicator is currently benign. No blocking action necessary.</li>`}
        </ul>
      </div>
    </div>
  `;
}

/* ================= 9. FULL SCAN REPORT VIEW ================= */
function renderFullScanReport(data) {
  const container = document.getElementById('full-scan-report-container');
  if (!container) return;

  const vClass = getVerdictClass(data.verdict);
  const scoreVal = Math.round(data.confidence_score);

  container.innerHTML = `
    <div class="glass-card" style="margin-bottom: 1.5rem;">
      <div class="panel-header-row">
        <div style="display:flex;align-items:center;gap:0.75rem;">
          <span class="badge-source-verdict ${vClass}" style="font-size:1rem;padding:0.4rem 1rem;">${data.verdict.toUpperCase()}</span>
          <strong style="font-family:var(--font-mono);font-size:1.1rem;">${escapeHtml(data.defanged_indicator || data.indicator)}</strong>
        </div>
        <div style="display:flex;gap:0.5rem;">
          <button class="btn-scan-main btn-sm" id="btn-report-dl-pdf">
            <i data-lucide="download"></i> Download Report
          </button>
          <button class="btn-secondary btn-sm" id="btn-report-raw-json">
            <i data-lucide="code"></i> Raw JSON
          </button>
        </div>
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

  const btnDlPdf = document.getElementById('btn-report-dl-pdf');
  if (btnDlPdf) {
    btnDlPdf.addEventListener('click', () => {
      window.open(`/api/reports/${data.id}/download`, '_blank');
    });
  }

  const rawBtn = document.getElementById('btn-report-raw-json');
  if (rawBtn) {
    rawBtn.addEventListener('click', () => {
      const modalPre = document.getElementById('modal-json-pre');
      const rawModal = document.getElementById('dashboard-raw-json-modal');
      if (modalPre) modalPre.textContent = JSON.stringify(data, null, 2);
      if (rawModal) rawModal.classList.remove('hidden');
    });
  }

  initIcons();
}

/* ================= 10. BULK SCAN VIEW ================= */
function initBulkView() {
  const textarea = document.getElementById('bulk-view-textarea');
  const countIndicator = document.getElementById('bulk-view-count');
  const btnExecute = document.getElementById('btn-bulk-view-execute');
  const btnImportCsv = document.getElementById('btn-bulk-import-csv');
  const fileInput = document.getElementById('bulk-view-csv-file');
  const resultsCard = document.getElementById('bulk-view-results');
  const tbody = document.getElementById('bulk-view-tbody');
  const btnExport = document.getElementById('btn-bulk-view-export');

  if (!textarea || !btnExecute) return;
  let bulkItems = [];

  textarea.addEventListener('input', () => {
    const count = textarea.value.split(/[\r\n,;\t]+/).filter(l => l.trim().length > 0).length;
    if (countIndicator) countIndicator.textContent = `${count} IOCs detected`;
  });

  if (btnImportCsv && fileInput) {
    btnImportCsv.addEventListener('click', () => fileInput.click());

    fileInput.addEventListener('change', () => {
      if (fileInput.files.length > 0) {
        const file = fileInput.files[0];
        const reader = new FileReader();
        reader.onload = (e) => {
          textarea.value = e.target.result;
          const count = textarea.value.split(/[\r\n,;\t]+/).filter(l => l.trim().length > 0).length;
          if (countIndicator) countIndicator.textContent = `${count} IOCs imported from ${file.name}`;
        };
        reader.readAsText(file);
      }
    });
  }

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

      const kpiTotal = document.getElementById('bulk-kpi-total');
      const kpiMal = document.getElementById('bulk-kpi-mal');
      const kpiSusp = document.getElementById('bulk-kpi-susp');
      const kpiClean = document.getElementById('bulk-kpi-clean');

      if (kpiTotal) kpiTotal.textContent = data.total;
      if (kpiMal) kpiMal.textContent = data.malicious_count;
      if (kpiSusp) kpiSusp.textContent = data.suspicious_count;
      if (kpiClean) kpiClean.textContent = data.clean_count;

      if (tbody) {
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
            if (ioc) executeScan(ioc);
          });
        });
      }

      if (resultsCard) resultsCard.classList.remove('hidden');
      fetchDashboardStats();
      showToast(`Batch completed: ${data.total} indicators processed in ${data.duration_seconds}s`, 'success');
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      btnExecute.disabled = false;
      btnExecute.innerHTML = `<i data-lucide="play"></i> <span>Execute Batch Scan</span>`;
      initIcons();
    }
  });

  if (btnExport) {
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
}

/* ================= 11. HISTORY FULL PAGE ================= */
function initHistoryView() {
  const typeFilter = document.getElementById('history-page-type');
  const verdictFilter = document.getElementById('history-page-verdict');
  const searchInput = document.getElementById('history-page-search');
  const btnClearAll = document.getElementById('btn-history-clear-all');

  if (typeFilter) typeFilter.addEventListener('change', loadHistoryPage);
  if (verdictFilter) verdictFilter.addEventListener('change', loadHistoryPage);

  if (searchInput) {
    let timeout = null;
    searchInput.addEventListener('input', () => {
      clearTimeout(timeout);
      timeout = setTimeout(loadHistoryPage, 300);
    });
  }

  if (btnClearAll) {
    btnClearAll.addEventListener('click', async () => {
      if (confirm('Clear all historical scan logs?')) {
        await fetch('/api/history', { method: 'DELETE' });
        showToast('Scan history deleted', 'success');
        fetchDashboardStats();
        loadHistoryPage();
      }
    });
  }
}

async function loadHistoryPage() {
  const typeEl = document.getElementById('history-page-type');
  const verdictEl = document.getElementById('history-page-verdict');
  const searchEl = document.getElementById('history-page-search');
  const tbody = document.getElementById('history-full-tbody');

  const type = typeEl ? typeEl.value : 'all';
  const verdict = verdictEl ? verdictEl.value : 'all';
  const search = searchEl ? searchEl.value.trim() : '';

  try {
    let url = `/api/history?limit=100&ioc_type=${type}&verdict=${verdict}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;

    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to load history');
    const data = await res.json();

    if (tbody) {
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
              <button class="btn-table-action btn-dl-hist-rep" data-id="${r.id}" title="Download Report"><i data-lucide="download"></i></button>
            </td>
          `;
          tbody.appendChild(tr);

          const btnDl = tr.querySelector('.btn-dl-hist-rep');
          if (btnDl) {
            btnDl.addEventListener('click', () => {
              window.open(`/api/reports/${r.id}/download`, '_blank');
            });
          }
        });

        document.querySelectorAll('.btn-rescan-row').forEach(b => {
          b.addEventListener('click', (e) => {
            const ioc = e.currentTarget.getAttribute('data-ioc');
            if (ioc) executeScan(ioc);
          });
        });
      } else {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:2rem;">No historical scans found.</td></tr>`;
      }
    }
    initIcons();
  } catch (err) {}
}

/* ================= 12. THREAT INTEL & API INTEGRATIONS ================= */
async function loadIntelPage() {
  const grid = document.getElementById('intel-feeds-grid');
  if (!grid) return;
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
                <span class="type-cell-tag">${k.configured ? 'Active Key' : 'Simulated / Active'}</span>
              </div>
              <p style="font-size:0.85rem;color:var(--text-secondary);margin-bottom:0.75rem;">${escapeHtml(k.description)}</p>
              <div style="font-size:0.75rem;color:var(--text-muted);border-top:1px solid var(--border-subtle);padding-top:0.5rem;">
                ${escapeHtml(k.free_tier_info)}
              </div>
            </div>
          `).join('')}
        </div>
      `;
      initIcons();
    }
  } catch (err) {}
}

function initApiIntegrations() {
  const form = document.getElementById('api-integrations-form');
  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = {};
    const vt = document.getElementById('page-key-vt')?.value.trim();
    const abuse = document.getElementById('page-key-abuse')?.value.trim();
    const urlscan = document.getElementById('page-key-urlscan')?.value.trim();
    const gsb = document.getElementById('page-key-gsb')?.value.trim();
    const mb = document.getElementById('page-key-mb')?.value.trim();

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

/* ================= 13. TOAST HELPER ================= */
function showToast(msg, type = 'success') {
  const container = document.getElementById('toast-container');
  if (!container) return;
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
