/**
 * ThreatScope - Frontend Application Core Logic
 */

// Application State
const state = {
  currentScan: null,
  activeTab: 'unified-scanner',
  bulkResults: [],
  selectedFile: null,
  isDarkTheme: true,
};

// Initialize App
document.addEventListener('DOMContentLoaded', () => {
  initLucideIcons();
  initTheme();
  initTabNavigation();
  initClassifierDebounce();
  initSingleScan();
  initFileScanner();
  initBulkScanner();
  initEmailScanner();
  initHistoryView();
  initSettingsModal();
  initSampleButtons();
});

function initLucideIcons() {
  if (window.lucide) {
    window.lucide.createIcons();
  }
}

/* ================= THEME TOGGLE ================= */
function initTheme() {
  const savedTheme = localStorage.getItem('threatscope_theme');
  const body = document.body;
  const themeIcon = document.getElementById('theme-icon');

  if (savedTheme === 'light') {
    body.classList.remove('dark-theme');
    body.classList.add('light-theme');
    state.isDarkTheme = false;
  } else {
    body.classList.remove('light-theme');
    body.classList.add('dark-theme');
    state.isDarkTheme = true;
  }

  document.getElementById('theme-toggle-btn').addEventListener('click', () => {
    state.isDarkTheme = !state.isDarkTheme;
    if (state.isDarkTheme) {
      body.classList.remove('light-theme');
      body.classList.add('dark-theme');
      localStorage.setItem('threatscope_theme', 'dark');
    } else {
      body.classList.remove('dark-theme');
      body.classList.add('light-theme');
      localStorage.setItem('threatscope_theme', 'light');
    }
  });
}

/* ================= TAB NAVIGATION ================= */
function initTabNavigation() {
  const tabButtons = document.querySelectorAll('.tab-btn');
  const tabPanes = document.querySelectorAll('.tab-pane');

  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');
      state.activeTab = targetTab;

      tabButtons.forEach(b => b.classList.remove('active'));
      tabPanes.forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const activePane = document.getElementById(targetTab);
      if (activePane) {
        activePane.classList.add('active');
      }

      if (targetTab === 'history-view') {
        loadHistory();
      }

      initLucideIcons();
    });
  });
}

function switchTab(tabId) {
  const tabBtn = document.querySelector(`.tab-btn[data-tab="${tabId}"]`);
  if (tabBtn) {
    tabBtn.click();
  }
}

/* ================= LIVE DEBOUNCED IOC CLASSIFIER ================= */
function initClassifierDebounce() {
  const input = document.getElementById('ioc-input');
  const badge = document.getElementById('ioc-badge');
  const badgeText = document.getElementById('ioc-badge-text');

  let debounceTimeout = null;

  input.addEventListener('input', () => {
    const val = input.value.trim();
    if (!val) {
      badge.classList.add('hidden');
      return;
    }

    clearTimeout(debounceTimeout);
    debounceTimeout = setTimeout(async () => {
      try {
        const res = await fetch('/api/classify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ indicator: val }),
        });
        if (res.ok) {
          const data = await res.json();
          if (data.ioc_type && data.ioc_type !== 'unknown') {
            let label = data.ioc_type.toUpperCase();
            if (data.is_defanged) label += ' (DEFANGED)';
            badgeText.textContent = label;
            badge.classList.remove('hidden');
          } else {
            badge.classList.add('hidden');
          }
        }
      } catch (err) {
        badge.classList.add('hidden');
      }
    }, 250);
  });
}

/* ================= SINGLE IOC SCANNER ================= */
function initSingleScan() {
  const form = document.getElementById('single-scan-form');
  const input = document.getElementById('ioc-input');
  const resultsContainer = document.getElementById('scan-results-container');
  const loading = document.getElementById('scan-loading');
  const report = document.getElementById('scan-report');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const indicator = input.value.trim();
    if (!indicator) return;

    resultsContainer.classList.remove('hidden');
    loading.classList.remove('hidden');
    report.classList.add('hidden');
    initLucideIcons();

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ indicator: indicator, force_refresh: false }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Scan request failed (HTTP ${res.status})`);
      }

      const scanData = await res.json();
      state.currentScan = scanData;
      renderScanReport(scanData);
    } catch (err) {
      showToast(err.message, 'error');
      resultsContainer.classList.add('hidden');
    } finally {
      loading.classList.add('hidden');
    }
  });

  // Copy Defanged IOC button
  document.getElementById('btn-copy-defanged').addEventListener('click', () => {
    const text = document.getElementById('report-ioc-defanged').textContent;
    navigator.clipboard.writeText(text).then(() => {
      showToast('Defanged IOC copied to clipboard', 'success');
    });
  });

  // Toggle Raw JSON Modal
  document.getElementById('btn-toggle-raw-json').addEventListener('click', () => {
    if (state.currentScan) {
      document.getElementById('raw-json-content').textContent = JSON.stringify(state.currentScan, null, 2);
      document.getElementById('raw-json-modal').classList.remove('hidden');
    }
  });

  document.getElementById('btn-close-raw-json').addEventListener('click', () => {
    document.getElementById('raw-json-modal').classList.add('hidden');
  });
}

function renderScanReport(data) {
  const report = document.getElementById('scan-report');
  report.classList.remove('hidden');

  // Verdict & Risk Badges
  const verdictBadge = document.getElementById('verdict-badge');
  const riskBadge = document.getElementById('risk-level-badge');
  const cachedPill = document.getElementById('cached-pill');

  verdictBadge.textContent = data.verdict.toUpperCase();
  riskBadge.textContent = `${data.risk_level} RISK`;

  // Apply Severity Styling Classes
  const severityClass = getSeverityClass(data.verdict, data.confidence_score);
  verdictBadge.className = `verdict-badge ${severityClass}`;
  riskBadge.className = `risk-level-badge ${severityClass}`;

  if (data.is_cached) {
    cachedPill.classList.remove('hidden');
  } else {
    cachedPill.classList.add('hidden');
  }

  // Defanged indicator & meta
  document.getElementById('report-ioc-defanged').textContent = data.defanged_indicator || data.indicator;
  document.getElementById('report-ioc-type').textContent = `Type: ${data.type.toUpperCase()}`;
  document.getElementById('report-timestamp').textContent = `Scanned: ${new Date(data.scanned_at).toLocaleTimeString()}`;
  document.getElementById('report-sources-count').textContent = `Sources: ${data.sources.length} evaluated`;

  // Update Threat Gauge
  const score = Math.round(data.confidence_score);
  document.getElementById('gauge-score-val').textContent = score;
  const gaugeFill = document.getElementById('gauge-fill-circle');
  
  // Circumference is 2 * PI * 42 ~= 264
  const offset = 264 - (264 * score / 100);
  gaugeFill.style.strokeDashoffset = offset;
  gaugeFill.style.stroke = getScoreColor(data.verdict, score);

  // Scoring Factors Breakdown
  const factorsContainer = document.getElementById('scoring-factors-list');
  factorsContainer.innerHTML = '';

  if (data.scoring_breakdown && data.scoring_breakdown.length > 0) {
    data.scoring_breakdown.forEach(factor => {
      const item = document.createElement('div');
      let itemClass = 'factor-item';
      if (factor.points_contributed > 0) {
        itemClass += ' factor-malicious';
      } else if (factor.reason.toLowerCase().includes('clean')) {
        itemClass += ' factor-clean';
      }

      item.className = itemClass;
      item.innerHTML = `
        <div class="factor-info">
          <span class="factor-source">${escapeHtml(factor.source)} (Weight: ${factor.weight}x)</span>
          <span class="factor-reason">${escapeHtml(factor.reason)}</span>
        </div>
        <div class="factor-points">${factor.points_contributed > 0 ? `+${factor.points_contributed} pts` : `0 pts`}</div>
      `;
      factorsContainer.appendChild(item);
    });
  } else {
    factorsContainer.innerHTML = `<div class="text-muted">No penalty factors registered.</div>`;
  }

  // Cascaded Email Sub-Scans
  const emailSubscansCard = document.getElementById('email-subscans-card');
  const emailSubscansContainer = document.getElementById('email-subscans-container');
  
  if (data.email_analysis && data.email_analysis.sub_scans && data.email_analysis.sub_scans.length > 0) {
    emailSubscansCard.classList.remove('hidden');
    emailSubscansContainer.innerHTML = '';

    data.email_analysis.sub_scans.forEach(sub => {
      const row = document.createElement('div');
      row.className = 'subscan-row';
      const subSev = getSeverityClass(sub.verdict, sub.confidence_score);
      row.innerHTML = `
        <div class="subscan-left">
          <span class="verdict-badge ${subSev}">${sub.verdict.toUpperCase()}</span>
          <span class="meta-tag">${sub.ioc_type.toUpperCase()}</span>
          <code class="subscan-ind">${escapeHtml(sub.indicator)}</code>
        </div>
        <div class="subscan-summary text-muted">${escapeHtml(sub.summary)}</div>
      `;
      emailSubscansContainer.appendChild(row);
    });
  } else {
    emailSubscansCard.classList.add('hidden');
  }

  // Threat Intel Provider Grid
  const providersGrid = document.getElementById('provider-cards-grid');
  providersGrid.innerHTML = '';

  if (data.sources && data.sources.length > 0) {
    data.sources.forEach(source => {
      const pCard = document.createElement('div');
      pCard.className = 'provider-card';
      const pSev = getSeverityClass(source.verdict, source.confidence_score);

      const linkHtml = source.detail_url 
        ? `<a href="${source.detail_url}" target="_blank" rel="noopener noreferrer" class="provider-link">View Provider Intelligence <i data-lucide="external-link"></i></a>`
        : `<span class="text-muted">Internal Dataset</span>`;

      const mockTag = source.status === 'mocked' 
        ? `<span class="mock-badge">Simulated Intelligence</span>` 
        : `<span class="mock-badge" style="color:var(--color-clean)">Live API</span>`;

      pCard.innerHTML = `
        <div>
          <div class="provider-top">
            <span class="provider-name">${escapeHtml(source.name)}</span>
            <span class="provider-duration">${source.duration_ms} ms</span>
          </div>
          <div>
            <span class="provider-verdict-badge ${pSev}">${source.verdict}</span>
          </div>
          <p class="provider-summary" style="margin-top: 0.75rem;">${escapeHtml(source.summary)}</p>
        </div>
        <div class="provider-bottom">
          ${linkHtml}
          ${mockTag}
        </div>
      `;
      providersGrid.appendChild(pCard);
    });
  }

  initLucideIcons();
  report.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function getSeverityClass(verdict, score) {
  if (verdict === 'malicious' || score >= 65) return 'severity-malicious';
  if (verdict === 'suspicious' || score >= 30) return 'severity-suspicious';
  if (verdict === 'clean') return 'severity-clean';
  return 'severity-unknown';
}

function getScoreColor(verdict, score) {
  if (verdict === 'malicious' || score >= 65) return '#ef4444';
  if (verdict === 'suspicious' || score >= 30) return '#f59e0b';
  if (verdict === 'clean') return '#10b981';
  return '#64748b';
}

/* ================= FILE SCANNER & CLIENT-SIDE HASHING ================= */
function initFileScanner() {
  const dropZone = document.getElementById('file-drop-zone');
  const fileInput = document.getElementById('file-upload-input');
  const btnBrowse = document.getElementById('btn-browse-file');
  const previewCard = document.getElementById('file-hashes-preview');
  const btnScan = document.getElementById('btn-scan-uploaded-file');

  btnBrowse.addEventListener('click', () => fileInput.click());
  dropZone.addEventListener('click', (e) => {
    if (e.target !== btnBrowse) fileInput.click();
  });

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
      handleFileSelected(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
      handleFileSelected(fileInput.files[0]);
    }
  });

  async function handleFileSelected(file) {
    state.selectedFile = file;
    document.getElementById('preview-filename').textContent = file.name;
    document.getElementById('preview-filesize').textContent = `(${(file.size / 1024).toFixed(1)} KB)`;
    previewCard.classList.remove('hidden');

    document.getElementById('preview-sha256').textContent = 'Computing SHA-256...';
    document.getElementById('preview-sha1').textContent = 'Computing SHA-1...';
    document.getElementById('preview-md5').textContent = 'Computing MD5...';

    const arrayBuffer = await file.arrayBuffer();

    // Compute Web Crypto Hashes
    const sha256Buffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
    const sha1Buffer = await crypto.subtle.digest('SHA-1', arrayBuffer);

    const sha256Hex = bufferToHex(sha256Buffer);
    const sha1Hex = bufferToHex(sha1Buffer);
    const md5Hex = computeFastMD5(new Uint8Array(arrayBuffer));

    document.getElementById('preview-sha256').textContent = sha256Hex;
    document.getElementById('preview-sha1').textContent = sha1Hex;
    document.getElementById('preview-md5').textContent = md5Hex;
  }

  btnScan.addEventListener('click', async () => {
    if (!state.selectedFile) return;

    btnScan.disabled = true;
    btnScan.innerHTML = `<div class="spinner" style="width:16px;height:16px;margin:0;display:inline-block;vertical-align:middle;border-width:2px;"></div> Scanning file...`;

    try {
      const formData = new FormData();
      formData.append('file', state.selectedFile);

      const res = await fetch('/api/scan/file', {
        method: 'POST',
        body: formData,
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || 'File scan failed');
      }

      const scanData = await res.json();
      state.currentScan = scanData;
      
      // Switch to unified scanner tab and render results
      switchTab('unified-scanner');
      document.getElementById('scan-results-container').classList.remove('hidden');
      renderScanReport(scanData);
      showToast('File scan completed successfully', 'success');
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      btnScan.disabled = false;
      btnScan.innerHTML = `<i data-lucide="shield-alert"></i> <span>Scan File Hash Now</span>`;
      initLucideIcons();
    }
  });
}

function bufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Fast JS MD5 implementation for client-side display
function computeFastMD5(data) {
  function md5cycle(x, k) {
    var a = x[0], b = x[1], c = x[2], d = x[3];
    a = ff(a, b, c, d, k[0], 7, -680876936);
    d = ff(d, a, b, c, k[1], 12, -389564586);
    c = ff(c, d, a, b, k[2], 17,  606105819);
    b = ff(b, c, d, a, k[3], 22, -1044525330);
    a = ff(a, b, c, d, k[4], 7, -176418897);
    d = ff(d, a, b, c, k[5], 12,  1200080426);
    c = ff(c, d, a, b, k[6], 17, -1473231341);
    b = ff(b, c, d, a, k[7], 22, -45705983);
    a = ff(a, b, c, d, k[8], 7,  1770035416);
    d = ff(d, a, b, c, k[9], 12, -1958414417);
    c = ff(c, d, a, b, k[10], 17, -42063);
    b = ff(b, c, d, a, k[11], 22, -1990404162);
    a = ff(a, b, c, d, k[12], 7,  1804603682);
    d = ff(d, a, b, c, k[13], 12, -40341101);
    c = ff(c, d, a, b, k[14], 17, -1502002290);
    b = ff(b, c, d, a, k[15], 22,  1236535329);
    x[0] = add32(a, x[0]);
    x[1] = add32(b, x[1]);
    x[2] = add32(c, x[2]);
    x[3] = add32(d, x[3]);
  }
  function cmn(q, a, b, x, s, t) {
    a = add32(add32(a, q), add32(x, t));
    return add32((a << s) | (a >>> (32 - s)), b);
  }
  function ff(a, b, c, d, x, s, t) {
    return cmn((b & c) | ((~b) & d), a, b, x, s, t);
  }
  function add32(a, b) {
    return (a + b) & 0xFFFFFFFF;
  }

  var n = data.length, state = [1732584193, -271733879, -1732584194, 271733878], i;
  for (i = 64; i <= n; i += 64) {
    var blk = [];
    for (var j = 0; j < 16; j++) {
      blk[j] = data[i - 64 + j * 4] | (data[i - 64 + j * 4 + 1] << 8) | (data[i - 64 + j * 4 + 2] << 16) | (data[i - 64 + j * 4 + 3] << 24);
    }
    md5cycle(state, blk);
  }
  return state.map(x => (x >>> 0).toString(16).padStart(8, '0')).join('');
}

/* ================= BULK MULTI-IOC SCANNER ================= */
function initBulkScanner() {
  const bulkInput = document.getElementById('bulk-text-input');
  const countIndicator = document.getElementById('bulk-detected-count');
  const btnScan = document.getElementById('btn-start-bulk-scan');
  const resultsContainer = document.getElementById('bulk-results-container');
  const tableBody = document.getElementById('bulk-table-body');
  const btnUploadCsv = document.getElementById('btn-upload-csv');
  const csvFileInput = document.getElementById('bulk-csv-file');
  const btnExportCsv = document.getElementById('btn-export-bulk-csv');

  bulkInput.addEventListener('input', () => {
    const lines = bulkInput.value.split(/[\r\n,;\t]+/).filter(l => l.trim().length > 0);
    countIndicator.textContent = `${lines.length} IOCs detected`;
  });

  btnUploadCsv.addEventListener('click', () => csvFileInput.click());

  csvFileInput.addEventListener('change', (e) => {
    if (csvFileInput.files.length > 0) {
      const file = csvFileInput.files[0];
      const reader = new FileReader();
      reader.onload = (event) => {
        bulkInput.value = event.target.result;
        const lines = bulkInput.value.split(/[\r\n,;\t]+/).filter(l => l.trim().length > 0);
        countIndicator.textContent = `${lines.length} IOCs detected from ${file.name}`;
      };
      reader.readAsText(file);
    }
  });

  btnScan.addEventListener('click', async () => {
    const content = bulkInput.value.trim();
    if (!content) {
      showToast('Please enter at least one IOC to scan', 'error');
      return;
    }

    btnScan.disabled = true;
    btnScan.innerHTML = `<div class="spinner" style="width:16px;height:16px;margin:0;display:inline-block;vertical-align:middle;border-width:2px;"></div> Scanning batch...`;

    try {
      const res = await fetch('/api/scan/bulk', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: content, force_refresh: false }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || 'Bulk scan failed');
      }

      const data = await res.json();
      state.bulkResults = data.results;

      // Update Metric Bars
      document.getElementById('bulk-total-val').textContent = data.total;
      document.getElementById('bulk-malicious-val').textContent = data.malicious_count;
      document.getElementById('bulk-suspicious-val').textContent = data.suspicious_count;
      document.getElementById('bulk-clean-val').textContent = data.clean_count;

      // Populate Table
      tableBody.innerHTML = '';
      data.results.forEach(row => {
        const tr = document.createElement('tr');
        const sevClass = getSeverityClass(row.verdict, row.confidence_score);
        tr.innerHTML = `
          <td>${row.index + 1}</td>
          <td><code>${escapeHtml(row.defanged || row.indicator)}</code></td>
          <td><span class="meta-tag">${row.ioc_type.toUpperCase()}</span></td>
          <td><span class="provider-verdict-badge ${sevClass}">${row.verdict}</span></td>
          <td><strong>${Math.round(row.confidence_score)} / 100</strong></td>
          <td><span class="risk-level-badge ${sevClass}">${row.risk_level}</span></td>
          <td>${row.is_cached ? '<span class="cached-pill"><i data-lucide="database"></i> Cached</span>' : 'Fresh Scan'}</td>
          <td>
            <button class="btn-secondary btn-sm btn-inspect-row" data-ioc="${escapeHtml(row.indicator)}">
              Inspect
            </button>
          </td>
        `;
        tableBody.appendChild(tr);
      });

      // Wire inspect buttons
      document.querySelectorAll('.btn-inspect-row').forEach(b => {
        b.addEventListener('click', (e) => {
          const ioc = e.currentTarget.getAttribute('data-ioc');
          document.getElementById('ioc-input').value = ioc;
          switchTab('unified-scanner');
          document.getElementById('single-scan-form').dispatchEvent(new Event('submit'));
        });
      });

      resultsContainer.classList.remove('hidden');
      initLucideIcons();
      showToast(`Bulk scan finished in ${data.duration_seconds}s`, 'success');
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      btnScan.disabled = false;
      btnScan.innerHTML = `<i data-lucide="play"></i> <span>Execute Batch Scan</span>`;
      initLucideIcons();
    }
  });

  // Export Bulk CSV
  btnExportCsv.addEventListener('click', () => {
    if (!state.bulkResults || state.bulkResults.length === 0) return;

    let csvContent = 'Index,Indicator,Defanged,Type,Verdict,Score,RiskLevel,Cached\n';
    state.bulkResults.forEach(r => {
      csvContent += `${r.index + 1},"${r.indicator}","${r.defanged}",${r.ioc_type},${r.verdict},${r.confidence_score},${r.risk_level},${r.is_cached}\n`;
    });

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `threatscope_batch_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  });
}

/* ================= EMAIL & HEADER INSPECTOR ================= */
function initEmailScanner() {
  const form = document.getElementById('email-scan-form');
  const headersInput = document.getElementById('email-headers-input');
  const btnLoadSample = document.getElementById('btn-load-sample-email');

  const SAMPLE_PHISHING_EMAIL = `Received: from mail.spoof-gateway.net (mail.spoof-gateway.net [198.51.100.33])
Authentication-Results: mx.google.com;
       dkim=fail header.i=@legit-bank.com;
       spf=fail (google.com: domain of alert@legit-bank.com does not designate 198.51.100.33 as permitted sender)
       dmarc=fail (p=REJECT)
Return-Path: <bounce@spoof-gateway.net>
From: "Security Operations Center" <alert@legit-bank.com>
Subject: Action Required: Unauthorized login attempt detected on your corporate account
Date: Wed, 12 Aug 2026 14:22:00 +0000
Message-ID: <threat-987654@spoof-gateway.net>
Content-Type: text/plain

Dear User,

We noticed a suspicious login to your account from IP 185.220.101.5 (Russia).
Please review your credentials immediately at:
hxxps[://]verify-login-portal[.]security-update[.]xyz/auth/session.php

Thank you,
IT Security Desk`;

  btnLoadSample.addEventListener('click', () => {
    headersInput.value = SAMPLE_PHISHING_EMAIL;
    showToast('Phishing header sample loaded', 'success');
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const content = headersInput.value.trim();
    if (!content) return;

    document.getElementById('ioc-input').value = content;
    switchTab('unified-scanner');
    document.getElementById('single-scan-form').dispatchEvent(new Event('submit'));
  });
}

/* ================= SCAN AUDIT LOG ================= */
function initHistoryView() {
  const typeFilter = document.getElementById('history-type-filter');
  const verdictFilter = document.getElementById('history-verdict-filter');
  const searchInput = document.getElementById('history-search-input');
  const btnClear = document.getElementById('btn-clear-history');

  typeFilter.addEventListener('change', loadHistory);
  verdictFilter.addEventListener('change', loadHistory);

  let searchTimeout = null;
  searchInput.addEventListener('input', () => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(loadHistory, 300);
  });

  btnClear.addEventListener('click', async () => {
    if (confirm('Are you sure you want to clear all scan history records?')) {
      try {
        await fetch('/api/history', { method: 'DELETE' });
        showToast('Scan history cleared', 'success');
        loadHistory();
      } catch (err) {
        showToast('Failed to clear history', 'error');
      }
    }
  });
}

async function loadHistory() {
  const type = document.getElementById('history-type-filter').value;
  const verdict = document.getElementById('history-verdict-filter').value;
  const search = document.getElementById('history-search-input').value.trim();
  const tableBody = document.getElementById('history-table-body');
  const emptyState = document.getElementById('history-empty');

  try {
    let url = `/api/history?limit=100&ioc_type=${type}&verdict=${verdict}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;

    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to fetch history');

    const data = await res.json();
    tableBody.innerHTML = '';

    if (data.records && data.records.length > 0) {
      emptyState.classList.add('hidden');
      data.records.forEach(rec => {
        const tr = document.createElement('tr');
        const sevClass = getSeverityClass(rec.verdict, rec.confidence_score);
        tr.innerHTML = `
          <td><code>${escapeHtml(rec.defanged_indicator || rec.indicator)}</code></td>
          <td><span class="meta-tag">${rec.type.toUpperCase()}</span></td>
          <td><span class="provider-verdict-badge ${sevClass}">${rec.verdict}</span></td>
          <td><strong>${Math.round(rec.confidence_score)} / 100</strong></td>
          <td><span class="risk-level-badge ${sevClass}">${rec.risk_level}</span></td>
          <td>${new Date(rec.scanned_at).toLocaleString()}</td>
          <td>
            <button class="btn-secondary btn-sm btn-rescan-history" data-ioc="${escapeHtml(rec.indicator)}">
              Re-Scan
            </button>
          </td>
        `;
        tableBody.appendChild(tr);
      });

      document.querySelectorAll('.btn-rescan-history').forEach(b => {
        b.addEventListener('click', (e) => {
          const ioc = e.currentTarget.getAttribute('data-ioc');
          document.getElementById('ioc-input').value = ioc;
          switchTab('unified-scanner');
          document.getElementById('single-scan-form').dispatchEvent(new Event('submit'));
        });
      });
    } else {
      emptyState.classList.remove('hidden');
    }
    initLucideIcons();
  } catch (err) {
    showToast('Failed to load history audit log', 'error');
  }
}

/* ================= SETTINGS & API KEYS MODAL ================= */
function initSettingsModal() {
  const modal = document.getElementById('settings-modal');
  const btnOpen = document.getElementById('settings-btn');
  const btnClose = document.getElementById('btn-close-settings');
  const btnCancel = document.getElementById('btn-cancel-settings');
  const form = document.getElementById('api-keys-form');

  btnOpen.addEventListener('click', async () => {
    modal.classList.remove('hidden');
    await loadSettingsStatus();
  });

  btnClose.addEventListener('click', () => modal.classList.add('hidden'));
  btnCancel.addEventListener('click', () => modal.classList.add('hidden'));

  form.addEventListener('submit', async (e) => {
    e.preventDefault();

    const payload = {};
    const vt = document.getElementById('key-virustotal').value.trim();
    const abuse = document.getElementById('key-abuseipdb').value.trim();
    const urlscan = document.getElementById('key-urlscan').value.trim();
    const gsb = document.getElementById('key-safebrowsing').value.trim();
    const mb = document.getElementById('key-malwarebazaar').value.trim();

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
        showToast('API Configuration saved successfully', 'success');
        modal.classList.add('hidden');
        loadSettingsStatus();
      } else {
        throw new Error('Failed to save keys');
      }
    } catch (err) {
      showToast(err.message, 'error');
    }
  });
}

async function loadSettingsStatus() {
  try {
    const res = await fetch('/api/settings');
    if (res.ok) {
      const data = await res.json();
      data.keys.forEach(k => {
        let tagId = '';
        if (k.name.includes('VirusTotal')) tagId = 'status-virustotal';
        else if (k.name.includes('AbuseIPDB')) tagId = 'status-abuseipdb';
        else if (k.name.includes('URLScan')) tagId = 'status-urlscan';
        else if (k.name.includes('Safe Browsing')) tagId = 'status-safebrowsing';
        else if (k.name.includes('MalwareBazaar')) tagId = 'status-malwarebazaar';

        if (tagId) {
          const el = document.getElementById(tagId);
          if (el) {
            if (k.configured) {
              el.textContent = 'Configured (Active)';
              el.classList.add('active');
            } else {
              el.textContent = 'Simulated / Mock';
              el.classList.remove('active');
            }
          }
        }
      });
    }
  } catch (err) {}
}

/* ================= QUICK SAMPLE PILLS ================= */
function initSampleButtons() {
  document.querySelectorAll('.example-pill').forEach(btn => {
    btn.addEventListener('click', () => {
      const ioc = btn.getAttribute('data-ioc');
      document.getElementById('ioc-input').value = ioc;
      document.getElementById('single-scan-form').dispatchEvent(new Event('submit'));
    });
  });
}

/* ================= HELPERS & TOASTS ================= */
function showToast(message, type = 'success') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  container.appendChild(toast);

  setTimeout(() => {
    toast.remove();
  }, 4000);
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
