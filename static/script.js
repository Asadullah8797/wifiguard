/* ═══════════════════════════════════════════════
   WiFiGuard v2.0 — Frontend Logic
═══════════════════════════════════════════════ */

let currentScanId = null;
let monitoringTimer = null;
let monitoringNextAt = null;
let riskChart = null;
let threatChart = null;
let currentScanMode = 'quick';

function setScanMode(mode) {
  currentScanMode = mode === 'full' ? 'full' : 'quick';
  const q = document.getElementById('quickModeBtn');
  const f = document.getElementById('fullModeBtn');
  if (q) q.classList.toggle('active', currentScanMode === 'quick');
  if (f) f.classList.toggle('active', currentScanMode === 'full');
}

// ── Detect public IP via ipify (sent to backend) ──────────────────────────

async function getPublicIp() {
  try {
    const r = await fetch('https://api.ipify.org?format=json', { signal: AbortSignal.timeout(5000) });
    return (await r.json()).ip;
  } catch {
    try {
      const r = await fetch('https://api64.ipify.org?format=json', { signal: AbortSignal.timeout(5000) });
      return (await r.json()).ip;
    } catch { return null; }
  }
}

// ── Loading Step Animator ─────────────────────────────────────────────────

let stepTimer = null;

function startStepAnimation() {
  const steps = document.querySelectorAll('.step-item');
  steps.forEach(s => { s.classList.remove('active','done'); s.textContent = s.dataset.original || s.textContent; });
  let i = 0;
  stepTimer = setInterval(() => {
    if (i > 0 && steps[i-1]) {
      steps[i-1].classList.remove('active'); steps[i-1].classList.add('done');
      steps[i-1].textContent = '✦' + steps[i-1].textContent.slice(1);
    }
    if (i < steps.length) { steps[i].classList.add('active'); i++; }
    else clearInterval(stepTimer);
  }, 700);
}

function stopStepAnimation() {
  clearInterval(stepTimer);
  document.querySelectorAll('.step-item').forEach(s => {
    s.classList.remove('active'); s.classList.add('done');
    s.textContent = '✦' + s.textContent.slice(1);
  });
}

// ── Section Control ───────────────────────────────────────────────────────

function showOnly(id) {
  ['loadingSection','resultsSection'].forEach(s => {
    document.getElementById(s).style.display = 'none';
  });
  if (id) document.getElementById(id).style.display = '';
}

// ── Main Scan ─────────────────────────────────────────────────────────────

async function startScan() {
  const btn      = document.getElementById('scanBtn');
  const btnText  = document.getElementById('scanBtnText');
  btn.disabled   = true;
  btnText.textContent = 'Scanning…';

  // Reset step labels
  const labels = [
    '⬡ Fetching network information…','⬡ Checking HTTPS connectivity…',
    '⬡ Validating SSL certificates…','⬡ Analyzing DNS behavior…',
    '⬡ Detecting captive portals…','⬡ Checking redirect patterns…',
    '⬡ Running MITM heuristics…','⬡ Computing risk score…',
  ];
  document.querySelectorAll('.step-item').forEach((s,i) => { s.textContent = labels[i] || '⬡ …'; s.classList.remove('active','done'); });

  showOnly('loadingSection');
  startStepAnimation();

  // Get public IP from browser first
  const clientIp = await getPublicIp();

  try {
    const res  = await fetch('/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_ip: clientIp, scan_mode: currentScanMode }),
    });

    stopStepAnimation();

    if (!res.ok) throw new Error(`Server error ${res.status}`);
    const json = await res.json();
    if (!json.success) throw new Error(json.error || 'Unknown error');

    renderResults(json.data);
    showOnly('resultsSection');
    // update charts after scan
    loadHistoryAndCharts();
    document.getElementById('resultsSection').scrollIntoView({ behavior: 'smooth', block: 'start' });

  } catch (err) {
    stopStepAnimation();
    showOnly(null);
    showError('Scan failed: ' + err.message);
  } finally {
    btn.disabled  = false;
    btnText.textContent = 'Scan Network';
  }
}

// ── Error Toast ───────────────────────────────────────────────────────────

function showError(msg) {
  const existing = document.getElementById('errorToast');
  if (existing) existing.remove();
  const toast = document.createElement('div');
  toast.id = 'errorToast';
  toast.style.cssText = `
    position:fixed;bottom:2rem;left:50%;transform:translateX(-50%);
    background:#1a0a0e;border:1px solid rgba(255,51,85,.4);color:#ff8899;
    font-family:var(--mono);font-size:.82rem;padding:.8rem 1.4rem;
    border-radius:10px;z-index:999;max-width:90%;text-align:center;
    animation:fadeIn .3s ease;box-shadow:0 4px 24px rgba(0,0,0,.6);`;
  toast.textContent = '⚠ ' + msg;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 6000);
}

// ── Render Results ────────────────────────────────────────────────────────

function renderResults(d) {
  currentScanId = d.scan_id;

  const colorMap = { green: '#00e676', cyan: '#00bcd4', yellow: '#ffd600', red: '#ff3355' };
  const sc = colorMap[d.color] || '#00d4b4';

  // Some elements only exist on the Dashboard page, so guard all DOM updates.
  const statusBanner = document.getElementById('statusBanner');
  if (statusBanner) statusBanner.style.setProperty('--status-color', sc);
  document.documentElement.style.setProperty('--status-color', sc);

  // ── Network info bar ──
  const net = d.network_info || {};
  const bar = document.getElementById('netInfoBar');
  const niIp = document.getElementById('niIp');
  const niLoc = document.getElementById('niLoc');
  const niIsp = document.getElementById('niIsp');
  const niLocalIp = document.getElementById('niLocalIp');
  if (niIp) niIp.textContent = net.public_ip || d.client_ip || '—';
  if (niLoc) niLoc.textContent = [net.city, net.country].filter(Boolean).join(', ') || '—';
  if (niIsp) niIsp.textContent = (net.isp || '—').replace(/^AS\\d+\\s/, '');
  if (niLocalIp) {
    const localIp = (net.local_ip || '').trim();
    niLocalIp.textContent = localIp || '—';
  }
  if (bar) bar.style.display = 'inline-flex';

  // ── Status banner ──
  const statusIcon = document.getElementById('statusIcon');
  const statusValue = document.getElementById('statusValue');
  const statusMeta = document.getElementById('statusMeta');
  if (statusIcon) {
    const iconPaths = {
      green:  '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4" stroke-linecap="round" stroke-linejoin="round"/>',
      yellow: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>',
      red:    '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>',
    };
    statusIcon.innerHTML = iconPaths[d.color] || iconPaths.green;
  }
  if (statusValue) {
    const emoji = { green:'✅', yellow:'⚠️', red:'❌' };
    statusValue.textContent = `${emoji[d.color]||''} ${d.status}`;
  }
  if (statusMeta) {
    statusMeta.textContent =
      `${net.city || ''} ${net.country ? '· ' + net.country : ''} · ${net.isp || ''}`.replace(/^[\\s·]+/, '');
  }

  // Animate only if the ring elements exist (Dashboard).
  if (document.getElementById('scoreArc') && document.getElementById('scoreNum')) {
    animateScore(d.risk_score, sc);
  }

  // ── Breakdown pills ──
  const bdRow = document.getElementById('breakdownRow');
  if (bdRow) {
    const bdLabels = {
      https_connectivity:'HTTPS',
      ssl_validation:'SSL',
      dns_health:'DNS',
      redirect_validation:'Redirects',
      mitm_indicators:'MITM',
      portal_check:'Portal',
    };
    const bd = d.breakdown || {};
    bdRow.innerHTML = Object.entries(bdLabels).map(([k,l]) => {
      const entry = bd[k] || {};
      const points = entry.points ?? 0;
      const max = entry.max ?? 0;
      const cls = max && points >= (max * 0.75) ? 'ok' : (max && points >= (max * 0.4) ? 'warn' : 'bad');
      return `<div class="bd-pill">
        <span class="bd-pill-label">${l}</span>
        <span class="bd-pill-val ${cls}">${points}/${max || 0}</span>
      </div>`;
    }).join('');
  }

  // ── Detailed checks on dashboard cards ──
  const https = d.checks?.https || [];
  const ssl = d.checks?.ssl || [];
  const dns = d.checks?.dns || [];
  const redirects = d.checks?.redirects || [];
  const mitm = d.mitm_warnings || [];

  const httpsFail = https.filter(r => !r.ok).length;
  setBadge('httpsBadge', httpsFail ? 'bad' : 'ok', httpsFail ? 'FAIL' : 'PASS');
  const httpsBody = document.getElementById('httpsBody');
  if (httpsBody) httpsBody.innerHTML = https.map(r => `<div class="check-row"><span class="check-icon">${r.ok?'🟢':'🔴'}</span><span class="check-text">${short(r.url)}<span class="check-sub">${r.ok?`HTTP ${r.status} · ${r.latency_ms}ms`:(r.error||'Failed')}</span></span></div>`).join('');

  const sslFail = ssl.filter(r => !r.valid).length;
  setBadge('sslBadge', sslFail ? 'bad' : 'ok', sslFail ? 'FAIL' : 'PASS');
  const sslBody = document.getElementById('sslBody');
  if (sslBody) sslBody.innerHTML = ssl.map(r => `<div class="check-row"><span class="check-icon">${r.valid?'🟢':'🔴'}</span><span class="check-text">${r.host}<span class="check-sub">${r.valid?`Expires ${r.expires} (${r.days_until_expiry}d)`:(r.error||'Invalid cert')}</span></span></div>`).join('');

  setBadge('dnsBadge', d.dns_suspicious ? 'warn' : 'ok', d.dns_suspicious ? 'SUSPICIOUS' : 'NORMAL');
  const dnsBody = document.getElementById('dnsBody');
  if (dnsBody) dnsBody.innerHTML = dns.map(r => `<div class="check-row"><span class="check-icon">${r.expected_prefix_match?'🟢':'🟡'}</span><span class="check-text">${r.domain}<span class="check-sub">${r.error || (r.resolved_ips||[]).join(', ')}</span></span></div>`).join('');

  setBadge('redirectBadge', d.redirect_suspicious ? 'warn' : 'ok', d.redirect_suspicious ? 'ISSUES' : 'PASS');
  const redirectBody = document.getElementById('redirectBody');
  if (redirectBody) redirectBody.innerHTML = redirects.map(r => `<div class="check-row"><span class="check-icon">${r.upgraded_to_https?'🟢':'🟡'}</span><span class="check-text">${short(r.original)}<span class="check-sub">${r.upgraded_to_https?'HTTPS enforced':'Not upgraded to HTTPS'}</span></span></div>`).join('');

  setBadge('mitmBadge', mitm.length ? 'bad' : 'ok', mitm.length ? `${mitm.length} WARN` : 'CLEAR');
  const mitmBody = document.getElementById('mitmBody');
  if (mitmBody) mitmBody.innerHTML = mitm.length ? mitm.map(w => `<div class="check-row"><span class="check-icon">🔴</span><span class="check-text">${escapeHtml(w)}</span></div>`).join('') : `<div class="check-row"><span class="check-icon">🟢</span><span class="check-text">No MITM indicators detected</span></div>`;

  setBadge('confBadge', d.confidence === 'High' ? 'ok' : (d.confidence === 'Medium' ? 'warn' : 'bad'), (d.confidence || 'Unknown').toUpperCase());
  const confBody = document.getElementById('confBody');
  if (confBody) confBody.innerHTML = `<div class="check-row"><span class="check-icon">ℹ️</span><span class="check-text">Confidence: ${escapeHtml(d.confidence || 'Unknown')}<span class="check-sub">Based on number of successful checks.</span></span></div>`;

  const dev = d.devices || { count: 0, list: [], scan_mode: currentScanMode };
  const hasNew = (dev.new_count || 0) > 0;
  const modeLabel = (dev.scan_mode || 'quick').toUpperCase();
  const devCount = Number(dev.total_devices ?? dev.count ?? 0) || 0;
  const badgeTone = dev.skipped ? 'warn' : (hasNew ? 'warn' : (devCount > 0 ? 'ok' : 'warn'));
  setBadge('devBadge', badgeTone, `Devices Connected: ${devCount} · ${modeLabel}`);
  const devBody = document.getElementById('devBody');
  if (devBody) {
    if (dev.skipped) {
      const disclaimer = `<div class="check-row"><span class="check-icon">ℹ️</span><span class="check-text">Note<span class="check-sub">${escapeHtml(dev.disclaimer || 'Device detection is based on ARP cache and active probing.')}</span></span></div>`;
      devBody.innerHTML = `<div class="check-row"><span class="check-icon">⚡</span><span class="check-text">Device scan skipped (Quick mode)<span class="check-sub">Switch to Full Scan for ARP + active probing and accurate device count.</span></span></div>${disclaimer}`;
      return;
    }
    const rows = (dev.list || []).slice(0, 12).map(x => {
      const tag = x.status_tag === 'new' ? '🟡 New' : (x.status_tag === 'unknown' ? '⚠ Unknown' : '🟢 Known');
      const typeIcon = x.type === 'Mobile' ? '📱'
        : (x.type === 'Laptop/Desktop' ? '💻'
        : (x.type === 'Router' ? '🌐'
        : '⚠️'));
      const vendor = (x.vendor && x.vendor !== 'Unidentified Device') ? x.vendor : '';
      const host = x.hostname && x.hostname !== 'No Hostname' ? x.hostname : 'No Hostname';
      let label = '';
      if (x.type === 'Router') {
        label = `${escapeHtml(x.ip)} → Router (${escapeHtml(vendor || 'Generic Device')}) [${escapeHtml(host)}]`;
      } else if (vendor) {
        label = `${escapeHtml(x.ip)} → ${escapeHtml(vendor)} (${escapeHtml(x.type || 'Generic Device')}) [${escapeHtml(host)}]`;
      } else if (x.type && x.type !== 'Generic Device') {
        label = `${escapeHtml(x.ip)} → Generic Device (${escapeHtml(x.type)}) [${escapeHtml(host)}]`;
      } else {
        label = `${escapeHtml(x.ip)} → Unidentified Device ⚠️`;
      }
      return `<div class="check-row"><span class="check-icon">${typeIcon}</span><span class="check-text">${label}<span class="check-sub">${escapeHtml(x.mac)} · ${tag}</span></span></div>`;
    }).join('');
    const emptyMsg = escapeHtml(dev.message || 'No local ARP entries found');
    const emptySub = dev.message
      ? 'Try Full Scan again after local network traffic is active.'
      : 'Device scan may require local network activity.';
    const disclaimer = `<div class="check-row"><span class="check-icon">ℹ️</span><span class="check-text">Note<span class="check-sub">${escapeHtml(dev.disclaimer || 'Device detection is based on ARP cache and active probing.')}</span></span></div>`;
    devBody.innerHTML = (rows || `<div class="check-row"><span class="check-icon">ℹ️</span><span class="check-text">${emptyMsg}<span class="check-sub">${escapeHtml(emptySub)}</span></span></div>`) + disclaimer;
  }

  const gw = d.gateway || {};
  setBadge('gwBadge', gw.changed ? 'warn' : 'ok', gw.changed ? 'CHANGED' : 'STABLE');
  const gwBody = document.getElementById('gwBody');
  if (gwBody) {
    gwBody.innerHTML = `<div class="check-row"><span class="check-icon">${gw.changed ? '⚠️' : '🟢'}</span><span class="check-text">Gateway ${escapeHtml(gw.ip || 'Unknown')}<span class="check-sub">MAC: ${escapeHtml(gw.mac || 'Unknown')}${gw.changed ? ' · Changed from previous scan' : ''}</span></span></div>`;
  }

  const ar = document.getElementById('alertRow');
  if (ar) {
    const severe = d.status === 'Dangerous' || (mitm.length > 0 && sslFail > 0 && d.redirect_suspicious);
    const title = severe ? 'High Risk Network' : 'Assessment';
    const msg = hasNew
      ? '⚠ New device detected on your network.'
      : ((d.findings && d.findings.length) ? d.findings[0] : 'No critical finding from current checks.');
    ar.style.display = '';
    ar.innerHTML = `<div class="alert-banner ${severe ? 'bad' : 'warn'}"><div class="alert-title">${escapeHtml(title)}</div><div class="alert-msg">${escapeHtml(msg)}</div></div>`;
  }

  // ── Threat chart from breakdown ──
  renderThreatChart(d.breakdown || {});

  // ── Recommendations ──
  const recList = document.getElementById('recList');
  if (recList) {
    recList.innerHTML = (d.recommendations || [])
      .map((r,i) => `<li style="animation-delay:${i*.06}s">${r}</li>`).join('');
  }

  // ── Meta ──
  const metaIp = document.getElementById('metaIp');
  const metaDuration = document.getElementById('metaDuration');
  const metaTime = document.getElementById('metaTime');
  if (metaIp) metaIp.textContent = d.client_ip;
  if (metaDuration) metaDuration.textContent = d.scan_duration_sec;
  if (metaTime) metaTime.textContent = d.timestamp;

  // ── Report button ──
  const rBtn = document.getElementById('reportBtn');
  if (rBtn) rBtn.style.display = d.scan_id ? '' : 'none';
}

// ── Score Ring ────────────────────────────────────────────────────────────

function animateScore(target, color) {
  const arc = document.getElementById('scoreArc');
  const num = document.getElementById('scoreNum');
  arc.style.stroke = color;
  const circ = 326.7;
  let current = 0;
  const start = performance.now();
  const dur   = 1100;
  (function step(now) {
    const p = Math.min((now - start) / dur, 1);
    const e = 1 - Math.pow(1 - p, 3);
    current = Math.round(target * e);
    num.textContent = current;
    arc.style.strokeDashoffset = circ - (current / 100) * circ;
    if (p < 1) requestAnimationFrame(step);
  })(performance.now());
}

// ── Download PDF Report ───────────────────────────────────────────────────

function downloadReport() {
  if (!currentScanId) return;
  window.location.href = `/report/${currentScanId}`;
}

// ── Load History ──────────────────────────────────────────────────────────

async function loadHistory() {
  try {
    const res  = await fetch('/api/history');
    const json = await res.json();
    if (!json.success) return;

    return json.history || [];
  } catch { /* silent */ }
  return [];
}

// ── Helpers ───────────────────────────────────────────────────────────────

function setBadge(id, cls, text) {
  const el = document.getElementById(id);
  if (!el) return;
  el.className = 'card-badge ' + cls;
  el.textContent = text;
}

function short(url) {
  try { return new URL(url).hostname; } catch { return url || '—'; }
}

function escapeHtml(s) {
  return String(s || '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function renderThreatChart(bd) {
  const labels = [
    ['https_connectivity','HTTPS'],
    ['ssl_validation','SSL'],
    ['dns_health','DNS'],
    ['redirect_validation','Redirects'],
    ['mitm_indicators','MITM'],
    ['portal_check','Portal'],
  ];
  const data = labels.map(([k,l]) => {
    const points = bd?.[k]?.points ?? 0;
    const max = bd?.[k]?.max ?? 0;
    const riskDelta = Math.max(0, max - points);
    return { label: l, val: riskDelta };
  }).filter(x => x.val > 0);

  const badge = document.getElementById('threatChartBadge');
  if (badge) badge.textContent = data.length ? `${data.length} TYPE(S)` : 'NONE';

  const ctx = document.getElementById('threatChart');
  if (!ctx) return;
  const chartData = {
    labels: data.length ? data.map(x => x.label) : ['No threats'],
    datasets: [{
      data: data.length ? data.map(x => x.val) : [1],
      backgroundColor: data.length
        ? ['#ff3355','#ffd600','#00d4b4','#4dabff','#8b5cf6','#00e676','#f97316','#f43f5e']
        : ['rgba(255,255,255,0.08)'],
      borderColor: 'rgba(255,255,255,0.06)',
      borderWidth: 1,
    }],
  };

  if (threatChart) {
    threatChart.data = chartData;
    threatChart.update();
    return;
  }
  threatChart = new Chart(ctx, {
    type: 'doughnut',
    data: chartData,
    options: {
      responsive: true,
      plugins: { legend: { labels: { color: '#b8ccd8', font: { family: 'Share Tech Mono' } } } },
      cutout: '62%',
    },
  });
}

async function loadHistoryAndCharts() {
  const history = await loadHistory();
  renderRiskChart(history);
}

function renderRiskChart(history) {
  const el = document.getElementById('riskChart');
  if (!el) return;
  const badge = document.getElementById('riskChartBadge');
  if (badge) badge.textContent = history.length ? `${history.length} SCAN(S)` : '—';

  const points = (history || []).slice().reverse().slice(-12);
  const labels = points.map(h => (h.timestamp || '').slice(5, 16));
  const values = points.map(h => h.risk_score ?? 0);

  const data = {
    labels: labels.length ? labels : ['—'],
    datasets: [{
      label: 'Risk Score',
      data: values.length ? values : [0],
      borderColor: '#00d4b4',
      backgroundColor: 'rgba(0,212,180,0.12)',
      tension: 0.35,
      fill: true,
      pointRadius: 2.5,
      pointHoverRadius: 4,
    }],
  };

  if (riskChart) {
    riskChart.data = data;
    riskChart.update();
    return;
  }
  riskChart = new Chart(el, {
    type: 'line',
    data,
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#4e667a' }, grid: { color: 'rgba(255,255,255,0.04)' } },
        y: { ticks: { color: '#4e667a' }, grid: { color: 'rgba(255,255,255,0.04)' }, suggestedMin: 0, suggestedMax: 100 },
      },
    },
  });
}

function toggleMonitoring(on) {
  const badge = document.getElementById('monitorBadge');
  const intervalEl = document.getElementById('monInterval');
  const lastEl = document.getElementById('monLast');
  const nextEl = document.getElementById('monNext');

  if (!on) {
    if (monitoringTimer) clearInterval(monitoringTimer);
    monitoringTimer = null;
    monitoringNextAt = null;
    if (badge) { badge.className = 'card-badge ok'; badge.textContent = 'IDLE'; }
    if (intervalEl) intervalEl.textContent = '—';
    if (nextEl) nextEl.textContent = '—';
    return;
  }

  const secs = 30 + Math.floor(Math.random() * 31); // 30–60s
  const tick = () => {
    const now = Date.now();
    if (!monitoringNextAt || now >= monitoringNextAt) {
      monitoringNextAt = now + secs * 1000;
      if (badge) { badge.className = 'card-badge warn'; badge.textContent = 'RUNNING'; }
      startScan().finally(() => {
        if (badge) { badge.className = 'card-badge ok'; badge.textContent = 'ACTIVE'; }
        if (lastEl) lastEl.textContent = new Date().toLocaleTimeString();
      });
    }
    const left = Math.max(0, Math.ceil((monitoringNextAt - now) / 1000));
    if (nextEl) nextEl.textContent = left ? `${left}s` : '—';
  };

  if (intervalEl) intervalEl.textContent = `${secs}s`;
  if (badge) { badge.className = 'card-badge ok'; badge.textContent = 'ACTIVE'; }
  monitoringNextAt = Date.now() + secs * 1000;
  tick();
  monitoringTimer = setInterval(tick, 1000);
}

// ── Init ──────────────────────────────────────────────────────────────────

loadHistoryAndCharts();
