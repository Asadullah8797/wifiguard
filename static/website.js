function colorMap(color) {
  return ({ green: '#00e676', yellow: '#ffd600', red: '#ff3355' }[color]) || '#00d4b4';
}

function escapeHtml(s) {
  return String(s || '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function setBadge(id, cls, text) {
  const el = document.getElementById(id);
  if (!el) return;
  el.className = 'card-badge ' + cls;
  el.textContent = text;
}

function animateArc(id, score, color) {
  const arc = document.getElementById(id);
  if (!arc) return;
  arc.style.stroke = color;
  const circ = 326.7;
  arc.style.strokeDashoffset = circ - (score / 100) * circ;
}

function statusToIcon(color) {
  return ({
    green:  '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4" stroke-linecap="round" stroke-linejoin="round"/>',
    yellow: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>',
    red:    '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>',
  }[color]) || '';
}

let lastWebsiteUrl = null;

async function scanWebsite() {
  const inp = document.getElementById('urlInput');
  const btn = document.getElementById('webScanBtn');
  const txt = document.getElementById('webScanText');
  const pdfBtn = document.getElementById('webPdfBtn');
  const url = (inp.value || '').trim();
  if (!url) return;

  btn.disabled = true;
  txt.textContent = 'Scanning…';
  if (pdfBtn) pdfBtn.style.display = 'none';
  try {
    const res = await fetch('/api/website-scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    const j = await res.json();
    if (!j.success) throw new Error(j.error || 'Scan failed');
    lastWebsiteUrl = url;
    renderWebsite(j.data);
    if (pdfBtn) pdfBtn.style.display = '';
  } catch (e) {
    alert(`Website scan failed: ${e.message}`);
  } finally {
    btn.disabled = false;
    txt.textContent = 'Scan Website';
  }
}

async function downloadWebsitePdf() {
  const url = (lastWebsiteUrl || document.getElementById('urlInput')?.value || '').trim();
  if (!url) return;
  const res = await fetch('/api/website-report', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });
  if (!res.ok) {
    try {
      const j = await res.json();
      throw new Error(j.error || 'Failed to generate report');
    } catch {
      throw new Error('Failed to generate report');
    }
  }
  const blob = await res.blob();
  const cd = res.headers.get('content-disposition') || '';
  const match = /filename=\"?([^\";]+)\"?/i.exec(cd);
  const filename = match?.[1] || 'WiFiGuard_Website_Report.pdf';
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 0);
}

function renderWebsite(d) {
  document.getElementById('webResults').style.display = '';
  const sc = colorMap(d.color);
  document.getElementById('webBanner').style.setProperty('--status-color', sc);
  document.getElementById('webIcon').innerHTML = statusToIcon(d.color);
  document.getElementById('webStatus').textContent = d.status;
  document.getElementById('webMeta').textContent = d.final_url;
  document.getElementById('webScore').textContent = d.risk_score;
  animateArc('webArc', d.risk_score, sc);

  // HTTPS / SSL
  const httpsOk = d.https_final === true;
  const sslOk = d.ssl?.valid === true;
  setBadge('webSslBadge', (httpsOk && sslOk) ? 'ok' : 'bad', (httpsOk && sslOk) ? 'OK' : 'ISSUES');
  document.getElementById('webSslBody').innerHTML = `
    <div class="check-row"><span class="check-icon">${d.https_final ? '🟢' : '🔴'}</span>
      <span class="check-text">HTTPS final
        <span class="check-sub">${d.https_final ? 'Final destination uses HTTPS' : 'Final destination is not HTTPS (high risk)'}</span>
      </span>
    </div>
    <div class="check-row"><span class="check-icon">${d.https_enforced ? '🟢' : '🟡'}</span>
      <span class="check-text">HTTPS enforcement
        <span class="check-sub">${d.https_enforced ? 'HTTP redirects to HTTPS' : 'HTTP is not cleanly enforced (SSL stripping risk)'}</span>
      </span>
    </div>
    <div class="check-row"><span class="check-icon">${d.ssl?.valid ? '🟢' : '🔴'}</span>
      <span class="check-text">SSL certificate
        <span class="check-sub">${d.ssl?.valid ? `Valid · Expires ${d.ssl.expires} (${d.ssl.days_until_expiry}d)` : (d.ssl?.error || 'Validation failed')}</span>
      </span>
    </div>
  `;

  // Redirects
  const chain = d.redirect_chain || [];
  const redirects = d.redirect_count ?? Math.max(0, chain.length - 1);
  const redirCls = redirects > 3 || d.cross_domain_redirect ? 'warn' : 'ok';
  setBadge('webRedirBadge', redirCls, `${redirects} REDIRECT(S)`);
  document.getElementById('webRedirBody').innerHTML = chain.map(x => `
    <div class="check-row">
      <span class="check-icon">${(x.status >= 200 && x.status < 400) ? '🟢' : '🟡'}</span>
      <span class="check-text">${escapeHtml(x.url)}
        <span class="check-sub">${escapeHtml(String(x.status))}${x.location ? ` · Location: ${escapeHtml(x.location)}` : ''}</span>
      </span>
    </div>
  `).join('');

  // Headers
  const checks = d.header_checks || [];
  const missing = d.missing_security_headers || checks.filter(c => !c.present).map(c => c.name);
  setBadge('webHdrBadge', missing.length ? 'warn' : 'ok', missing.length ? `${missing.length} MISSING` : 'OK');
  document.getElementById('webHdrBody').innerHTML = checks.map(c => `
    <div class="check-row">
      <span class="check-icon">${c.present ? '🟢' : (c.risk === 'High' ? '🔴' : '🟡')}</span>
      <span class="check-text">${escapeHtml(c.name)}
        <span class="check-sub">${c.present ? `Present · ${escapeHtml((c.value||'')).slice(0,140)}` : escapeHtml(c.explanation || 'Missing')}</span>
      </span>
    </div>
  `).join('');
}

document.getElementById('urlInput')?.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') scanWebsite();
});

