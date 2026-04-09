function escapeHtml(s) {
  return String(s || '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

async function loadHistory() {
  const res = await fetch('/api/history');
  const json = await res.json();
  if (!json.success) return [];
  return json.history || [];
}

function render(history) {
  const tbody = document.getElementById('historyTableBody');
  const empty = document.getElementById('historyEmpty');
  const counter = document.getElementById('historyCount');

  counter.textContent = `${history.length} scan(s)`;
  if (!history.length) {
    tbody.innerHTML = '';
    empty.style.display = '';
    return;
  }
  empty.style.display = 'none';

  tbody.innerHTML = history.map(h => `
    <tr>
      <td><span class="h-status ${h.color}"><span class="h-dot ${h.color}"></span>${escapeHtml(h.status)}</span></td>
      <td><span class="h-score ${h.color}">${escapeHtml(String(h.risk_score))}/100</span></td>
      <td>${escapeHtml(h.public_ip || '—')}</td>
      <td>${escapeHtml([h.city, h.country].filter(Boolean).join(', ') || '—')}</td>
      <td>${escapeHtml((h.isp||'—').replace(/^AS\\d+\\s/,'').slice(0,28))}</td>
      <td>${escapeHtml(String(h.duration))}s</td>
      <td>${escapeHtml(h.timestamp)}</td>
      <td class="h-actions">
        <a class="h-report-btn" href="/report/${h.id}" title="Download PDF">PDF</a>
      </td>
    </tr>`).join('');
}

(async function init() {
  try {
    const history = await loadHistory();
    render(history);
  } catch {
    render([]);
  }
})();

