const state = {
  activeTab: 'recon',
  activeSubTab: 'alive',
  currentJob: null,
  reconResults: null,
  elapsedTimer: null,
  gitdumpFindings: [],
  gitdumpSelected: null,
};

function switchTab(tab) {
  if (tab === 'subdomain') tab = 'subdomains';
  if (tab === 'dirscan') tab = 'exposures';
  state.activeTab = tab;
  const modules = ['recon', 'subdomains', 'associated', 'ports', 'crawler', 'exposures', 'gitdump'];
  modules.forEach(m => {
    const el = document.getElementById(`module-${m}`);
    const btn = document.getElementById(`tab-${m}`);
    if (el) el.classList.toggle('hidden', m !== tab);
    if (btn) btn.classList.toggle('active', m === tab);
  });
}

function toggleGuide() {
  const body = document.getElementById('guide-body');
  const btn = document.getElementById('guide-toggle-btn');
  if (!body) return;
  const isHidden = body.style.display === 'none' || !body.style.display;
  body.style.display = isHidden ? 'block' : 'none';
  if (btn) btn.textContent = isHidden ? '▲' : '▼';
}

function openPrintableReport() {
  if (!state.currentJob || !state.currentJob.id) {
    toast('No completed scan session found. Run a scan first.', true);
    return;
  }
  window.open(`/api/jobs/${state.currentJob.id}/report/html`, '_blank');
}

function exportReport(fmt) {
  if (!state.currentJob || !state.currentJob.id) {
    toast('No completed scan session to export.', true);
    return;
  }
  window.open(`/api/jobs/${state.currentJob.id}/export?format=${fmt}`, '_blank');
}

function filterSubTab(tab) {
  state.activeSubTab = tab;
  const aliveBtn = document.getElementById('itab-alive');
  const allBtn = document.getElementById('itab-all');
  if (aliveBtn) aliveBtn.classList.toggle('active', tab === 'alive');
  if (allBtn) allBtn.classList.toggle('active', tab === 'all');
  if (state.reconResults) renderSubdomainsTable(state.reconResults.subdomains);
}

function switchCrawlerTab(tab) {
  ['pages', 'api', 'scripts'].forEach(st => {
    const btn = document.getElementById('ctab-' + st);
    const panel = document.getElementById('cpanel-' + st);
    if (btn) btn.classList.toggle('active', st === tab);
    if (panel) panel.classList.toggle('hidden', st !== tab);
  });
}

function setPresetDomain(domain) {
  const input = document.getElementById('domain-input');
  if (input) {
    input.value = domain;
    input.focus();
    toast(`Target preset: ${domain}`);
  }
}

function appendTLD(tld) {
  const input = document.getElementById('domain-input');
  if (!input) return;
  let val = input.value.trim();
  if (!val) {
    input.value = 'target' + tld;
  } else {
    let host = val.replace(/^https?:\/\//i, '').split('/')[0];
    input.value = host.split('.')[0] + tld;
  }
  input.focus();
}

function toast(msg, isErr = false) {
  const c = document.getElementById('toast-container');
  if (!c) return;
  const t = document.createElement('div');
  t.className = 'toast' + (isErr ? ' toast-err' : '');
  t.textContent = msg;
  c.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function termAppend(text) {
  const el = document.getElementById('recon-terminal');
  if (!el) return;
  const last = el.querySelector('.cursor-blink');
  if (last) last.classList.remove('cursor-blink');

  const div = document.createElement('div');
  div.className = 't-line';
  let cls = 'info';
  if (text.includes('[✓]') || text.includes('[OK]') || text.startsWith('[+]')) cls = 'ok';
  if (text.includes('[EXPOSED]') || text.includes('SECRET')) cls = 'exposed';
  if (text.startsWith('[!]')) cls = 'warn';
  if (text.toLowerCase().includes('error')) cls = 'err';

  div.innerHTML = `<span class="t-prefix">›</span><span class="t-text ${cls} cursor-blink">${escapeHtml(text)}</span>`;
  el.appendChild(div);
  el.scrollTop = el.scrollHeight;
}

function clearTerminal() {
  const el = document.getElementById('recon-terminal');
  if (el) el.innerHTML = '';
}

function updateStepper(currentPhase, statusText, pct) {
  const fill = document.getElementById('stepper-progress-fill');
  const badge = document.getElementById('stepper-pct-badge');
  const status = document.getElementById('stepper-status-text');
  if (fill) fill.style.width = `${pct}%`;
  if (badge) badge.textContent = `${pct}% Completed`;
  if (status && statusText) status.textContent = statusText;

  for (let i = 1; i <= 6; i++) {
    const node = document.getElementById(`step-node-${i}`);
    if (!node) continue;
    if (pct >= 100) {
      node.classList.remove('active');
      node.classList.add('completed');
    } else if (i < currentPhase) {
      node.classList.remove('active');
      node.classList.add('completed');
    } else if (i === currentPhase) {
      node.classList.add('active');
      node.classList.remove('completed');
    } else {
      node.classList.remove('active', 'completed');
    }
  }
}

function startScan(scanType) {
  const inputEl = document.getElementById('domain-input');
  const domain = inputEl ? inputEl.value.trim() : '';
  if (!domain) return toast('Enter a target domain', true);

  if (state.currentJob && state.currentJob.sse) {
    state.currentJob.sse.close();
  }

  clearTerminal();
  termAppend(`[*] Target: ${domain}`);
  updateStepper(1, 'Initializing Pipeline...', 5);

  const titleEl = document.getElementById('terminal-title');
  if (titleEl) titleEl.textContent = `${scanType.toUpperCase()} — ${domain}`;

  document.getElementById('start-full-btn').disabled = true;
  document.querySelectorAll('.btn-module-run').forEach(b => (b.disabled = true));
  document.getElementById('stop-scan-btn').classList.remove('hidden');
  document.getElementById('server-label').textContent = 'Scanning';
  document.getElementById('export-bar').classList.add('hidden');

  ['subdomains', 'alive', 'ports', 'pages', 'exposures'].forEach(id => {
    const el = document.getElementById(`stat-${id}`);
    if (el) el.textContent = '0';
  });

  const rate = document.getElementById('scope-rate')?.value || '10';
  const depth = document.getElementById('scope-depth')?.value || '2';
  const ports = document.getElementById('scope-ports')?.value || 'web';

  const endpointMap = {
    full: '/api/scan/full',
    subdomain: '/api/scan/subdomains',
    subdomains: '/api/scan/subdomains',
    associated: '/api/scan/associated',
    ports: '/api/scan/ports',
    crawler: '/api/scan/crawler',
    directories: '/api/scan/directories',
  };
  const endpoint = endpointMap[scanType] || `/api/scan/${scanType}`;

  fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain, options: { rate_limit: rate, max_depth: depth, port_profile: ports } }),
  })
    .then(r => r.json())
    .then(data => {
      if (data.error) {
        toast(data.error, true);
        termAppend(`[ERROR] ${data.error}`);
        resetUI();
        return;
      }
      state.currentJob = { id: data.job_id, domain: data.domain };
      const sse = new EventSource(`/api/jobs/${data.job_id}/stream`);
      state.currentJob.sse = sse;

      let cSub = 0, cAlive = 0, cPort = 0, cPage = 0, cExp = 0;

      sse.onmessage = e => {
        const d = JSON.parse(e.data);
        if (d.error) {
          termAppend(`[ERROR] ${d.error}`);
          sse.close();
          resetUI();
          return;
        }
        if (d.line) {
          termAppend(d.line);
          if (d.line.includes('[PHASE:1:START]')) updateStepper(1, 'Phase 1: Scope Validation', 15);
          if (d.line.includes('[PHASE:2:START]')) updateStepper(2, 'Phase 2: Associated Roots', 25);
          if (d.line.includes('[PHASE:3:START]')) updateStepper(3, 'Phase 3: Subdomain Enumeration', 40);
          if (d.line.includes('[PHASE:4:START]')) updateStepper(4, 'Phase 4: Port Scanning', 60);
          if (d.line.includes('[PHASE:5:START]')) updateStepper(5, 'Phase 5: Crawling & Secret Hunting', 80);
          if (d.line.includes('[PHASE:6:START]')) updateStepper(6, 'Phase 6: Directory Audit', 90);
          if (d.line.includes('[PHASE:DONE]')) updateStepper(6, 'Pipeline Complete', 100);

          if (d.line.includes('Aggregated') || d.line.includes('Discovered')) {
            const m = d.line.match(/(\d+)\s+(?:candidate\s+)?subdomains/i);
            if (m) {
              cSub = Math.max(cSub, parseInt(m[1], 10));
              document.getElementById('stat-subdomains').textContent = cSub;
            }
          }
          if (d.line.includes('ALIVE:')) document.getElementById('stat-alive').textContent = ++cAlive;
          if (d.line.startsWith('[PORT]')) document.getElementById('stat-ports').textContent = ++cPort;
          if (d.line.includes('Crawling:')) document.getElementById('stat-pages').textContent = ++cPage;
          if (d.line.includes('[EXPOSED]') || d.line.includes('SECRET')) {
            document.getElementById('stat-exposures').textContent = ++cExp;
          }
        }
        if (d.done) {
          sse.close();
          resetUI();
          if (d.status === 'stopped') {
            updateStepper(1, 'Scan Stopped by User', 0);
            toast('Scan stopped.');
          } else if (d.status === 'failed') {
            updateStepper(1, 'Scan Failed', 0);
            toast('Scan failed. Check terminal output.', true);
          } else {
            updateStepper(6, 'Pipeline Complete', 100);
          }
          if (d.result && Object.keys(d.result).length > 0 && d.status !== 'failed') {
            state.reconResults = d.result;
            renderAll(d.result);
            document.getElementById('export-bar').classList.remove('hidden');
            const expTotal =
              (d.result.directories?.sensitive_findings?.length || 0) +
              (d.result.crawler?.exposed_secrets?.length || 0);
            if (d.status === 'completed') {
              toast(`Scan complete! Found ${expTotal} exposures.`);
            }
            refreshSessionDropdown();
          }
        }
      };

      sse.onerror = () => {
        sse.close();
        resetUI();
      };
    })
    .catch(err => {
      toast(`Failed to start scan: ${err.message}`, true);
      resetUI();
    });
}

function stopActiveScan() {
  if (state.currentJob) {
    if (state.currentJob.sse) state.currentJob.sse.close();
    fetch(`/api/jobs/${state.currentJob.id}/stop`, { method: 'POST' }).catch(() => {});
  }
  resetUI();
}

function resetUI() {
  document.getElementById('start-full-btn').disabled = false;
  document.querySelectorAll('.btn-module-run').forEach(b => (b.disabled = false));
  document.getElementById('stop-scan-btn').classList.add('hidden');
  document.getElementById('server-label').textContent = 'Ready';
}

function renderAll(r) {
  const subs = r.subdomains?.records || [];
  const ports = r.ports?.findings || [];
  const pages = r.crawler?.pages || [];
  const jsSecrets = r.crawler?.exposed_secrets || [];
  const dirSens = r.directories?.sensitive_findings || [];
  const takeovers = r.subdomains?.takeover_findings || [];

  document.getElementById('stat-subdomains').textContent = subs.length;
  document.getElementById('stat-alive').textContent = subs.filter(s => s.alive).length;
  document.getElementById('stat-ports').textContent = ports.length;
  document.getElementById('stat-pages').textContent = pages.length;
  document.getElementById('stat-exposures').textContent = jsSecrets.length + dirSens.length + takeovers.length;

  renderRiskAssessment(r.risk_assessment);

  // Overview Cards
  document.getElementById('overview-sub-list').innerHTML =
    subs.slice(0, 5).map(s => `<div class="overview-item">● ${escapeHtml(s.subdomain)}</div>`).join('') || 'No data';
  document.getElementById('overview-assoc-list').innerHTML =
    (r.associated_domains || []).slice(0, 5).map(a => `<div class="overview-item">⎇ ${escapeHtml(a.domain)}</div>`).join('') || 'No data';
  document.getElementById('overview-port-list').innerHTML =
    ports.slice(0, 5).map(p => `<div class="overview-item">⚡ ${escapeHtml(p.host)}:${escapeHtml(p.port)}</div>`).join('') || 'No data';

  let expHtml = '';
  takeovers.slice(0, 2).forEach(t => {
    expHtml += `<div class="overview-item text-red">⚠️ Takeover: ${escapeHtml(t.subdomain)}</div>`;
  });
  dirSens.slice(0, 3).forEach(s => {
    expHtml += `<div class="overview-item text-red">🔐 ${escapeHtml(s.url)}</div>`;
  });
  jsSecrets.slice(0, 2).forEach(s => {
    expHtml += `<div class="overview-item text-red">🔐 ${escapeHtml(s.type)} in JS</div>`;
  });
  document.getElementById('overview-exp-list').innerHTML = expHtml || 'No data';

  // Tables
  renderSubdomainsTable(r.subdomains);
  renderPortsTable(r.ports);
  renderCrawler(r.crawler);
  renderAssociated(r.associated_domains);
  renderExposures(jsSecrets, dirSens, r.directories?.directory_findings || [], takeovers);
}

function renderRiskAssessment(risk) {
  const card = document.getElementById('risk-posture-card');
  const pill = document.getElementById('risk-score-pill');
  const list = document.getElementById('risk-recs-list');
  if (!card || !pill || !list) return;
  if (!risk) {
    card.classList.add('hidden');
    return;
  }
  card.classList.remove('hidden');
  const col = risk.color || '#38bdf8';
  card.style.borderLeftColor = col;
  pill.textContent = `${risk.level || 'LOW'} RISK (${risk.score ?? 10}/100)`;
  pill.style.color = col;
  pill.style.borderColor = col + '55';
  pill.style.background = col + '18';

  const recs = risk.recommendations || [];
  if (!recs.length) {
    list.innerHTML = '<div style="font-size:0.82rem;color:var(--blue-bright);">✓ No high-risk exposures or immediate remediation actions identified.</div>';
    return;
  }
  list.innerHTML = recs
    .map(
      rec => `
    <div class="rec-item">
      <div class="rec-item-title">
        <span class="badge" style="color:${rec.severity === 'CRITICAL' ? 'var(--red)' : rec.severity === 'HIGH' ? 'var(--yellow)' : 'var(--blue-bright)'};">${escapeHtml(rec.severity)}</span>
        <span>${escapeHtml(rec.title)}</span>
      </div>
      <div style="color:var(--text-dim);font-size:0.8rem;">${escapeHtml(rec.desc)}</div>
      <div class="rec-item-action">→ Fix: ${escapeHtml(rec.action)}</div>
    </div>
  `
    )
    .join('');
}

function renderSubdomainsTable(data) {
  if (!data) return;
  const records = data.records || [];
  const q = (document.getElementById('subdomain-search-input')?.value || '').trim().toLowerCase();
  let list = state.activeSubTab === 'alive' ? records.filter(r => r.alive) : records;
  if (q) {
    list = list.filter(
      r =>
        (r.subdomain || '').toLowerCase().includes(q) ||
        (r.ip || '').toLowerCase().includes(q) ||
        (r.waf || '').toLowerCase().includes(q) ||
        (r.server || '').toLowerCase().includes(q) ||
        (r.title || '').toLowerCase().includes(q)
    );
  }
  document.getElementById('subdomains-tbody').innerHTML =
    list
      .map((r, i) => {
        const sh = r.sec_headers || {};
        const secHtml = r.alive
          ? [
              ['HSTS', sh.hsts],
              ['CSP', sh.csp],
              ['XFO', sh.x_frame_options],
              ['XCTO', sh.x_content_type],
            ]
              .map(([lbl, ok]) => `<span class="sec-pill ${ok ? 'sec-pill--ok' : 'sec-pill--miss'}" title="${lbl}: ${ok ? 'Present' : 'Missing'}">${lbl}</span>`)
              .join('')
          : '<span style="color:var(--text-dim)">-</span>';
        const wafBadge =
          r.waf && r.waf !== 'None' && r.waf !== 'Direct / Unknown'
            ? `<div style="font-size:0.7rem;color:var(--blue-bright);margin-top:2px;">🛡️ ${escapeHtml(r.waf)}</div>`
            : '';
        return `
    <tr>
      <td>${i + 1}</td>
      <td class="text-blue" style="font-family:var(--font-mono);font-weight:600;">${escapeHtml(r.subdomain)}</td>
      <td style="color:var(--text-dim);font-family:var(--font-mono);font-size:0.78rem;">${escapeHtml(r.ip)}</td>
      <td><span class="badge ${r.alive ? 'badge--green' : ''}">${escapeHtml(r.status_code)}</span></td>
      <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escapeHtml(r.title || '')}">${escapeHtml(r.title || '-')}</td>
      <td><div>${escapeHtml(r.server)}</div>${wafBadge}</td>
      <td>${secHtml}</td>
      <td><a href="${escapeHtml(r.url)}" target="_blank" rel="noopener" class="btn-secondary" style="padding:3px 9px;font-size:0.75rem;">Visit ↗</a></td>
    </tr>
  `;
      })
      .join('') || '<tr><td colspan="8" class="table-empty">No subdomains found.</td></tr>';
}

function renderPortsTable(data) {
  if (!data) return;
  const findings = data.findings || [];
  document.getElementById('ports-tbody').innerHTML =
    findings
      .map(
        (p, i) => `
    <tr>
      <td>${i + 1}</td>
      <td style="font-family:var(--font-mono);font-weight:600;">${escapeHtml(p.host)}</td>
      <td class="text-yellow" style="font-weight:bold;">${escapeHtml(p.port)}</td>
      <td>${escapeHtml(p.protocol)}</td>
      <td>${escapeHtml(p.service)}</td>
      <td style="color:var(--text-dim)">${escapeHtml(p.banner)}</td>
    </tr>
  `
      )
      .join('') || '<tr><td colspan="6" class="table-empty">No open ports.</td></tr>';
}

function renderCrawler(data) {
  if (!data) return;
  const pages = data.pages || [];
  const apis = data.api_endpoints || [];
  const scripts = data.scripts || [];

  document.getElementById('crawler-pages-tbody').innerHTML =
    pages
      .map(
        (p, i) => `
    <tr><td>${i + 1}</td><td class="text-blue" style="font-family:var(--font-mono)">${escapeHtml(p.url)}</td><td><span class="badge">${escapeHtml(p.status)}</span></td><td>${escapeHtml(p.depth)}</td></tr>
  `
      )
      .join('') || '<tr><td colspan="4" class="table-empty">No pages.</td></tr>';

  document.getElementById('crawler-api-tbody').innerHTML =
    apis
      .map(
        (a, i) => `
    <tr><td>${i + 1}</td><td class="text-purple" style="font-family:var(--font-mono)">${escapeHtml(a)}</td><td><a href="${escapeHtml(a)}" target="_blank" rel="noopener" class="btn-secondary" style="padding:2px 8px;font-size:0.75rem;">Open ↗</a></td></tr>
  `
      )
      .join('') || '<tr><td colspan="3" class="table-empty">No APIs.</td></tr>';

  document.getElementById('crawler-scripts-tbody').innerHTML =
    scripts
      .map(
        (s, i) => `
    <tr><td>${i + 1}</td><td style="font-family:var(--font-mono);color:var(--text-dim)">${escapeHtml(s)}</td><td><a href="${escapeHtml(s)}" target="_blank" rel="noopener" class="btn-secondary" style="padding:2px 8px;font-size:0.75rem;">Inspect ↗</a></td></tr>
  `
      )
      .join('') || '<tr><td colspan="3" class="table-empty">No scripts.</td></tr>';
}

function renderAssociated(data) {
  if (!data) return;
  document.getElementById('associated-cards-container').innerHTML =
    data
      .map(
        a => `
    <div class="assoc-card" style="background:var(--bg-input);border:1px solid var(--border);padding:1rem;border-radius:8px;margin-bottom:0.5rem;">
      <div class="assoc-domain" style="font-family:var(--font-mono);font-weight:bold;color:var(--cyan);">${escapeHtml(a.domain)}</div>
      <div class="assoc-rel" style="font-size:0.8rem;color:var(--text-dim);margin-top:4px;">${escapeHtml(a.relationship)} (${escapeHtml(a.source || 'OSINT')})</div>
    </div>
  `
      )
      .join('') || '<div class="table-empty">No associated roots.</div>';
}

function renderExposures(jsSecrets, dirSens, dirs, takeovers = []) {
  let html = '';
  let rowIdx = 1;
  takeovers.forEach(t => {
    html += `<tr style="background:rgba(255,68,102,0.08);"><td>${rowIdx++}</td><td class="text-red" style="font-family:var(--font-mono);font-weight:600;">${escapeHtml(t.subdomain)}</td><td><span class="badge badge--red" style="background:rgba(255,68,102,0.2);color:var(--red);padding:2px 8px;border-radius:4px;font-size:0.7rem;">Subdomain Takeover (${escapeHtml(t.takeover_provider)})</span></td><td style="font-family:var(--font-mono);color:var(--red);">${escapeHtml(t.cname)}</td><td>Dangling CNAME</td><td><a href="${escapeHtml(t.url)}" target="_blank" rel="noopener" class="btn-secondary" style="padding:2px 8px;font-size:0.75rem;">Verify ↗</a></td></tr>`;
  });
  dirSens.forEach(s => {
    html += `<tr style="background:rgba(255,68,102,0.05);"><td>${rowIdx++}</td><td class="text-red" style="font-family:var(--font-mono);font-weight:600;">${escapeHtml(s.url)}</td><td><span class="badge badge--red" style="background:rgba(255,68,102,0.2);color:var(--red);padding:2px 8px;border-radius:4px;font-size:0.7rem;">Sensitive File</span></td><td>${escapeHtml(s.status)}</td><td>${escapeHtml(s.size)} B</td><td><a href="${escapeHtml(s.url)}" target="_blank" rel="noopener" class="btn-secondary" style="padding:2px 8px;font-size:0.75rem;">Review ↗</a></td></tr>`;
    if (s.url && s.url.includes('/.git/HEAD') && !state.gitdumpFindings.includes(s.url)) {
      state.gitdumpFindings.push(s.url);
    }
  });
  jsSecrets.forEach(s => {
    html += `<tr style="background:rgba(255,140,66,0.05);"><td>${rowIdx++}</td><td class="text-yellow" style="font-family:var(--font-mono);font-weight:600;">${escapeHtml(s.url)}</td><td><span class="badge badge--orange" style="background:rgba(255,140,66,0.2);color:var(--yellow);padding:2px 8px;border-radius:4px;font-size:0.7rem;">JS Secret (${escapeHtml(s.type)})</span></td><td style="font-family:var(--font-mono);color:var(--red);word-break:break-all;">${escapeHtml(s.match)}</td><td>-</td><td><a href="${escapeHtml(s.url)}" target="_blank" rel="noopener" class="btn-secondary" style="padding:2px 8px;font-size:0.75rem;">Review ↗</a></td></tr>`;
  });

  document.getElementById('sensitive-tbody').innerHTML =
    html || '<tr><td colspan="6" class="table-empty text-green">✓ No sensitive exposures found.</td></tr>';

  document.getElementById('directories-tbody').innerHTML =
    dirs
      .map(
        (d, i) => `
    <tr><td>${i + 1}</td><td class="text-blue" style="font-family:var(--font-mono)">${escapeHtml(d.url)}</td><td><span class="badge">${escapeHtml(d.status)}</span></td><td>${escapeHtml(d.size)} B</td><td><a href="${escapeHtml(d.url)}" target="_blank" rel="noopener" class="btn-secondary" style="padding:2px 8px;font-size:0.75rem;">Open ↗</a></td></tr>
  `
      )
      .join('') || '<tr><td colspan="5" class="table-empty">No directories.</td></tr>';

  renderGitDumpFindings();
}

// ─── Git-Dumper Integration ─────────────────────────────────
function renderGitDumpFindings() {
  const list = document.getElementById('gitdump-findings-list');
  if (!list) return;
  if (!state.gitdumpFindings.length) {
    list.innerHTML = '<div class="table-empty" style="padding:1rem !important;">No /.git/HEAD targets added yet.</div>';
    return;
  }
  list.innerHTML = state.gitdumpFindings
    .map(
      url => `
    <div style="display:flex;align-items:center;justify-content:space-between;padding:0.6rem 1rem;border:1px solid ${state.gitdumpSelected === url ? 'var(--red)' : 'var(--border)'};border-radius:8px;margin-bottom:0.5rem;background:var(--bg-input);">
      <span style="font-family:var(--font-mono);font-size:0.85rem;color:var(--cyan);">${escapeHtml(url)}</span>
      <button class="btn-secondary" onclick="selectGitDumpTarget('${escapeHtml(url)}')">Select Target</button>
    </div>
  `
    )
    .join('');
}

function selectGitDumpTarget(url) {
  state.gitdumpSelected = url;
  renderGitDumpFindings();
  const confirmCard = document.getElementById('gitdump-confirm-card');
  if (confirmCard) confirmCard.classList.remove('hidden');
  const disp = document.getElementById('gitdump-target-display');
  if (disp) disp.textContent = url;
}

function addCustomGitDumpTarget() {
  const input = document.getElementById('gitdump-custom-url');
  const url = input ? input.value.trim() : '';
  if (!url || !url.endsWith('/.git/HEAD')) {
    toast('URL must end with /.git/HEAD (e.g. https://target.com/.git/HEAD)', true);
    return;
  }
  if (!state.gitdumpFindings.includes(url)) {
    state.gitdumpFindings.push(url);
  }
  selectGitDumpTarget(url);
  if (input) input.value = '';
  toast(`Target added: ${url}`);
}

function toggleGitDumpBtn() {
  const cb = document.getElementById('gitdump-authorized-checkbox');
  const btn = document.getElementById('start-gitdump-btn');
  if (btn && cb) btn.disabled = !cb.checked;
}

function startGitDump() {
  if (!state.gitdumpSelected) {
    toast('Please select or add a /.git/HEAD target first.', true);
    return;
  }
  const cb = document.getElementById('gitdump-authorized-checkbox');
  if (!cb || !cb.checked) {
    toast('You must confirm legal authorization first.', true);
    return;
  }
  fetch('/api/gitdump/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ git_head_url: state.gitdumpSelected, authorized: true }),
  })
    .then(r => r.json())
    .then(data => {
      if (data.error) {
        toast(data.error, true);
      } else {
        toast(`Git extraction job started for ${data.label}`);
        switchTab('recon');
        clearTerminal();
        termAppend(`[*] Starting git-dumper extraction for: ${data.target}`);
        const sse = new EventSource(`/api/jobs/${data.job_id}/stream`);
        state.currentJob = { id: data.job_id, domain: data.label, sse };
        sse.onmessage = e => {
          const d = JSON.parse(e.data);
          if (d.line) termAppend(d.line);
          if (d.done) {
            sse.close();
            resetUI();
          }
        };
        sse.onerror = () => {
          sse.close();
          resetUI();
        };
      }
    })
    .catch(err => toast(err.message, true));
}

function refreshSessionDropdown() {
  const sel = document.getElementById('session-select');
  if (!sel) return;
  fetch('/api/sessions')
    .then(r => r.json())
    .then(sessions => {
      if (!Array.isArray(sessions)) return;
      const completed = sessions.filter(s => s.status === 'completed');
      sel.innerHTML =
        '<option value="">-- Load Past Scan (' + completed.length + ') --</option>' +
        completed
          .map(
            s =>
              `<option value="${escapeHtml(s.id)}">${escapeHtml(s.domain)} [${escapeHtml((s.type || 'full').toUpperCase())}]</option>`
          )
          .join('');
    })
    .catch(() => {});
}

function loadSavedSession(jobId) {
  if (!jobId) return;
  fetch(`/api/jobs/${jobId}/status`)
    .then(r => r.json())
    .then(job => {
      if (job.error || !job.result) {
        toast('Could not load saved session.', true);
        return;
      }
      state.currentJob = { id: job.id, domain: job.domain };
      state.reconResults = job.result;
      const domIn = document.getElementById('domain-input');
      if (domIn && job.domain) domIn.value = job.domain;
      clearTerminal();
      termAppend(`[+] Loaded saved scan session for: ${job.domain} (${job.created_at || ''})`);
      updateStepper(6, `Loaded Session — ${job.domain}`, 100);
      renderAll(job.result);
      document.getElementById('export-bar').classList.remove('hidden');
      toast(`Loaded scan results for ${job.domain}`);
    })
    .catch(err => toast(err.message, true));
}

document.addEventListener('DOMContentLoaded', () => {
  renderGitDumpFindings();
  refreshSessionDropdown();
  const domIn = document.getElementById('domain-input');
  if (domIn) {
    domIn.addEventListener('keydown', e => {
      if (e.key === 'Enter') startScan('full');
    });
  }
  const gitIn = document.getElementById('gitdump-custom-url');
  if (gitIn) {
    gitIn.addEventListener('keydown', e => {
      if (e.key === 'Enter') addCustomGitDumpTarget();
    });
  }
});
