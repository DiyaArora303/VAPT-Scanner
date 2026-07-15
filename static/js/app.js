/* =========================================================
   VAPT Scanner — Frontend Logic (app.js)
   ========================================================= */

// ─── State ───────────────────────────────────────────────
const state = {
  activeTab: 'subdomain',
  subdomainJob: null,      // { id, domain, startTime, sse }
  dirJob: null,            // { id, domain, startTime, sse }
  aliveFile: null,         // path from last subdomain scan
  aliveFileDomain: null,
  subResults: { alive: [], all: [] },
  dirResults: { findings: [] },
  subElapsedTimer: null,
  dirElapsedTimer: null,
};

// ─── Tab Switching ────────────────────────────────────────
function switchTab(tab) {
  state.activeTab = tab;
  document.getElementById('module-subdomain').classList.toggle('hidden', tab !== 'subdomain');
  document.getElementById('module-dirscan').classList.toggle('hidden', tab !== 'dirscan');
  document.getElementById('tab-subdomain').classList.toggle('active', tab === 'subdomain');
  document.getElementById('tab-dirscan').classList.toggle('active', tab === 'dirscan');
}

// ─── Toast ────────────────────────────────────────────────
function toast(msg, isErr = false) {
  const c = document.getElementById('toast-container');
  const t = document.createElement('div');
  t.className = 'toast' + (isErr ? ' toast-err' : '');
  t.textContent = msg;
  c.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}

// ─── Terminal helpers ─────────────────────────────────────
function termAppend(termId, text) {
  const el = document.getElementById(termId);
  if (!el) return;

  // Remove cursor from last line
  const last = el.querySelector('.cursor-blink');
  if (last) last.classList.remove('cursor-blink');

  const div = document.createElement('div');
  div.className = 't-line';

  const prefix = document.createElement('span');
  prefix.className = 't-prefix';
  prefix.textContent = '›';

  const span = document.createElement('span');
  span.className = 't-text ' + classifyLine(text);
  span.textContent = text;
  span.classList.add('cursor-blink');

  div.appendChild(prefix);
  div.appendChild(span);
  el.appendChild(div);
  el.scrollTop = el.scrollHeight;
}

function classifyLine(line) {
  if (line.includes('[✓]') || line.startsWith('[+]')) return 'ok';
  if (line.startsWith('[!]')) return 'warn';
  if (line.startsWith('[ERROR]') || line.includes('error')) return 'err';
  if (line.startsWith('[*]')) return 'info';
  if (line.includes('EXPOSED')) return 'exposed';
  return '';
}

function clearTerminal(termId) {
  const el = document.getElementById(termId);
  if (el) el.innerHTML = '';
}

function removeCursor(termId) {
  const el = document.getElementById(termId);
  if (!el) return;
  el.querySelectorAll('.cursor-blink').forEach(e => e.classList.remove('cursor-blink'));
}

// ─── Elapsed Timer ────────────────────────────────────────
function startElapsed(timerKey, statId) {
  if (state[timerKey]) clearInterval(state[timerKey]);
  const start = Date.now();
  state[timerKey] = setInterval(() => {
    const s = Math.floor((Date.now() - start) / 1000);
    const el = document.getElementById(statId);
    if (el) el.textContent = s < 60 ? `${s}s` : `${Math.floor(s/60)}m${s%60}s`;
  }, 1000);
}

function stopElapsed(timerKey) {
  if (state[timerKey]) { clearInterval(state[timerKey]); state[timerKey] = null; }
}

// ─── Chip animation helpers ───────────────────────────────
const TOOL_CHIPS = ['subfinder','assetfinder','amass','chaos','github','certspotter','anubis'];
const CHIP_KEYWORDS = {
  subfinder:    ['Subfinder'],
  assetfinder:  ['Assetfinder'],
  amass:        ['Amass'],
  chaos:        ['Chaos'],
  github:       ['GitHub'],
  certspotter:  ['certspotter','CertSpotter'],
  anubis:       ['Anubis','anubis'],
};

function resetChips() {
  TOOL_CHIPS.forEach(id => {
    const el = document.getElementById('chip-' + id);
    if (el) el.className = 'chip';
  });
}

function updateChipsFromLine(line) {
  TOOL_CHIPS.forEach(id => {
    const el = document.getElementById('chip-' + id);
    if (!el) return;
    const keywords = CHIP_KEYWORDS[id];
    if (keywords.some(k => line.includes(k))) {
      if (line.startsWith('[*]')) el.className = 'chip running';
      else if (line.startsWith('[+]')) el.className = 'chip done';
      else if (line.startsWith('[!]')) el.className = 'chip skipped';
    }
  });
}

// ─── ═══════════════════════════════════════
//     SUBDOMAIN SCANNER
// ═════════════════════════════════════════
function startSubdomainScan() {
  const domain = document.getElementById('domain-input').value.trim().toLowerCase();
  if (!domain) { toast('Please enter a domain', true); return; }
  if (state.subdomainJob && state.subdomainJob.status === 'running') {
    toast('A scan is already running', true); return;
  }

  // Reset UI
  resetChips();
  clearTerminal('sub-terminal');
  document.getElementById('sub-terminal-card').style.display = 'block';
  document.getElementById('sub-stats-row').style.display = 'grid';
  document.getElementById('sub-results-card').style.display = 'none';
  document.getElementById('stat-total').textContent = '0';
  document.getElementById('stat-alive').textContent = '0';
  document.getElementById('stat-elapsed').textContent = '0s';
  document.getElementById('sub-terminal-title').textContent = `bash — subdomain_finder.sh ${domain}`;
  document.getElementById('sub-badge').textContent = 'RUNNING';
  document.getElementById('sub-badge').className = 'module-badge module-badge--running';
  document.getElementById('start-sub-btn').disabled = true;
  document.getElementById('stop-sub-btn').style.display = 'flex';

  startElapsed('subElapsedTimer', 'stat-elapsed');
  termAppend('sub-terminal', `[*] Initiating subdomain enumeration for: ${domain}`);

  fetch('/api/scan/subdomains', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain }),
  })
  .then(r => r.json())
  .then(data => {
    if (data.error) { toast(data.error, true); resetSubBtn(); return; }
    state.subdomainJob = { id: data.job_id, domain, status: 'running' };
    streamJob(data.job_id, 'subdomain');
    refreshHistory();
  })
  .catch(e => { toast('Failed to start scan: ' + e.message, true); resetSubBtn(); });
}

function resetSubBtn() {
  document.getElementById('start-sub-btn').disabled = false;
  document.getElementById('stop-sub-btn').style.display = 'none';
  document.getElementById('sub-badge').textContent = 'READY';
  document.getElementById('sub-badge').className = 'module-badge';
  stopElapsed('subElapsedTimer');
}

// ─── ═══════════════════════════════════════
//     DIRECTORY SCANNER
// ═════════════════════════════════════════
let fileSource = 'scan';

function selectFileSource(src) {
  fileSource = src;
  document.getElementById('src-from-scan').classList.toggle('active', src === 'scan');
  document.getElementById('src-custom').classList.toggle('active', src === 'custom');
  document.getElementById('src-scan-panel').style.display = src === 'scan' ? 'block' : 'none';
  document.getElementById('src-custom-panel').style.display = src === 'custom' ? 'block' : 'none';
}

function startDirScan() {
  let aliveFile = '';
  let domain = document.getElementById('dir-domain-label').value.trim() || 'unknown';

  if (fileSource === 'scan') {
    if (!state.aliveFile) { toast('No subdomain scan completed yet. Run subdomain scanner first.', true); return; }
    aliveFile = state.aliveFile;
    if (!domain || domain === 'unknown') domain = state.aliveFileDomain || 'unknown';
  } else {
    aliveFile = document.getElementById('custom-alive-path').value.trim();
    if (!aliveFile) { toast('Please enter the path to alive_subdomains.txt', true); return; }
  }

  if (state.dirJob && state.dirJob.status === 'running') {
    toast('A directory scan is already running', true); return;
  }

  // Reset UI
  clearTerminal('dir-terminal');
  document.getElementById('dir-terminal-card').style.display = 'block';
  document.getElementById('dir-stats-row').style.display = 'grid';
  document.getElementById('dir-results-card').style.display = 'none';
  document.getElementById('dir-stat-scanned').textContent = '0';
  document.getElementById('dir-stat-found').textContent = '0';
  document.getElementById('dir-stat-elapsed').textContent = '0s';
  document.getElementById('dir-terminal-title').textContent = `bash — dir_search.sh`;
  document.getElementById('dir-badge').textContent = 'RUNNING';
  document.getElementById('dir-badge').className = 'module-badge module-badge--running module-badge--orange';
  document.getElementById('start-dir-btn').disabled = true;
  document.getElementById('stop-dir-btn').style.display = 'flex';

  startElapsed('dirElapsedTimer', 'dir-stat-elapsed');
  termAppend('dir-terminal', `[*] Starting directory scan using: ${aliveFile}`);

  fetch('/api/scan/directories', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ alive_file: aliveFile, domain }),
  })
  .then(r => r.json())
  .then(data => {
    if (data.error) { toast(data.error, true); resetDirBtn(); return; }
    state.dirJob = { id: data.job_id, domain, status: 'running' };
    streamJob(data.job_id, 'dirscan');
    refreshHistory();
  })
  .catch(e => { toast('Failed to start scan: ' + e.message, true); resetDirBtn(); });
}

function resetDirBtn() {
  document.getElementById('start-dir-btn').disabled = false;
  document.getElementById('stop-dir-btn').style.display = 'none';
  document.getElementById('dir-badge').textContent = 'READY';
  document.getElementById('dir-badge').className = 'module-badge module-badge--orange';
  stopElapsed('dirElapsedTimer');
}

// ─── SSE Stream ───────────────────────────────────────────
function streamJob(jobId, type) {
  const termId = type === 'subdomain' ? 'sub-terminal' : 'dir-terminal';
  const sse = new EventSource(`/api/jobs/${jobId}/stream`);
  let scannedCount = 0;
  let foundCount = 0;

  sse.onmessage = (e) => {
    const data = JSON.parse(e.data);

    if (data.error) {
      termAppend(termId, '[ERROR] ' + data.error);
      sse.close(); return;
    }

    if (data.line) {
      termAppend(termId, data.line);
      if (type === 'subdomain') {
        updateChipsFromLine(data.line);
        // Parse live counts
        const aliveMatch = data.line.match(/(\d+) alive domains/i);
        const totalMatch = data.line.match(/Total unique subdomains found: (\d+)/i);
        if (aliveMatch) document.getElementById('stat-alive').textContent = aliveMatch[1];
        if (totalMatch) document.getElementById('stat-total').textContent = totalMatch[1];
      }
      if (type === 'dirscan') {
        if (data.line.includes('[*] Auditing:')) {
          scannedCount++;
          document.getElementById('dir-stat-scanned').textContent = scannedCount;
        }
        if (data.line.includes('EXPOSED')) {
          foundCount++;
          document.getElementById('dir-stat-found').textContent = foundCount;
        }
      }
    }

    if (data.done) {
      removeCursor(termId);
      sse.close();

      if (type === 'subdomain') {
        stopElapsed('subElapsedTimer');
        state.subdomainJob.status = data.status;
        if (data.status === 'completed') {
          document.getElementById('sub-badge').textContent = 'DONE';
          document.getElementById('sub-badge').className = 'module-badge module-badge--done';
          loadSubdomainResults(data.result);
        } else {
          document.getElementById('sub-badge').textContent = data.status === 'stopped' ? 'STOPPED' : 'FAILED';
          document.getElementById('sub-badge').className = 'module-badge module-badge--failed';
          if (data.status !== 'stopped') toast('Scan failed. Check terminal output.', true);
        }
        document.getElementById('start-sub-btn').disabled = false;
        document.getElementById('stop-sub-btn').style.display = 'none';
      }

      if (type === 'dirscan') {
        stopElapsed('dirElapsedTimer');
        state.dirJob.status = data.status;
        if (data.status === 'completed') {
          document.getElementById('dir-badge').textContent = 'DONE';
          document.getElementById('dir-badge').className = 'module-badge module-badge--done';
          loadDirResults(data.result);
        } else {
          document.getElementById('dir-badge').textContent = data.status === 'stopped' ? 'STOPPED' : 'FAILED';
          document.getElementById('dir-badge').className = 'module-badge module-badge--failed';
          if (data.status !== 'stopped') toast('Scan failed. Check terminal output.', true);
        }
        document.getElementById('start-dir-btn').disabled = false;
        document.getElementById('stop-dir-btn').style.display = 'none';
      }

      refreshHistory();
    }
  };

  sse.onerror = () => {
    termAppend(termId, '[ERROR] Connection to server lost.');
    sse.close();
    if (type === 'subdomain') resetSubBtn();
    else resetDirBtn();
  };
}

// ─── Load Subdomain Results ───────────────────────────────
function loadSubdomainResults(result) {
  if (!result || !result.domain) return;

  state.aliveFile = result.alive_file;
  state.aliveFileDomain = result.domain;

  // Update alive file display in dir scanner
  const display = document.getElementById('alive-file-path-display');
  if (display) {
    display.textContent = result.alive_file || 'No alive domains file found';
    display.className = 'alive-file-path' + (result.alive_file ? '' : ' empty');
  }
  const labelEl = document.getElementById('dir-domain-label');
  if (labelEl && !labelEl.value) labelEl.value = result.domain;

  document.getElementById('stat-total').textContent = result.total_subdomains || 0;
  document.getElementById('stat-alive').textContent = result.alive_count || 0;

  fetch(`/api/results/subdomains/${encodeURIComponent(result.domain)}`)
    .then(r => r.json())
    .then(data => {
      state.subResults = { alive: data.alive || [], all: data.all_subdomains || [] };
      state.subResults._allFile = data.all_file;
      state.subResults._aliveFile = data.alive_file;

      document.getElementById('alive-count-badge').textContent = state.subResults.alive.length;
      document.getElementById('all-count-badge').textContent = state.subResults.all.length;
      document.getElementById('sub-results-card').style.display = 'block';
      renderSubTable('alive');
      toast(`✓ ${state.subResults.alive.length} alive domains found!`);
    })
    .catch(() => {
      document.getElementById('sub-results-card').style.display = 'block';
      toast('Results loaded from terminal output.');
    });
}

// ─── Sub Results Table ────────────────────────────────────
let currentSubTab = 'alive';
function showResultTab(tab) {
  currentSubTab = tab;
  document.getElementById('itab-alive').classList.toggle('active', tab === 'alive');
  document.getElementById('itab-all').classList.toggle('active', tab === 'all');
  renderSubTable(tab);
}

function renderSubTable(tab) {
  const tbody = document.getElementById('results-tbody');
  tbody.innerHTML = '';
  const list = tab === 'alive' ? state.subResults.alive : state.subResults.all;

  if (!list || list.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;color:var(--text-dim);padding:1.5rem;font-family:var(--mono);font-size:0.78rem;">No results</td></tr>`;
    return;
  }

  list.forEach((host, i) => {
    const tr = document.createElement('tr');
    const isAlive = tab === 'alive';
    const url = host.startsWith('http') ? host : `http://${host}`;
    tr.innerHTML = `
      <td class="num">${i + 1}</td>
      <td class="host"><a href="${url}" target="_blank" rel="noopener">${host}</a></td>
      <td><span class="badge ${isAlive ? 'badge-alive' : 'badge-sub'}">${isAlive ? 'ALIVE' : 'FOUND'}</span></td>
      <td><a href="${url}" target="_blank" rel="noopener" class="btn-icon-only" title="Open">↗</a></td>
    `;
    tbody.appendChild(tr);
  });
}

// ─── Download ─────────────────────────────────────────────
function downloadFile(type) {
  const path = type === 'alive' ? state.subResults._aliveFile : state.subResults._allFile;
  if (!path) { toast('File not available', true); return; }
  window.location.href = `/api/download?path=${encodeURIComponent(path)}`;
}

function downloadDirFindings() {
  if (!state.dirResults._outputFile) { toast('No findings file available', true); return; }
  window.location.href = `/api/download?path=${encodeURIComponent(state.dirResults._outputFile)}`;
}

// ─── Pass alive domains to dir scanner ───────────────────
function passToDirectoryScanner() {
  if (!state.aliveFile) { toast('No alive domains file yet', true); return; }
  switchTab('dirscan');
  selectFileSource('scan');
  toast('Alive domains loaded from subdomain scan ✓');
}

// ─── Load Dir Results ─────────────────────────────────────
function loadDirResults(result) {
  if (!result) return;
  state.dirResults = { findings: result.findings || [], _outputFile: result.output_file };

  document.getElementById('dir-stat-found').textContent = result.total_findings || 0;
  document.getElementById('dir-results-card').style.display = 'block';
  renderFindingsTable(result.findings || []);

  if (result.total_findings > 0) toast(`⚠ ${result.total_findings} exposures found!`, true);
  else toast('✓ Scan complete — no verified exposures found.');
}

function renderFindingsTable(findings) {
  const tbody = document.getElementById('findings-tbody');
  const noMsg = document.getElementById('no-findings-msg');
  tbody.innerHTML = '';

  if (!findings || findings.length === 0) {
    noMsg.style.display = 'flex';
    return;
  }
  noMsg.style.display = 'none';

  findings.forEach((url, i) => {
    const type = guessFileType(url);
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="num">${i + 1}</td>
      <td class="host"><a href="${url}" target="_blank" rel="noopener">${url}</a></td>
      <td><span class="badge badge-exposed">${type}</span></td>
      <td><a href="${url}" target="_blank" rel="noopener" class="btn-icon-only" title="Open">↗</a></td>
    `;
    tbody.appendChild(tr);
  });
}

function guessFileType(url) {
  if (url.includes('.env'))          return '.ENV';
  if (url.includes('.git'))          return '.GIT';
  if (url.includes('.svn'))          return '.SVN';
  if (url.includes('composer.json')) return 'COMPOSER';
  if (url.includes('package.json'))  return 'PACKAGE';
  if (url.includes('wp-config'))     return 'WP-CONFIG';
  if (url.includes('config.php'))    return 'CONFIG';
  return 'FILE';
}

// ─── Session History ──────────────────────────────────────
function toggleHistory() {
  document.getElementById('history-panel').classList.toggle('open');
  refreshHistory();
}

function refreshHistory() {
  fetch('/api/sessions')
    .then(r => r.json())
    .then(sessions => {
      const list = document.getElementById('history-list');
      if (!sessions.length) {
        list.innerHTML = '<div class="history-empty">No scans yet</div>';
        return;
      }
      list.innerHTML = sessions.map(s => {
        const dt = new Date(s.created_at).toLocaleString();
        const meta = s.type === 'subdomain'
          ? `Alive: ${s.result_summary?.alive_count ?? '—'}`
          : `Findings: ${s.result_summary?.total_findings ?? '—'}`;
        const statusColor = s.status === 'completed' ? 'var(--green)' : s.status === 'failed' ? 'var(--red)' : 'var(--cyan)';
        const canLoad = s.status === 'completed';
        return `<div class="history-item${canLoad ? ' history-item--clickable' : ''}" ${canLoad ? `onclick="loadHistoryItem('${s.id}','${s.type}')"` : ''}>
          <div class="history-item-top">
            <div class="history-item-type">${s.type === 'subdomain' ? '◈ SUBDOMAIN' : '◉ DIR SCAN'}</div>
            <div class="history-item-status" style="color:${statusColor}">${s.status.toUpperCase()}</div>
          </div>
          <div class="history-item-domain">${s.domain}</div>
          <div class="history-item-meta">${meta} · ${dt}</div>
          ${canLoad ? '<div class="history-item-cta">Click to view results →</div>' : ''}
        </div>`;
      }).join('');
    })
    .catch(() => {});
}

// ─── Load history item into UI ───────────────────────────
function loadHistoryItem(jobId, type) {
  toast('Loading results...');

  fetch(`/api/jobs/${jobId}/status`)
    .then(r => r.json())
    .then(job => {
      if (job.error) { toast('Could not load job: ' + job.error, true); return; }
      const result = job.result || {};

      if (type === 'subdomain') {
        switchTab('subdomain');
        // Restore state
        state.aliveFile = result.alive_file || null;
        state.aliveFileDomain = result.domain || job.domain;

        // Update alive file display in dir scanner
        const display = document.getElementById('alive-file-path-display');
        if (display && result.alive_file) {
          display.textContent = result.alive_file;
          display.className = 'alive-file-path';
        }
        const labelEl = document.getElementById('dir-domain-label');
        if (labelEl && result.domain) labelEl.value = result.domain;

        // Show stats
        document.getElementById('sub-stats-row').style.display = 'grid';
        document.getElementById('stat-total').textContent = result.total_subdomains || 0;
        document.getElementById('stat-alive').textContent = result.alive_count || 0;
        document.getElementById('stat-elapsed').textContent = '—';

        // Update badge
        document.getElementById('sub-badge').textContent = 'DONE';
        document.getElementById('sub-badge').className = 'module-badge module-badge--done';

        // Fetch and render results
        const domain = result.domain || job.domain;
        fetch(`/api/results/subdomains/${encodeURIComponent(domain)}`)
          .then(r => r.json())
          .then(data => {
            state.subResults = { alive: data.alive || [], all: data.all_subdomains || [] };
            state.subResults._allFile = data.all_file;
            state.subResults._aliveFile = data.alive_file;

            document.getElementById('alive-count-badge').textContent = state.subResults.alive.length;
            document.getElementById('all-count-badge').textContent = state.subResults.all.length;
            document.getElementById('sub-results-card').style.display = 'block';
            document.getElementById('sub-terminal-card').style.display = 'none';
            renderSubTable('alive');
            toast(`✓ Loaded: ${state.subResults.alive.length} alive domains for ${domain}`);

            // Close history panel
            document.getElementById('history-panel').classList.remove('open');
          })
          .catch(() => toast('Could not load subdomain list', true));

      } else if (type === 'dirscan') {
        switchTab('dirscan');

        const findings = result.findings || [];
        state.dirResults = { findings, _outputFile: result.output_file };

        // Show stats
        document.getElementById('dir-stats-row').style.display = 'grid';
        document.getElementById('dir-stat-found').textContent = result.total_findings || 0;
        document.getElementById('dir-stat-scanned').textContent = '—';
        document.getElementById('dir-stat-elapsed').textContent = '—';

        // Update badge
        document.getElementById('dir-badge').textContent = 'DONE';
        document.getElementById('dir-badge').className = 'module-badge module-badge--done';

        // Render findings
        document.getElementById('dir-results-card').style.display = 'block';
        document.getElementById('dir-terminal-card').style.display = 'none';
        renderFindingsTable(findings);

        const count = findings.length;
        toast(count > 0 ? `⚠ Loaded: ${count} verified exposures` : '✓ Loaded: No exposures found');

        // Close history panel
        document.getElementById('history-panel').classList.remove('open');
      }
    })
    .catch(e => toast('Failed to load results: ' + e.message, true));
}

// ─── Stop Scan ───────────────────────────────────────────
function stopScan(type) {
  const jobMap = {
    subdomain: state.subdomainJob,
    dirscan:   state.dirJob,
    commondir: state.commonJob,
  };
  const job = jobMap[type];
  if (!job || !job.id) { toast('No active scan to stop', true); return; }

  fetch(`/api/jobs/${job.id}/stop`, { method: 'POST' })
    .then(r => r.json())
    .then(data => {
      if (data.error) { toast(data.error, true); return; }
      toast('■ Scan stopped.');
      // UI reset handled by SSE done event (status=stopped)
    })
    .catch(e => toast('Stop failed: ' + e.message, true));
}

// ─── Dir Sub-Tab Switcher ─────────────────────────────────
function switchDirSubTab(tab) {
  document.getElementById('dirpanel-sensitive').style.display = tab === 'sensitive' ? 'block' : 'none';
  document.getElementById('dirpanel-common').style.display   = tab === 'common'    ? 'block' : 'none';
  document.getElementById('dsubtab-sensitive').classList.toggle('active', tab === 'sensitive');
  document.getElementById('dsubtab-common').classList.toggle('active', tab === 'common');
}

// ─── Common scan file source ──────────────────────────────
let commonFileSource = 'scan';

function selectCommonFileSource(src) {
  commonFileSource = src;
  document.getElementById('csrc-from-scan').classList.toggle('active', src === 'scan');
  document.getElementById('csrc-custom').classList.toggle('active', src === 'custom');
  document.getElementById('csrc-scan-panel').style.display  = src === 'scan'   ? 'block' : 'none';
  document.getElementById('csrc-custom-panel').style.display = src === 'custom' ? 'block' : 'none';
}

// ─── Start Common Dir Scan ────────────────────────────────
function startCommonDirScan() {
  const targetUrl = document.getElementById('common-target-url').value.trim();

  if (!targetUrl) { toast('Please enter a target URL', true); return; }
  if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
    toast('URL must start with http:// or https://', true); return;
  }
  if (state.commonJob && state.commonJob.status === 'running') {
    toast('A common directory scan is already running', true); return;
  }

  // Derive domain label from URL
  let domain = 'unknown';
  try { domain = new URL(targetUrl).hostname; } catch(e) {}

  // Reset UI
  clearTerminal('common-terminal');
  document.getElementById('common-terminal-card').style.display = 'block';
  document.getElementById('common-stats-row').style.display = 'grid';
  document.getElementById('common-results-card').style.display = 'none';
  document.getElementById('common-stat-scanned').textContent = '0';
  document.getElementById('common-stat-found').textContent = '0';
  document.getElementById('common-stat-elapsed').textContent = '0s';
  document.getElementById('common-terminal-title').textContent = `bash — common_dir_scan.sh (4750 paths)`;
  document.getElementById('dir-badge').textContent = 'RUNNING';
  document.getElementById('dir-badge').className = 'module-badge module-badge--running';
  document.getElementById('start-common-btn').disabled = true;
  document.getElementById('stop-common-btn').style.display = 'flex';

  startElapsed('commonElapsedTimer', 'common-stat-elapsed');
  termAppend('common-terminal', `[*] Target: ${targetUrl}`);
  termAppend('common-terminal', `[*] Wordlist: common.txt (4750 entries) — reporting 200 OK only`);

  fetch('/api/scan/common-dirs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: targetUrl, domain }),
  })
  .then(r => r.json())
  .then(data => {
    if (data.error) { toast(data.error, true); resetCommonBtn(); return; }
    state.commonJob = { id: data.job_id, domain, status: 'running' };
    streamCommonJob(data.job_id);
    refreshHistory();
  })
  .catch(e => { toast('Failed to start scan: ' + e.message, true); resetCommonBtn(); });
}

function resetCommonBtn() {
  document.getElementById('start-common-btn').disabled = false;
  document.getElementById('stop-common-btn').style.display = 'none';
  document.getElementById('dir-badge').textContent = 'READY';
  document.getElementById('dir-badge').className = 'module-badge module-badge--orange';
  stopElapsed('commonElapsedTimer');
}

// ─── SSE Stream for Common Dir ────────────────────────────
function streamCommonJob(jobId) {
  const sse = new EventSource(`/api/jobs/${jobId}/stream`);
  let scannedCount = 0;
  let foundCount = 0;

  sse.onmessage = (e) => {
    const data = JSON.parse(e.data);

    if (data.error) { termAppend('common-terminal', '[ERROR] ' + data.error); sse.close(); return; }

    if (data.line) {
      termAppend('common-terminal', data.line);
      if (data.line.includes('[*] Scanning:')) {
        scannedCount++;
        document.getElementById('common-stat-scanned').textContent = scannedCount;
      }
      if (data.line.includes('[FOUND]')) {
        foundCount++;
        document.getElementById('common-stat-found').textContent = foundCount;
      }
    }

    if (data.done) {
      removeCursor('common-terminal');
      sse.close();
      stopElapsed('commonElapsedTimer');
      state.commonJob.status = data.status;

      if (data.status === 'completed') {
        document.getElementById('dir-badge').textContent = 'DONE';
        document.getElementById('dir-badge').className = 'module-badge module-badge--done';
        loadCommonDirResults(data.result);
      } else {
        document.getElementById('dir-badge').textContent = data.status === 'stopped' ? 'STOPPED' : 'FAILED';
        document.getElementById('dir-badge').className = 'module-badge module-badge--failed';
        if (data.status !== 'stopped') toast('Scan failed. Check terminal output.', true);
      }
      document.getElementById('start-common-btn').disabled = false;
      document.getElementById('stop-common-btn').style.display = 'none';
      refreshHistory();
    }
  };

  sse.onerror = () => {
    termAppend('common-terminal', '[ERROR] Connection to server lost.');
    sse.close();
    resetCommonBtn();
  };
}

// ─── Load Common Dir Results ──────────────────────────────
function loadCommonDirResults(result) {
  if (!result) return;
  const findings = result.findings || [];
  state.commonResults = { findings, _outputFile: result.output_file };

  document.getElementById('common-stat-found').textContent = findings.length;
  document.getElementById('common-results-card').style.display = 'block';
  renderCommonFindingsTable(findings);

  if (findings.length > 0) toast(`📂 ${findings.length} common directories found!`);
  else toast('✓ No common directories found.');
}

function renderCommonFindingsTable(findings) {
  const tbody = document.getElementById('common-findings-tbody');
  const noMsg = document.getElementById('common-no-findings-msg');
  tbody.innerHTML = '';

  if (!findings || findings.length === 0) {
    noMsg.style.display = 'flex';
    return;
  }
  noMsg.style.display = 'none';

  findings.forEach((item, i) => {
    const url   = typeof item === 'object' ? item.url  : item;
    const code  = typeof item === 'object' ? item.code : '?';
    const badgeClass = code === '200' ? 'badge-alive'
                     : code === '403' ? 'badge-exposed'
                     : 'badge-sub';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="num">${i + 1}</td>
      <td class="host"><a href="${url}" target="_blank" rel="noopener">${url}</a></td>
      <td><span class="badge ${badgeClass}">${code}</span></td>
      <td><a href="${url}" target="_blank" rel="noopener" class="btn-icon-only" title="Open">↗</a></td>
    `;
    tbody.appendChild(tr);
  });
}

function downloadCommonFindings() {
  if (!state.commonResults || !state.commonResults._outputFile) { toast('No report available', true); return; }
  window.location.href = `/api/download?path=${encodeURIComponent(state.commonResults._outputFile)}`;
}

// ─── Init ─────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Allow Enter key in domain input
  document.getElementById('domain-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') startSubdomainScan();
  });

  // Extend state with new fields
  state.commonJob = null;
  state.commonResults = { findings: [] };
  state.commonElapsedTimer = null;

  // Ping server
  fetch('/api/sessions')
    .then(() => {
      document.getElementById('server-dot').style.background = 'var(--green)';
      document.getElementById('server-label').textContent = 'Connected';
    })
    .catch(() => {
      document.getElementById('server-dot').style.background = 'var(--red)';
      document.getElementById('server-label').textContent = 'Offline';
    });

  refreshHistory();
});

// ─── Patch: sync common alive file display when subdomain scan completes ──
const _origLoadSubResults = loadSubdomainResults;
// Override to also update common panel
window.loadSubdomainResults = function(result) {
  _origLoadSubResults(result);
  const el = document.getElementById('common-alive-file-path-display');
  if (el && result && result.alive_file) {
    el.textContent = result.alive_file;
    el.className = 'alive-file-path';
  }
  const lbl = document.getElementById('common-domain-label');
  if (lbl && result && result.domain && !lbl.value) lbl.value = result.domain;
};

// ─── Patch: history item restore for commondir type ──────
const _origLoadHistoryItem = loadHistoryItem;
window.loadHistoryItem = function(jobId, type) {
  if (type !== 'commondir') { _origLoadHistoryItem(jobId, type); return; }

  toast('Loading common dir results...');
  fetch(`/api/jobs/${jobId}/status`)
    .then(r => r.json())
    .then(job => {
      if (job.error) { toast('Could not load job', true); return; }
      switchTab('dirscan');
      switchDirSubTab('common');

      const result = job.result || {};
      const findings = result.findings || [];
      state.commonResults = { findings, _outputFile: result.output_file };

      document.getElementById('common-stats-row').style.display = 'grid';
      document.getElementById('common-stat-found').textContent = findings.length;
      document.getElementById('common-stat-scanned').textContent = '—';
      document.getElementById('common-stat-elapsed').textContent = '—';
      document.getElementById('dir-badge').textContent = 'DONE';
      document.getElementById('dir-badge').className = 'module-badge module-badge--done';
      document.getElementById('common-results-card').style.display = 'block';
      document.getElementById('common-terminal-card').style.display = 'none';
      renderCommonFindingsTable(findings);

      toast(findings.length > 0 ? `📂 Loaded: ${findings.length} paths` : '✓ No paths found');
      document.getElementById('history-panel').classList.remove('open');
    })
    .catch(e => toast('Failed: ' + e.message, true));
};

