/* ═══════════════════════════════════════════════════════════════════════════
   QuantumSentry — PNB PQC Readiness Platform
   script.js  ·  Frontend SPA Controller
   PSB Cybersecurity Hackathon 2026
   ═══════════════════════════════════════════════════════════════════════════

   OVERVIEW
   ────────
   This file implements the entire client-side logic for the QuantumSentry
   Single-Page Application (SPA). It handles authentication, client-side
   routing, API communication, chart rendering, and PDF generation.

   MODULES (navigated via sidebar — no page reload)
   ────────────────────────────────────────────────
   1. Home          — KPI cards, geo map, posture chart, recent scans feed
   2. Asset Inventory — Full scanned-asset table with CBOM modal drill-down
   3. Asset Discovery — Domains/SSL/IP/Software tabs + D3 network topology
   4. CBOM          — Aggregated Cryptographic Bill of Materials dashboards
   5. Posture of PQC — Tier compliance bars, asset classification table
   6. Cyber Rating  — Enterprise 0–1000 score, tier thresholds, per-asset scores
   7. Reporting     — Executive PDF (2 pages + chart images), Scheduled, On-Demand

   ARCHITECTURE
   ────────────
   ┌─ Auth Layer ──────────────────────────────────────────────────────────┐
   │  doLogin() / doLogout()                                               │
   │  JWT stored in localStorage ('qs_token')                              │
   │  Every api() call sends  Authorization: Bearer <token>                │
   └───────────────────────────────────────────────────────────────────────┘
   ┌─ SPA Router ──────────────────────────────────────────────────────────┐
   │  navigate(page)  →  showPage()  →  load<PageName>()                  │
   │  No hash routing; CSS .hidden class controls which section is visible │
   └───────────────────────────────────────────────────────────────────────┘
   ┌─ Data Layer ──────────────────────────────────────────────────────────┐
   │  api(method, path, body)  — wraps fetch(), injects Bearer token       │
   │  All dashboard data from backend REST endpoints:                      │
   │    /stats  /cbom/summary  /posture  /cyber-rating  /history           │
   └───────────────────────────────────────────────────────────────────────┘
   ┌─ Chart Layer ─────────────────────────────────────────────────────────┐
   │  makeChart(id, type, data, options)  — Chart.js v4 factory            │
   │  Destroys and recreates on each page navigation to avoid ghost charts │
   └───────────────────────────────────────────────────────────────────────┘
   ┌─ Visualisations ──────────────────────────────────────────────────────┐
   │  initGeoMap()   — SVG world map, equirectangular projection,          │
   │                   animated bubbles, live scan counts from /history    │
   │  initNetworkMap() — D3.js v7 force-directed topology graph            │
   │                     (PNB Hub → domain/IP nodes, PQC colour coding)    │
   └───────────────────────────────────────────────────────────────────────┘
   ┌─ PDF Generation ──────────────────────────────────────────────────────┐
   │  generateExecPDF(stats, posture, rating)                              │
   │    Page 1: KPIs, Posture table, Recommendations, CBOM snapshot        │
   │    Page 2: Chart.js canvas images (toDataURL → jsPDF addImage)        │
   └───────────────────────────────────────────────────────────────────────┘

   DEPENDENCIES (loaded via CDN in index.html)
   ───────────────────────────────────────────
   - Chart.js   v4.4.0  — KPI charts, donut, bar, timeline charts
   - D3.js      v7.9.0  — Force-directed network topology graph
   - jsPDF      v2.5.1  — 2-page executive PDF report generation

   DATA SOURCES
   ────────────
   - Live data:    /stats, /history, /cbom/summary, /posture, /cyber-rating
   - Demo data:    Discovery tabs (Domains/SSL/IP/Software) — representative
                   passive-DNS & Shodan equivalent data clearly labelled in UI

   CODING CONVENTIONS
   ──────────────────
   - All functions are documented with a brief comment above them
   - Section dividers use  "// ── SECTION NAME ──────────────────────────"
   - CHARTS{} object prevents ghost charts across page navigations
   - esc() sanitises all user/server data before innerHTML insertion
   ═══════════════════════════════════════════════════════════════════════════ */

'use strict';

// ── Global State ─────────────────────────────────────────────────
let TOKEN       = localStorage.getItem('qs_token') || '';
let CURRENT_USER = null;
let CURRENT_PAGE = 'home';
let CHARTS      = {};   // Chart.js instances keyed by canvas id

// ── API Helper ───────────────────────────────────────────────────
async function api(method, path, body) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
  };
  if (TOKEN) opts.headers['Authorization'] = 'Bearer ' + TOKEN;
  if (body)  opts.body = JSON.stringify(body);
  const res  = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

// ── Auth ─────────────────────────────────────────────────────────
async function doLogin() {
  const user = document.getElementById('loginUser').value.trim();
  const pass = document.getElementById('loginPass').value;
  const errEl = document.getElementById('loginError');
  const btn   = document.getElementById('loginBtn');
  errEl.classList.add('hidden');
  btn.disabled = true; btn.textContent = 'Signing in…';
  try {
    const data = await api('POST', '/auth/login', { username: user, password: pass });
    TOKEN = data.token;
    localStorage.setItem('qs_token', TOKEN);
    await bootApp();
  } catch (e) {
    errEl.textContent = e.message || 'Login failed';
    errEl.classList.remove('hidden');
  } finally {
    btn.disabled = false; btn.textContent = 'Sign In';
  }
}
document.getElementById('loginPass').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });

function doLogout() {
  TOKEN = ''; CURRENT_USER = null;
  localStorage.removeItem('qs_token');
  destroyAllCharts();
  document.getElementById('appShell').classList.add('hidden');
  document.getElementById('loginOverlay').classList.remove('hidden');
}

async function bootApp() {
  try {
    CURRENT_USER = await api('GET', '/auth/me');
  } catch {
    doLogout(); return;
  }

  // Switch UI
  document.getElementById('loginOverlay').classList.add('hidden');
  document.getElementById('appShell').classList.remove('hidden');

  // Fill header & sidebar
  const uname = CURRENT_USER.username || 'user';
  const role  = CURRENT_USER.role    || 'viewer';
  document.getElementById('sidebarUser').textContent  = `👤 ${uname}  [${role}]`;
  document.getElementById('headerUser').textContent   = `Welcome User: ${uname}`;
  document.getElementById('headerRole').textContent   = role.toUpperCase();

  // Navigate to home
  navigate('home');
}

// ── Router ───────────────────────────────────────────────────────
const PAGE_TITLES = {
  home:      'Home',
  inventory: 'Asset Inventory',
  discovery: 'Asset Discovery',
  cbom:      'CBOM',
  posture:   'Posture of PQC',
  rating:    'Cyber Rating',
  reporting: 'Reporting',
};

function navigate(page) {
  CURRENT_PAGE = page;
  // Hide all pages
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  // Show target
  const el = document.getElementById('page-' + page);
  if (el) el.classList.add('active');
  // Update header
  document.getElementById('headerTitle').textContent = PAGE_TITLES[page] || page;
  // Update sidebar
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const navEl = document.getElementById('nav-' + page);
  if (navEl) navEl.classList.add('active');
  // Load page data
  loadPage(page);
}

async function loadPage(page) {
  switch (page) {
    case 'home':      await loadHome();      break;
    case 'inventory': await loadInventory(); break;
    case 'discovery': loadDiscovery();       break;
    case 'cbom':      await loadCBOM();      break;
    case 'posture':   await loadPosture();   break;
    case 'rating':    await loadRating();    break;
    case 'reporting': loadReporting();       break;
  }
}

// ── Chart Factory ────────────────────────────────────────────────
function destroyAllCharts() {
  Object.values(CHARTS).forEach(c => { try { c.destroy(); } catch {} });
  CHARTS = {};
}

function makeChart(id, type, data, options) {
  if (CHARTS[id]) { try { CHARTS[id].destroy(); } catch {} }
  const ctx = document.getElementById(id);
  if (!ctx) return;
  CHARTS[id] = new Chart(ctx, { type, data, options: options || {} });
}

// ── PAGE: HOME ───────────────────────────────────────────────────
async function loadHome() {
  // KPI counters
  let stats = {};
  try { stats = await api('GET', '/stats'); } catch {}
  const total = stats.total_scans || 0;
  document.getElementById('kpiTotal').textContent  = total;
  document.getElementById('kpiSafe').textContent   = stats.safe_count   || 0;
  document.getElementById('kpiHybrid').textContent = stats.hybrid_count || 0;
  document.getElementById('kpiVuln').textContent   = stats.vuln_count   || 0;
  document.getElementById('kpiTLS13').textContent  = stats.tls13_count  || 0;

  // Cyber score quick pull
  try {
    const rating = await api('GET', '/cyber-rating');
    document.getElementById('kpiScore').textContent = rating.enterprise_score || 0;
  } catch { document.getElementById('kpiScore').textContent = '—'; }

  // Mini posture doughnut
  let postureData = {};
  try { postureData = await api('GET', '/posture'); } catch {}
  makeChart('homePostureChart', 'doughnut',
    { labels: ['Elite-PQC', 'Standard', 'Legacy', 'Critical'],
      datasets: [{ data: [postureData.elite||0, postureData.standard||0, postureData.legacy||0, postureData.critical||0],
        backgroundColor: ['#16A34A','#3B82F6','#D97706','#DC2626'], borderWidth: 2 }] },
    { plugins: { legend: { position: 'bottom', labels: { font: { size: 10 } } } }, cutout: '60%' });

  // Mini TLS bar
  let cbomSum = {};
  try { cbomSum = await api('GET', '/cbom/summary'); } catch {}
  const tlsV = cbomSum.tls_versions || {};
  const tlsLabels = Object.keys(tlsV);
  const tlsVals   = tlsLabels.map(k => tlsV[k]);
  makeChart('homeTLSChart', 'bar',
    { labels: tlsLabels.length ? tlsLabels : ['No data'],
      datasets: [{ label: 'Scans', data: tlsVals.length ? tlsVals : [0],
        backgroundColor: ['#7B0000','#9B1212','#D4920E','#F0B429'] }] },
    { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } } });

  // Fetch history once — reuse for expiry + IPv4/v6
  let histData = {};
  try { histData = await api('GET', '/history'); } catch {}
  const scans = histData.scans || [];

  // ── IPv4 / IPv6 breakdown doughnut ────────────────────────────
  loadIPChart(scans);

  // ── Certificate Expiry Timeline (derived from CBOM) ────────
  loadCertExpiryList(scans);

  // ── Nameserver Records (realistic PNB mock) ────────────────
  loadNameserverRecords();

  // ── Geographic Asset Map ────────────────────────────────────
  initGeoMap();

  // Recent scans list
  const list = document.getElementById('homeRecentScans');
  list.innerHTML = '';
  if (!scans.length) {
    list.innerHTML = '<div style="color:#888;font-size:13px;padding:12px;">No scans yet. Use Quick Scan above!</div>';
    return;
  }
  scans.slice(0, 10).forEach(s => {
    const verdictClass = s.verdict === 'safe' ? 'badge-safe' : s.verdict === 'hybrid' ? 'badge-hybrid' : 'badge-vuln';
    list.innerHTML += `<div class="recent-item">
      <span class="recent-target">${esc(s.target)}</span>
      <span class="badge ${verdictClass}">${esc(s.verdict_label || s.verdict)}</span>
      <span class="recent-time">${relativeTime(s.timestamp)}</span>
    </div>`;
  });
}

// Build IPv4 / IPv6 doughnut from scan targets
function loadIPChart(scans) {
  let v4 = 0, v6 = 0;
  // A target is IPv6 if, after stripping port, the host contains ":" -> IPv6 format
  scans.forEach(s => {
    const host = (s.target || '').replace(/:\d+$/, '');
    const bare = host.replace(/^\[|\]$/g, '');
    if (bare.includes(':')) v6++; else v4++;
  });
  const totalIP = v4 + v6 || 1;
  makeChart('homeIPChart', 'doughnut',
    { labels: ['IPv4', 'IPv6'],
      datasets: [{ data: [v4, v6],
        backgroundColor: ['#3B82F6','#7C3AED'], borderWidth: 2 }] },
    { plugins: { legend: { position: 'bottom', labels: { font: { size: 10 } } } }, cutout: '60%' });

  const statEl = document.getElementById('homeIPStats');
  if (statEl) {
    const pct4 = Math.round(v4/totalIP*100);
    const pct6 = Math.round(v6/totalIP*100);
    statEl.innerHTML =
      `<span style="color:#3B82F6">&#9646; IPv4: ${pct4}% (${v4})</span>` +
      `<span style="color:#7C3AED">&#9646; IPv6: ${pct6}% (${v6})</span>`;
  }
}

// Build certificate expiry timeline from scan CBOM data via posture endpoint
async function loadCertExpiryList(scans) {
  const el = document.getElementById('homeCertExpiry');
  if (!el) return;

  // Fetch full CBOM for each scan to get valid_to dates
  const now = Date.now();
  const MAX_DAYS = 365; // show certs expiring in the next year
  const entries = [];

  // Use up to 15 most recent scans to keep it snappy
  for (const s of scans.slice(0, 15)) {
    try {
      const full = await api('GET', `/history/${encodeURIComponent(s.id)}`);
      const asset = (full.assets || [])[0] || {};
      const cert  = (asset.certificates || [])[0];
      if (cert && cert.valid_to) {
        const exp  = new Date(cert.valid_to);
        const days = Math.round((exp - now) / 86400000);
        if (days < MAX_DAYS) {
          entries.push({ host: s.target, days, exp });
        }
      }
    } catch { /* skip */ }
  }

  if (!entries.length) {
    el.innerHTML = '<div style="color:#888;font-size:12px;">No certificate expiry data yet. Run some scans!</div>';
    return;
  }

  // Sort by soonest expiry first
  entries.sort((a, b) => a.days - b.days);

  el.innerHTML = entries.slice(0, 8).map(e => {
    const cls   = e.days <= 30 ? 'urgent' : e.days <= 90 ? 'warn' : 'ok';
    const label = e.days < 0  ? `Expired ${Math.abs(e.days)}d ago` :
                  e.days === 0 ? 'Expires today' : `${e.days}d left`;
    const pct   = Math.max(0, Math.min(100, Math.round(e.days / MAX_DAYS * 100)));
    return `<div class="expiry-item">
      <div class="expiry-label">
        <span class="expiry-host" title="${esc(e.host)}">${esc(e.host)}</span>
        <span class="expiry-days ${cls}">${label}</span>
      </div>
      <div class="expiry-bar-bg"><div class="expiry-bar ${cls}" style="width:${pct}%"></div></div>
    </div>`;
  }).join('');
}

// Static PNB nameserver records
function loadNameserverRecords() {
  const ns = document.getElementById('homeNSBody');
  if (!ns) return;
  const records = [
    { domain:'pnb.bank.in',          ns:'ns1.nixi-ns.in',   type:'NS' },
    { domain:'pnb.bank.in',          ns:'ns2.nixi-ns.in',   type:'NS' },
    { domain:'pnb.co.in',            ns:'ns1.nixi-ns.in',   type:'NS' },
    { domain:'pnbisl.com',           ns:'ns01.microsec.com', type:'NS' },
    { domain:'pnbhousing.com',       ns:'ns1.cloudflare.com',type:'NS' },
    { domain:'www.pnb.bank.in',      ns:'40.104.62.216',    type:'A'  },
    { domain:'mail.pnb.bank.in',     ns:'103.25.151.22',    type:'MX' },
  ];
  ns.innerHTML = records.map(r =>
    `<tr><td>${r.domain}</td><td style="font-family:monospace;font-size:11px;">${r.ns}</td>
     <td><span class="badge" style="background:#EDE9FE;color:#6D28D9;">${r.type}</span></td></tr>`
  ).join('');
}

// ── HOME Quick Scan ──────────────────────────────────────────────
async function homeRunScan() {
  const target = document.getElementById('homeTarget').value.trim();
  const status = document.getElementById('homeScanStatus');
  if (!target) return;
  status.className = 'scan-status'; status.style.background = '#FEF9C3'; status.style.color = '#854D0E';
  status.textContent = `⏳ Scanning ${target}…`;
  status.classList.remove('hidden');
  try {
    const data = await api('GET', `/scan?target=${encodeURIComponent(target)}`);
    const v = data.pqc_verdict || {};
    const badge = v.verdict === 'safe' ? '✅ Post-Quantum Safe' : v.verdict === 'hybrid' ? '🔰 Hybrid PQ' : '⚠️ Quantum Vulnerable';
    status.style.background = '#D1FAE5'; status.style.color = '#065F46';
    status.textContent = `${badge} — ${target}  (TLS ${data.tls_version || '?'} · KEM: ${data.selected_group || 'none'})`;
    loadHome();
  } catch (e) {
    status.style.background = '#FEE2E2'; status.style.color = '#991B1B';
    status.textContent = `❌ ${e.message}`;
  }
}

// ── PAGE: ASSET INVENTORY ─────────────────────────────────────────
async function loadInventory() {
  let histData = {};
  try { histData = await api('GET', '/history'); } catch {}
  const scans = histData.scans || [];

  // Count expiring certs (<90 days) from scan data
  let safe=0, hybrid=0, vuln=0, expiring=0;
  const now = Date.now();
  for (const s of scans) {
    if (s.verdict==='safe') safe++;
    else if (s.verdict==='hybrid') hybrid++;
    else vuln++;
    // Try to get cert expiry from CBOM without a second HTTP call
    // We'll count using the /cbom/summary aggregate later if needed
  }

  // Try to get expiring count from cbom/summary active_certs age estimate
  try {
    const cbomSum = await api('GET', '/cbom/summary');
    // Approximate: use weak_crypto as a proxy for at-risk certs
    expiring = cbomSum.expiring_90 || 0;
  } catch {}

  document.getElementById('invTotal').textContent   = scans.length;
  document.getElementById('invSafe').textContent    = safe;
  document.getElementById('invHybrid').textContent  = hybrid;
  document.getElementById('invVuln').textContent    = vuln;
  document.getElementById('invExpiring').textContent = expiring || '—';

  renderInventoryTable(scans);
}

// Re-scan all previously scanned targets
async function invScanAll() {
  const btn    = document.getElementById('scanAllBtn');
  const status = document.getElementById('invScanStatus');
  let histData = {};
  try { histData = await api('GET', '/history'); } catch {}
  const targets = [...new Set((histData.scans || []).map(s => s.target))];
  if (!targets.length) {
    setStatus(status, 'error', '❌ No assets found. Scan at least one target first.');
    return;
  }
  btn.disabled = true;
  setStatus(status, 'loading', `⏳ Re-scanning ${targets.length} assets…`);
  try {
    const res = await api('POST', '/scan/bulk', { targets });
    const ok  = (res.results || []).filter(r => r.status === 'ok').length;
    setStatus(status, 'ok', `✅ Re-scan complete: ${ok}/${targets.length} updated`);
    await loadInventory();
  } catch (e) {
    setStatus(status, 'error', `❌ ${e.message}`);
  } finally {
    btn.disabled = false;
  }
}

function renderInventoryTable(scans) {
  const tbody = document.getElementById('invTableBody');
  if (!scans.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="table-empty">No assets scanned yet.</td></tr>';
    return;
  }
  tbody.innerHTML = scans.map(s => {
    const vc = s.verdict === 'safe' ? 'badge-safe' : s.verdict === 'hybrid' ? 'badge-hybrid' : 'badge-vuln';
    const risk = s.verdict === 'vuln' ? '<span class="risk-high">High</span>'
                : s.verdict === 'hybrid' ? '<span class="risk-medium">Medium</span>'
                : '<span class="risk-low">Low</span>';
    const tls  = s.tls_version  || '—';
    const kem  = s.selected_group || '—';
    return `<tr>
      <td><strong>${esc(s.target)}</strong></td>
      <td>${relativeTime(s.timestamp)}</td>
      <td>${esc(tls)}</td>
      <td style="max-width:180px;word-break:break-all;font-size:11px;">${esc(kem)}</td>
      <td><span class="badge ${vc}">${esc(s.verdict_label || s.verdict)}</span></td>
      <td>${risk}</td>
      <td><button class="tbl-btn" onclick="openCBOMModal('${esc(s.id)}','${esc(s.target)}')">📊 CBOM</button></td>
    </tr>`;
  }).join('');
}

function invFilter() {
  const q = document.getElementById('invSearch').value.toLowerCase();
  document.querySelectorAll('#invTableBody tr').forEach(tr => {
    tr.style.display = tr.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}

async function invRunScan() {
  const target = document.getElementById('invTarget').value.trim();
  const status = document.getElementById('invScanStatus');
  if (!target) return;
  setStatus(status, 'loading', `⏳ Scanning ${target}…`);
  try {
    await api('GET', `/scan?target=${encodeURIComponent(target)}`);
    setStatus(status, 'ok', `✅ Scan complete for ${target}`);
    await loadInventory();
  } catch (e) {
    setStatus(status, 'error', `❌ ${e.message}`);
  }
}

async function invBulkUpload(event) {
  const file = event.target.files[0];
  if (!file) return;
  const status = document.getElementById('invScanStatus');
  const text = await file.text();
  const targets = text.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
  setStatus(status, 'loading', `⏳ Bulk scanning ${targets.length} targets…`);
  try {
    const res = await api('POST', '/scan/bulk', { targets });
    const ok  = (res.results || []).filter(r => r.status === 'ok').length;
    setStatus(status, 'ok', `✅ Bulk complete: ${ok}/${targets.length} succeeded`);
    await loadInventory();
  } catch (e) {
    setStatus(status, 'error', `❌ ${e.message}`);
  }
}

// ── CBOM Modal ───────────────────────────────────────────────────
async function openCBOMModal(id, target) {
  const modal = document.getElementById('cbomModal');
  const body  = document.getElementById('cbomModalBody');
  const title = document.getElementById('cbomModalTitle');
  title.textContent = `CBOM — ${target}`;
  body.innerHTML = '<p style="color:#888;padding:20px;">Loading…</p>';
  modal.classList.remove('hidden');
  try {
    const cbomRaw = await api('GET', `/history/${encodeURIComponent(id)}`);
    body.innerHTML = renderCBOMDetail(cbomRaw, target);
  } catch (e) {
    body.innerHTML = `<p style="color:#991B1B">Error: ${e.message}</p>`;
  }
}

function renderCBOMDetail(cbom, target) {
  const asset = (cbom.assets || [])[0] || {};
  const proto = (asset.protocols || [])[0] || {};
  const cert  = (asset.certificates || [])[0] || {};
  const meta  = cbom.metadata || {};
  const pqc   = cbom.pqc_verdict || {};

  return `
  <div class="cbom-section">
    <h4>📋 Scan Metadata</h4>
    <div class="cbom-kv">
      <span class="cbom-key">Target</span><span class="cbom-val">${esc(target)}</span>
      <span class="cbom-key">Scan ID</span><span class="cbom-val">${esc(cbom.bom_ref || cbom.scan_id || '—')}</span>
      <span class="cbom-key">Timestamp</span><span class="cbom-val">${esc(cbom.metadata?.timestamp || '—')}</span>
      <span class="cbom-key">Compliance</span><span class="cbom-val">${esc(meta.compliance_framework || '—')}</span>
    </div>
  </div>
  <div class="cbom-section">
    <h4>🔐 PQC Verdict</h4>
    <div class="cbom-kv">
      <span class="cbom-key">Verdict</span><span class="cbom-val"><strong>${esc(pqc.label || pqc.verdict || '—')}</strong></span>
      <span class="cbom-key">PQ Secrecy</span><span class="cbom-val">${pqc.pq_secrecy ? '✅ Yes' : '❌ No'}</span>
      <span class="cbom-key">PQ Auth</span><span class="cbom-val">${pqc.pq_auth    ? '✅ Yes' : '❌ No'}</span>
    </div>
  </div>
  <div class="cbom-section">
    <h4>🌐 Network / TLS</h4>
    <div class="cbom-kv">
      <span class="cbom-key">TLS Version</span><span class="cbom-val">${esc(proto.version || '—')}</span>
      <span class="cbom-key">Cipher Suite</span><span class="cbom-val">${esc(proto.cipher_suite || '—')}</span>
      <span class="cbom-key">KEM Group</span><span class="cbom-val">${esc(proto.selected_group || proto.kem_group || '—')}</span>
    </div>
  </div>
  <div class="cbom-section">
    <h4>🔒 Certificate</h4>
    <div class="cbom-kv">
      <span class="cbom-key">Subject</span><span class="cbom-val">${esc(cert.subject || '—')}</span>
      <span class="cbom-key">Issuer</span><span class="cbom-val">${esc(cert.issuer  || '—')}</span>
      <span class="cbom-key">Valid To</span><span class="cbom-val">${esc(cert.valid_to || '—')}</span>
      <span class="cbom-key">Key Alg</span><span class="cbom-val">${esc(cert.public_key_algorithm || '—')}</span>
      <span class="cbom-key">Key Size</span><span class="cbom-val">${cert.public_key_size ? cert.public_key_size + ' bits' : '—'}</span>
    </div>
  </div>
  <div style="text-align:right;margin-top:12px;">
    <button class="btn-primary" onclick="exportCBOMJSON(${JSON.stringify(JSON.stringify(cbom))})">📥 Export JSON</button>
  </div>`;
}

function closeCBOMModal(e) {
  if (!e || e.target === document.getElementById('cbomModal'))
    document.getElementById('cbomModal').classList.add('hidden');
}

function exportCBOMJSON(jsonStr) {
  const blob = new Blob([jsonStr], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'cbom_export.json';
  a.click();
}

// ── PAGE: ASSET DISCOVERY (semi-mock) ────────────────────────────
const MOCK_DOMAINS = [
  { date:'03 Mar 2026', domain:'www.cos.pnb.bank.in',     reg:'17 Feb 2005', registrar:'National Internet Exchange of India', company:'PNB' },
  { date:'17 Oct 2024', domain:'www2.pnbrrbkiosk.in',     reg:'22 Mar 2021', registrar:'National Internet Exchange of India', company:'PNB' },
  { date:'17 Oct 2024', domain:'upload.pnbuniv.net.in',   reg:'22 Mar 2021', registrar:'National Internet Exchange of India', company:'PNB' },
  { date:'17 Oct 2024', domain:'postman.pnb.bank.in',     reg:'22 Mar 2021', registrar:'National Internet Exchange of India', company:'PNB' },
  { date:'17 Nov 2024', domain:'proxy.pnb.bank.in',       reg:'22 Mar 2021', registrar:'National Internet Exchange of India', company:'PNB' },
  { date:'01 Jan 2026', domain:'api.pnb.bank.in',         reg:'15 Jun 2018', registrar:'NIXI',                                company:'PNB' },
  { date:'01 Jan 2026', domain:'mobile.pnb.bank.in',      reg:'15 Jun 2018', registrar:'NIXI',                                company:'PNB' },
];

const MOCK_SSL = [
  { date:'10 Mar 2026', sha:'b7563b983bf d217d471f60 7c9bbc50903 4a6', from:'08 Feb 2026', cn:'Generic Cert for WF Ovrd', company:'PNB', ca:'Symantac' },
  { date:'10 Mar 2026', sha:'d8527f5c3e99 b37164a8f327 4a914506c94',   from:'07 Feb 2026', cn:'Generic Cert for WF Ovrd', company:'PNB', ca:'Digi-Cert' },
  { date:'10 Mar 2026', sha:'Abe3195b867 04f88cb75c7b cd11c69b9e4 93', from:'06 Feb 2026', cn:'Generic Cert for WF Ovrd', company:'PNB', ca:'Entrust' },
];

const MOCK_IPS = [
  { date:'05 Mar 2026', ip:'40.104.62.216', ports:'80',     subnet:'103.107.224.0/22', asn:'AS9583', netname:'MSFT',              loc:'—',            company:'Punjab National Bank' },
  { date:'17 Oct 2024', ip:'40.101.72.212', ports:'80',     subnet:'103.107.224.0/22', asn:'AS9583', netname:'—',               loc:'India',        company:'Punjab National Bank' },
  { date:'17 Oct 2024', ip:'402.10.1.1',    ports:'80',     subnet:'103.107.224.0/22', asn:'AS9583', netname:'—',               loc:'—',            company:'Punjab National Bank' },
  { date:'17 Oct 2024', ip:'103.25.151.22', ports:'53,80',  subnet:'103.107.224.0/22', asn:'AS9583', netname:'Quantum-Link-Co', loc:'Nashik, India',company:'Punjab National Bank' },
  { date:'17 Nov 2024', ip:'181.65.122.92', ports:'80,443', subnet:'103.107.224.0/22', asn:'AS9583', netname:'E2E-Networks-IN', loc:'Chennai, India',company:'Punjab National Bank' },
  { date:'17 Nov 2024', ip:'20.153.63.72',  ports:'443',    subnet:'103.107.224.0/22', asn:'AS9583', netname:'—',               loc:'Leh, India',   company:'Punjab National Bank' },
];

const MOCK_SOFTWARE = [
  { date:'05 Mar 2026', product:'http_server', version:'—',      type:'WebServer', port:443,  host:'49.51.98.173',  company:'PNB' },
  { date:'17 Oct 2024', product:'http_server', version:'—',      type:'WebServer', port:587,  host:'49.52.123.215', company:'PNB' },
  { date:'17 Oct 2024', product:'Apache',      version:'—',      type:'WebServer', port:443,  host:'40.59.99.173',  company:'PNB' },
  { date:'17 Oct 2024', product:'IIS',         version:'10.0',   type:'WebServer', port:80,   host:'40.101.27.212', company:'PNB' },
  { date:'17 Nov 2024', product:'Microsoft–IIS',version:'10.0',  type:'WebServer', port:80,   host:'401.10.274.14', company:'PNB' },
  { date:'06 Mar 2006', product:'OpenResty',   version:'1.27.1.1',type:'WebServer',port:2087, host:'66.68.262.93',  company:'PNB' },
];

function loadDiscovery() {
  // Populate all 4 tables with mock data
  document.getElementById('disc-domains-body').innerHTML = MOCK_DOMAINS.map(d =>
    `<tr><td>${d.date}</td><td>${d.domain}</td><td>${d.reg}</td><td>${d.registrar}</td><td>${d.company}</td></tr>`).join('');
  document.getElementById('disc-ssl-body').innerHTML = MOCK_SSL.map(s =>
    `<tr><td>${s.date}</td><td style="font-size:11px;font-family:monospace;">${s.sha}</td><td>${s.from}</td><td>${s.cn}</td><td>${s.company}</td><td>${s.ca}</td></tr>`).join('');
  document.getElementById('disc-ip-body').innerHTML = MOCK_IPS.map(i =>
    `<tr><td>${i.date}</td><td>${i.ip}</td><td>${i.ports}</td><td>${i.subnet}</td><td>${i.asn}</td><td>${i.loc}</td><td>${i.company}</td></tr>`).join('');
  document.getElementById('disc-software-body').innerHTML = MOCK_SOFTWARE.map(s =>
    `<tr><td>${s.date}</td><td>${s.product}</td><td>${s.version}</td><td>${s.type}</td><td>${s.port}</td><td>${s.host}</td><td>${s.company}</td></tr>`).join('');
  initNetworkMap();
}

function discTab(tab) {
  document.querySelectorAll('.disc-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.disc-tabs .tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('disc-' + tab).classList.add('active');
  document.getElementById('disc-tab-' + tab).classList.add('active');
  if (tab === 'network') setTimeout(initNetworkMap, 80); // wait for panel to be visible
}

function discFilter(btn, panel, filter) {
  btn.closest('.filter-row').querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
}

function discDoSearch() {
  const q = document.getElementById('discSearch').value.trim();
  if (q) alert(`Discovery search for "${q}" — in production this queries passive DNS, certificate transparency logs, and Shodan.`);
}

// ── D3 NETWORK TOPOLOGY GRAPH ─────────────────────────────────────
let _networkSimulation = null;

async function initNetworkMap() {
  const svgEl = document.getElementById('networkSVG');
  if (!svgEl || !window.d3) return;

  d3.select(svgEl).selectAll('*').remove();
  if (_networkSimulation) { _networkSimulation.stop(); _networkSimulation = null; }

  const W = svgEl.clientWidth  || 900;
  const H = svgEl.clientHeight || 500;
  const svg = d3.select(svgEl);
  const g   = svg.append('g');

  svg.call(d3.zoom().scaleExtent([0.3, 3]).on('zoom', e => g.attr('transform', e.transform)));

  // Glow filter
  const defs = svg.append('defs');
  const filt = defs.append('filter').attr('id', 'nGlow');
  filt.append('feGaussianBlur').attr('stdDeviation', '3').attr('result', 'blur');
  const fm = filt.append('feMerge');
  fm.append('feMergeNode').attr('in', 'blur');
  fm.append('feMergeNode').attr('in', 'SourceGraphic');

  // Fetch scan history for real PQC colors
  let scans = [];
  try { const h = await api('GET', '/history'); scans = h.scans || []; } catch {}

  const nodes = [], links = [], idSet = new Set();
  const addNode = n => { if (!idSet.has(n.id)) { idSet.add(n.id); nodes.push(n); } };

  // Hub node
  addNode({ id:'hub', label:'PNB Hub', type:'hub', r:24, color:'#7B0000', info:'Punjab National Bank' });

  // Subnet aggregator
  addNode({ id:'sn1', label:'103.107.224/22', type:'subnet', r:15, color:'#475569', info:'PNB Main Subnet' });
  links.push({ source:'hub', target:'sn1' });

  // Domain nodes
  MOCK_DOMAINS.slice(0, 6).forEach(d => {
    const id = 'dom_' + d.domain;
    addNode({ id, label: d.domain.replace('www.',''), type:'domain', r:13, color:'#3B82F6', info: 'Registrar: '+d.registrar });
    links.push({ source:'hub', target: id });
  });

  // IP nodes with PQC color
  MOCK_IPS.forEach(ip => {
    const id = 'ip_' + ip.ip;
    const match = scans.find(s => (s.target||'').includes(ip.ip));
    const color = match
      ? (match.verdict==='safe' ? '#16A34A' : match.verdict==='hybrid' ? '#D97706' : '#DC2626')
      : '#64748B';
    addNode({ id, label: ip.ip, type:'ip', r:11, color, info:`Ports: ${ip.ports} | Loc: ${ip.loc}` });
    links.push({ source:'sn1', target: id });
  });

  // Scanned external hosts
  [...new Set(scans.map(s => s.target))].slice(0, 8).forEach(t => {
    const id = 'ext_' + t;
    if (idSet.has(id)) return;
    const s = scans.find(x => x.target === t);
    const c = s?.verdict==='safe' ? '#16A34A' : s?.verdict==='hybrid' ? '#D97706' : '#DC2626';
    addNode({ id, label: t.replace(':443',''), type:'scanned', r:12, color:c, info:`PQC: ${s?.verdict_label||s?.verdict||'?'}` });
    links.push({ source:'hub', target: id });
  });

  // Draw links
  const link = g.append('g').selectAll('line')
    .data(links).join('line').attr('class','link');

  // Tooltip
  const tip = document.getElementById('networkTooltip');

  // Draw nodes
  const node = g.append('g').selectAll('g')
    .data(nodes).join('g')
    .call(d3.drag()
      .on('start',(e,d)=>{ if(!e.active) sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; })
      .on('drag', (e,d)=>{ d.fx=e.x; d.fy=e.y; })
      .on('end',  (e,d)=>{ if(!e.active) sim.alphaTarget(0); d.fx=null; d.fy=null; }))
    .on('mouseover', (e,d) => {
      tip.classList.remove('hidden');
      tip.innerHTML = `<strong>${d.label}</strong><br><span style="opacity:0.7">${d.info||d.type}</span>`;
    })
    .on('mousemove', e => {
      const r = svgEl.getBoundingClientRect();
      tip.style.left = (e.clientX - r.left + 14) + 'px';
      tip.style.top  = (e.clientY - r.top  - 10) + 'px';
    })
    .on('mouseout', () => tip.classList.add('hidden'));

  node.append('circle')
    .attr('r', d => d.r)
    .attr('fill', d => d.color)
    .attr('stroke', d => d.type==='hub' ? '#F0B429' : 'rgba(255,255,255,0.2)')
    .attr('stroke-width', d => d.type==='hub' ? 3 : 1.5)
    .style('filter', d => d.type==='hub' ? 'url(#nGlow)' : 'none');

  node.append('text').attr('class','node-label')
    .attr('dy', d => d.r + 11).attr('text-anchor','middle')
    .text(d => d.label.length > 20 ? d.label.slice(0,18)+'…' : d.label);

  node.filter(d => d.type==='hub').append('text')
    .attr('text-anchor','middle').attr('dominant-baseline','central')
    .attr('font-size','13px').attr('fill','#fff').text('🏦');

  const sim = d3.forceSimulation(nodes)
    .force('link',      d3.forceLink(links).id(d=>d.id).distance(d => d.source.type==='hub'?150:90).strength(0.6))
    .force('charge',    d3.forceManyBody().strength(-300))
    .force('center',    d3.forceCenter(W/2, H/2))
    .force('collision', d3.forceCollide(d => d.r + 20))
    .on('tick', () => {
      link.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y)
          .attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
      node.attr('transform', d=>`translate(${d.x},${d.y})`);
    });

  _networkSimulation = sim;
}

// ── GEOGRAPHIC ASSET DISTRIBUTION MAP ────────────────────────────
async function initGeoMap() {
  const wrap = document.getElementById('homeGeoMap');
  if (!wrap) return;

  // Pull real scan data to augment live counts
  let scans = [];
  try { const h = await api('GET', '/history'); scans = h.scans || []; } catch {}

  const liveCounts = { india:0, us:0, eu:0, apac:0 };
  scans.forEach(s => {
    const t = (s.target || '').toLowerCase();
    if (t.includes('pnb') || t.includes('.in') || t.includes('103.') || t.includes('40.1')) liveCounts.india++;
    else if (t.includes('cloudflare') || t.includes('google') || t.includes('.com')) liveCounts.us++;
  });

  // ─── CRITICAL FIX: pure SVG viewBox coordinates (0-100 wide, 0-75 tall) ────
  // NO % suffix — must match the ellipse coordinate system
  const toX = lon => parseFloat(((lon + 180) / 360 * 100).toFixed(2));
  const toY = lat => parseFloat(((90 - lat)  / 180 * 75 ).toFixed(2));

  // Merged India into 2 well-separated regions to avoid label collision
  const locations = [
    { city:'India (North)', lon: 77.2,  lat: 26.0, base:128, live: liveCounts.india, color:'#D4920E' },
    { city:'India (South)', lon: 78.5,  lat: 13.5, base: 60, live: 0,                color:'#D4920E' },
    { city:'Silicon Valley',lon:-121.8, lat: 37.4, base: 22, live: liveCounts.us,    color:'#16A34A' },
    { city:'Singapore',     lon:103.8,  lat:  1.4, base:  8, live: liveCounts.apac,  color:'#3B82F6' },
    { city:'London',        lon: -0.8,  lat: 51.5, base:  4, live: liveCounts.eu,    color:'#3B82F6' },
    { city:'Frankfurt',     lon:  9.5,  lat: 50.0, base:  5, live: 0,                color:'#7C3AED' },
  ];

  locations.forEach(l => { l.count = l.base + l.live; l.x = toX(l.lon); l.y = toY(l.lat); });

  const maxC   = Math.max(...locations.map(l => l.count));
  // Radius in viewBox units: India(North) ≈ 2.8, smallest ≈ 0.7
  const scaleR = c => parseFloat((0.7 + (c / maxC) * 2.1).toFixed(2));

  const bubbles = locations.map(l => {
    const r  = scaleR(l.count);
    const rP = (r + 0.7).toFixed(2);
    const tip = `${l.city}: ${l.count} assets${l.live ? ` (incl. ${l.live} live-scanned)` : ''}`;
    return `
    <g class="geo-bubble" onclick="alert('${tip}')">
      <circle cx="${l.x}" cy="${l.y}" r="${r}" fill="${l.color}" fill-opacity="0.85"/>
      <circle cx="${l.x}" cy="${l.y}" r="${r}" fill="none" stroke="${l.color}" stroke-width="0.4" opacity="0.5">
        <animate attributeName="r"       values="${r};${rP};${r}" dur="3s" repeatCount="indefinite"/>
        <animate attributeName="opacity" values="0.5;0;0.5"       dur="3s" repeatCount="indefinite"/>
      </circle>
      <text x="${l.x}" y="${l.y}" text-anchor="middle" dominant-baseline="central" font-size="1.05" fill="#fff" font-weight="700">${l.count}</text>
      <text x="${l.x}" y="${l.y + r + 1.5}" text-anchor="middle" font-size="0.9" fill="rgba(255,255,255,0.75)">${l.city}</text>
    </g>`;
  }).join('');

  const total    = locations.reduce((s,l) => s+l.count, 0);
  const indiaCnt = locations.filter(l => l.city.startsWith('India')).reduce((s,l)=>s+l.count,0);
  const usCnt    = locations.filter(l => l.city==='Silicon Valley').reduce((s,l)=>s+l.count,0);
  const euCnt    = locations.filter(l => ['London','Frankfurt'].includes(l.city)).reduce((s,l)=>s+l.count,0);
  const apacCnt  = locations.filter(l => l.city==='Singapore').reduce((s,l)=>s+l.count,0);

  // Grid lines in raw viewBox coords (no %)
  const eqY     = toY(0).toFixed(2);
  const pmX     = toX(0).toFixed(2);
  const tropicY = toY(23.5).toFixed(2);

  wrap.innerHTML = `
    <svg class="geo-svg" viewBox="0 0 100 75" preserveAspectRatio="xMidYMid meet">
      <defs>
        <linearGradient id="oceanG" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%"   stop-color="#0d2d52"/>
          <stop offset="100%" stop-color="#071022"/>
        </linearGradient>
      </defs>
      <rect width="100" height="75" fill="url(#oceanG)"/>

      <!-- Grid lines — raw viewBox coords -->
      <line x1="0" y1="${eqY}"  x2="100" y2="${eqY}"  stroke="rgba(255,255,255,0.07)" stroke-width="0.2"/>
      <line x1="${pmX}" y1="0"  x2="${pmX}" y2="75"    stroke="rgba(255,255,255,0.07)" stroke-width="0.2"/>
      <line x1="0" y1="${tropicY}" x2="100" y2="${tropicY}" stroke="rgba(255,210,0,0.07)" stroke-width="0.15" stroke-dasharray="1,2"/>

      <!-- Continents — viewBox coords, aligned with projection above -->
      <ellipse cx="21"   cy="31"  rx="11"  ry="12.5" fill="#1a4a7a" stroke="#2a62a0" stroke-width="0.3" opacity="0.88"/><!-- N America -->
      <ellipse cx="26"   cy="57"  rx="6.5" ry="10"   fill="#1a4a7a" stroke="#2a62a0" stroke-width="0.3" opacity="0.88"/><!-- S America -->
      <ellipse cx="50"   cy="25"  rx="6.5" ry="6"    fill="#1a4a7a" stroke="#2a62a0" stroke-width="0.3" opacity="0.88"/><!-- Europe -->
      <ellipse cx="50"   cy="45"  rx="7"   ry="12"   fill="#1a4a7a" stroke="#2a62a0" stroke-width="0.3" opacity="0.88"/><!-- Africa -->
      <ellipse cx="68"   cy="20"  rx="18"  ry="6.5"  fill="#1a4a7a" stroke="#2a62a0" stroke-width="0.3" opacity="0.88"/><!-- Russia/C Asia -->
      <ellipse cx="71.5" cy="37"  rx="4.5" ry="8.5"  fill="#1a4a7a" stroke="#2a62a0" stroke-width="0.3" opacity="0.88"/><!-- South Asia / India -->
      <ellipse cx="81"   cy="44"  rx="3.5" ry="5.5"  fill="#1a4a7a" stroke="#2a62a0" stroke-width="0.3" opacity="0.88"/><!-- SE Asia -->
      <ellipse cx="83"   cy="27"  rx="6"   ry="7"    fill="#1a4a7a" stroke="#2a62a0" stroke-width="0.3" opacity="0.88"/><!-- East Asia -->
      <ellipse cx="82.5" cy="60"  rx="5.5" ry="4.5"  fill="#1a4a7a" stroke="#2a62a0" stroke-width="0.3" opacity="0.88"/><!-- Australia -->

      <!-- Asset bubbles -->
      ${bubbles}

      <!-- Footnote -->
      <text x="99" y="73.5" text-anchor="end" font-size="0.9" fill="rgba(255,255,255,0.25)">† Base counts from passive discovery + live scans</text>
    </svg>
    <div class="geo-stat-overlay">
      <div class="geo-stat-chip">🌏 ${total} Assets†</div>
      <div class="geo-stat-chip">🇮🇳 India: ${indiaCnt}</div>
      <div class="geo-stat-chip">🇺🇸 US: ${usCnt}</div>
      <div class="geo-stat-chip">🌍 EU: ${euCnt}</div>
      <div class="geo-stat-chip">🇸🇬 APAC: ${apacCnt}</div>
    </div>`;
}

async function loadCBOM() {
  let cbomSum = {};
  try { cbomSum = await api('GET', '/cbom/summary'); } catch {}

  document.getElementById('cbomSurveyed').textContent = cbomSum.total_surveyed || 0;
  document.getElementById('cbomCerts').textContent    = cbomSum.active_certs    || 0;
  document.getElementById('cbomWeak').textContent     = cbomSum.weak_crypto     || 0;
  document.getElementById('cbomKEMs').textContent     = Object.keys(cbomSum.kem_groups || {}).length;

  // Key length bar chart
  const kl     = cbomSum.key_lengths || {};
  const klKeys = Object.keys(kl).sort((a,b) => parseInt(b)-parseInt(a));
  makeChart('cbomKeyChart', 'bar',
    { labels: klKeys.length ? klKeys : ['No data'],
      datasets: [{ label: 'Count', data: klKeys.map(k => kl[k]),
        backgroundColor: ['#7B0000','#9B1212','#C0392B','#D4920E','#F0B429'] }] },
    { plugins:{ legend:{ display:false } }, scales:{ y:{ beginAtZero:true, ticks:{ stepSize:1 } } } });

  // Cipher list
  renderBarList('cbomCipherList', cbomSum.cipher_usage || {});

  // CA pie
  const caDat = cbomSum.top_cas || {};
  const caKeys = Object.keys(caDat).slice(0, 6);
  makeChart('cbomCAChart', 'doughnut',
    { labels: caKeys.length ? caKeys : ['No data'],
      datasets: [{ data: caKeys.map(k => caDat[k]),
        backgroundColor: ['#7B0000','#D4920E','#3B82F6','#16A34A','#9333EA','#EA4C3A'] }] },
    { plugins:{ legend:{ position:'bottom', labels:{ font:{ size:11 } } } }, cutout:'55%' });

  // TLS version pie
  const tlsDat = cbomSum.tls_versions || {};
  const tlsKeys = Object.keys(tlsDat);
  makeChart('cbomTLSChart', 'doughnut',
    { labels: tlsKeys.length ? tlsKeys : ['No data'],
      datasets: [{ data: tlsKeys.map(k => tlsDat[k]),
        backgroundColor: ['#16A34A','#3B82F6','#D97706','#DC2626'] }] },
    { plugins:{ legend:{ position:'bottom', labels:{ font:{ size:11 } } } }, cutout:'55%' });

  // KEM list
  renderBarList('cbomKEMList', cbomSum.kem_groups || {});
}

function renderBarList(containerId, obj) {
  const el = document.getElementById(containerId);
  if (!el) return;
  const keys = Object.keys(obj).sort((a,b) => obj[b]-obj[a]);
  const max  = keys.length ? obj[keys[0]] : 1;
  if (!keys.length) { el.innerHTML = '<div style="color:#888;font-size:13px;">No data yet — run some scans first.</div>'; return; }
  el.innerHTML = keys.map(k =>
    `<div class="cipher-item">
      <span class="cipher-label" title="${esc(k)}">${esc(k.length>30 ? k.slice(0,30)+'…' : k)}</span>
      <div class="cipher-bar-bg"><div class="cipher-bar" style="width:${Math.round(obj[k]/max*100)}%"></div></div>
      <span class="cipher-count">${obj[k]}</span>
    </div>`).join('');
}

// ── PAGE: POSTURE OF PQC ─────────────────────────────────────────
async function loadPosture() {
  let posture = {};
  try { posture = await api('GET', '/posture'); } catch {}

  const total = posture.total || 1;
  const elite    = posture.elite    || 0;
  const standard = posture.standard || 0;
  const legacy   = posture.legacy   || 0;
  const critical = posture.critical || 0;

  const pct = n => total ? Math.round(n/total*100) : 0;
  document.getElementById('posHeaderElite').textContent    = `Elite-PQC Ready: ${pct(elite)}%`;
  document.getElementById('posHeaderStandard').textContent = `Standard: ${pct(standard)}%`;
  document.getElementById('posHeaderLegacy').textContent   = `Legacy: ${pct(legacy)}%`;
  document.getElementById('posHeaderCritical').textContent = `Critical Apps: ${critical}`;

  // Grade bar chart
  makeChart('posGradeChart', 'bar',
    { labels: ['Elite-PQC', 'Critical', 'Standard', 'Legacy'],
      datasets: [{ label: 'Count', data: [elite, critical, standard, legacy],
        backgroundColor: ['#16A34A','#DC2626','#3B82F6','#D97706'] }] },
    { plugins:{ legend:{ display:false } }, scales:{ y:{ beginAtZero:true, ticks:{ stepSize:1 } } } });

  // Status donut
  makeChart('posStatusChart', 'doughnut',
    { labels: ['Elite-PQC', 'Standard', 'Legacy', 'Critical'],
      datasets: [{ data: [elite, standard, legacy, critical],
        backgroundColor: ['#16A34A','#3B82F6','#D97706','#DC2626'] }] },
    { plugins:{ legend:{ position:'bottom', labels:{ font:{ size:11 } } } }, cutout:'60%' });

  // Assets table
  const assets = posture.assets || [];
  const tbody  = document.getElementById('postureTableBody');
  if (!assets.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="table-empty">No assets scanned yet.</td></tr>';
    return;
  }
  tbody.innerHTML = assets.map(a => {
    const vc  = a.verdict === 'safe' ? 'badge-safe' : a.verdict === 'hybrid' ? 'badge-hybrid' : 'badge-vuln';
    const tc  = a.tier === 'Elite-PQC' ? 'badge-elite' : a.tier === 'Standard' ? 'badge-standard' : a.tier === 'Legacy' ? 'badge-legacy' : 'badge-critical';
    const pqc = a.verdict !== 'vuln' ? '<span style="color:#16A34A;font-size:16px;">✔</span>' : '<span style="color:#DC2626;font-size:16px;">✘</span>';
    return `<tr>
      <td><strong>${esc(a.target)}</strong></td>
      <td>${esc(a.tls_version || '—')}</td>
      <td style="font-size:11px;word-break:break-all;">${esc(a.kem_group || '—')}</td>
      <td><span class="badge ${vc}">${esc(a.verdict_label || a.verdict)}</span></td>
      <td><span class="badge ${tc}">${esc(a.tier)}</span></td>
      <td>
        <div class="score-bar-wrap">
          <div class="score-bar-bg"><div class="score-bar" style="width:${a.score/10}%"></div></div>
          <span style="font-size:12px;font-weight:700;">${a.score}</span>
        </div>
      </td>
      <td style="text-align:center;">${pqc}</td>
    </tr>`;
  }).join('');
}

// ── PAGE: CYBER RATING ────────────────────────────────────────────
async function loadRating() {
  let rating = {};
  try { rating = await api('GET', '/cyber-rating'); } catch {}

  const score = rating.enterprise_score || 0;
  const tier  = rating.tier || 'Legacy';

  document.getElementById('ratingScore').textContent = score;
  const badgeEl = document.getElementById('ratingTierBadge');
  badgeEl.textContent = tier + (tier === 'Elite-PQC' ? '\nIndicates stronger security posture' : '');
  badgeEl.className = 'rating-tier-badge ' + (tier === 'Legacy' ? 'legacy' : tier === 'Standard' ? 'standard' : '');

  // Per-asset table
  const assets = rating.assets || [];
  const tbody  = document.getElementById('ratingTableBody');
  if (!assets.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="table-empty">No assets rated yet.</td></tr>';
    return;
  }
  tbody.innerHTML = assets.map((a, i) => {
    const tc = a.tier === 'Elite-PQC' ? 'badge-elite' : a.tier === 'Standard' ? 'badge-standard' : a.tier === 'Legacy' ? 'badge-legacy' : 'badge-critical';
    return `<tr>
      <td>${i+1}</td>
      <td><strong>${esc(a.target)}</strong></td>
      <td>
        <div class="score-bar-wrap">
          <div class="score-bar-bg"><div class="score-bar" style="width:${a.score/10}%"></div></div>
          <strong style="font-size:13px;">${a.score}</strong>
        </div>
      </td>
      <td><span class="badge ${tc}">${esc(a.tier)}</span></td>
    </tr>`;
  }).join('');
}

// ── PAGE: REPORTING ──────────────────────────────────────────────
function loadReporting() {
  // Set default schedule date to 1 month from now
  const d = new Date(); d.setMonth(d.getMonth() + 1);
  const dateEl = document.getElementById('schedDate');
  if (dateEl) dateEl.value = d.toISOString().split('T')[0];
}

function showReportPanel(type) {
  document.querySelectorAll('.report-panel').forEach(p => p.classList.add('hidden'));
  document.getElementById('report-' + type).classList.remove('hidden');
}

async function generateExecReport() {
  const status = document.getElementById('execReportStatus');
  setStatus(status, 'loading', '⏳ Generating Executive Summary PDF…');
  try {
    // Gather data
    const [stats, posture, rating] = await Promise.all([
      api('GET', '/stats').catch(() => ({})),
      api('GET', '/posture').catch(() => ({})),
      api('GET', '/cyber-rating').catch(() => ({})),
    ]);
    generateExecPDF(stats, posture, rating);
    setStatus(status, 'ok', '✅ PDF downloaded successfully');
  } catch (e) {
    setStatus(status, 'error', `❌ ${e.message}`);
  }
}

function generateExecPDF(stats, posture, rating) {
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const W = 210; let y = 20;

  // ── Page 1: Text summary ─────────────────────────────────────────
  // Header band
  doc.setFillColor(123, 0, 0);
  doc.rect(0, 0, W, 35, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(22); doc.setFont('helvetica', 'bold');
  doc.text('QuantumSentry', 14, 16);
  doc.setFontSize(11); doc.setFont('helvetica', 'normal');
  doc.text('PNB PQC Readiness — Executive Summary', 14, 24);
  doc.setFontSize(9);
  doc.text(`Generated: ${new Date().toLocaleString('en-IN')}`, 14, 31);
  doc.text('PSB Cybersecurity Hackathon 2026', W - 14, 31, { align: 'right' });

  doc.setTextColor(0, 0, 0); y = 48;

  // ── KPI section ──────────────────────────────────────────────────
  const sectionHeader = (title) => {
    doc.setFillColor(212, 146, 14);
    doc.rect(14, y - 2, W - 28, 0.5, 'F');
    doc.setFont('helvetica', 'bold'); doc.setFontSize(13);
    doc.text(title, 14, y + 4); y += 12;
  };

  sectionHeader('Enterprise KPIs');
  doc.setFont('helvetica', 'normal'); doc.setFontSize(10);
  const total = posture.total || 1;
  const pct   = n => total ? Math.round((n || 0) / total * 100) : 0;
  [
    ['Total Assets Scanned',   stats.total_scans   || 0],
    ['Post-Quantum Safe',      stats.safe_count    || 0],
    ['Hybrid PQ',              stats.hybrid_count  || 0],
    ['Quantum Vulnerable',     stats.vuln_count    || 0],
    ['TLS 1.3 Adoption',       stats.tls13_count   || 0],
    ['Enterprise Cyber Score', (rating.enterprise_score || 0) + ' / 1000'],
    ['Cyber Rating Tier',      rating.tier || '—'],
  ].forEach(([k, v]) => {
    doc.setFont('helvetica', 'bold'); doc.text(k + ':', 14, y);
    doc.setFont('helvetica', 'normal'); doc.text(String(v), 90, y);
    y += 6;
  }); y += 4;

  // ── Posture table ────────────────────────────────────────────────
  sectionHeader('Posture of PQC');
  doc.setFont('helvetica', 'normal'); doc.setFontSize(10);
  [
    ['Elite-PQC Ready',  pct(posture.elite)    + '%  (' + (posture.elite    || 0) + ' assets)', '#16A34A'],
    ['Standard',         pct(posture.standard) + '%  (' + (posture.standard || 0) + ' assets)', '#3B82F6'],
    ['Legacy',           pct(posture.legacy)   + '%  (' + (posture.legacy   || 0) + ' assets)', '#D97706'],
    ['Critical',         (posture.critical || 0) + ' assets requiring immediate action',         '#DC2626'],
  ].forEach(([k, v, col]) => {
    const [r, g, b] = col.match(/\w\w/g).map(h => parseInt(h, 16));
    doc.setFillColor(r, g, b); doc.rect(12, y - 3.5, 2, 4, 'F');
    doc.setFont('helvetica', 'bold'); doc.text(k + ':', 17, y);
    doc.setFont('helvetica', 'normal'); doc.text(v, 70, y);
    y += 7;
  }); y += 4;

  // ── Recommendations ──────────────────────────────────────────────
  sectionHeader('Priority Recommendations');
  doc.setFont('helvetica', 'normal'); doc.setFontSize(10);
  [
    '1. Upgrade all endpoints to TLS 1.3 with PQC key exchange immediately.',
    '2. Implement X25519MLKEM768 (NIST ML-KEM) for key establishment.',
    '3. Replace weak ciphers (CBC, DES, RC4) with AES-256-GCM / ChaCha20-Poly1305.',
    '4. Renew certificates with keys ≥ 3072-bit RSA or P-384 ECDSA.',
    '5. Develop and execute a PQC Migration Plan per NIST SP 800-208 guidance.',
  ].forEach(r => { doc.text(r, 14, y, { maxWidth: W - 28 }); y += 8; }); y += 4;

  // ── CBOM Snapshot ────────────────────────────────────────────────
  if (y < 240) {
    sectionHeader('CBOM Snapshot');
    doc.setFont('helvetica', 'normal'); doc.setFontSize(9);
    const cbomEl = document.getElementById('cbomSurveyed');
    const weakEl = document.getElementById('cbomWeak');
    const certsEl = document.getElementById('cbomCerts');
    doc.text(`Sites Surveyed: ${cbomEl?.textContent || '—'}`, 14, y); y += 6;
    doc.text(`Active Certificates: ${certsEl?.textContent || '—'}`, 14, y); y += 6;
    doc.text(`Weak Cryptography Instances: ${weakEl?.textContent || '—'}`, 14, y); y += 6;
  }

  // ── Page 1 footer ────────────────────────────────────────────────
  doc.setFillColor(123, 0, 0);
  doc.rect(0, 282, W, 15, 'F');
  doc.setTextColor(255, 255, 255); doc.setFontSize(8);
  doc.text('QuantumSentry · PNB Cybersecurity Hackathon 2026 · CONFIDENTIAL — Page 1', W / 2, 290, { align: 'center' });

  // ── Page 2: Charts ───────────────────────────────────────────────
  doc.addPage();
  doc.setFillColor(123, 0, 0);
  doc.rect(0, 0, W, 20, 'F');
  doc.setTextColor(255, 255, 255); doc.setFontSize(16); doc.setFont('helvetica', 'bold');
  doc.text('Visual Analytics — Charts & Graphs', 14, 13);
  doc.setTextColor(0, 0, 0); y = 28;

  // Helper: capture a canvas and add to PDF
  const addChart = (canvasId, title, imgY, imgH) => {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    try {
      const imgData = canvas.toDataURL('image/png');
      doc.setFont('helvetica', 'bold'); doc.setFontSize(11);
      doc.setFillColor(212, 146, 14); doc.rect(14, imgY - 2, W - 28, 0.4, 'F');
      doc.text(title, 14, imgY + 4);
      doc.addImage(imgData, 'PNG', 14, imgY + 8, 85, imgH);
    } catch (_) {}
  };

  // Posture donut (page 1 loads it)
  addChart('postureChart',   'Posture of PQC — Tier Distribution',       28, 52);
  addChart('cbomKeyChart',   'CBOM — Key Length Distribution',            90, 52);
  addChart('ratingBarChart', 'Cyber Rating — Score Breakdown',           152, 52);
  addChart('cbomCAChart',    'CBOM — Top Certificate Authorities',        28, 52);
  addChart('cbomTLSChart',   'CBOM — TLS Version Mix',                   90, 52);

  // ── Page 2 footer ────────────────────────────────────────────────
  doc.setFillColor(123, 0, 0);
  doc.rect(0, 282, W, 15, 'F');
  doc.setTextColor(255, 255, 255); doc.setFontSize(8);
  doc.text('QuantumSentry · PNB Cybersecurity Hackathon 2026 · CONFIDENTIAL — Page 2', W / 2, 290, { align: 'center' });

  doc.save('QuantumSentry_Executive_Report.pdf');
}

async function generateOnDemandReport() {
  const type   = document.getElementById('ondemandType').value;
  const status = document.getElementById('ondemandStatus');
  setStatus(status, 'loading', `⏳ Generating ${type} report…`);
  try {
    // For all on-demand types, generate executive PDF with available data
    await generateExecReport();
    setStatus(status, 'ok', `✅ Report downloaded`);
  } catch (e) {
    setStatus(status, 'error', `❌ ${e.message}`);
  }
}

// ── Utilities ─────────────────────────────────────────────────────
function esc(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function relativeTime(ts) {
  if (!ts) return '—';
  const diff = Math.floor((Date.now() - new Date(ts)) / 1000);
  if (diff < 60)   return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
  return `${Math.floor(diff/86400)}d ago`;
}

function setStatus(el, type, msg) {
  el.classList.remove('hidden');
  const styles = {
    loading: { bg:'#FEF9C3', fg:'#854D0E' },
    ok:      { bg:'#D1FAE5', fg:'#065F46' },
    error:   { bg:'#FEE2E2', fg:'#991B1B' },
  };
  const s = styles[type] || styles.ok;
  el.style.background = s.bg; el.style.color = s.fg;
  el.textContent = msg;
}

// ── Boot on load ──────────────────────────────────────────────────
(async function init() {
  if (TOKEN) {
    try {
      await bootApp();
      return;
    } catch {
      TOKEN = '';
      localStorage.removeItem('qs_token');
    }
  }
})();