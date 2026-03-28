/* ──────────────────────────────────────────────────────────────
   QuantumSentry — Dashboard Script
   PQC verdict engine + tabbed result cards
────────────────────────────────────────────────────────────── */

const PQ_GROUPS = [
  'MLKEM512', 'MLKEM768', 'MLKEM1024',
  'X25519MLKEM768', 'SecP256r1MLKEM768', 'SecP384r1MLKEM1024',
];
const HYBRID_GROUPS = [
  'X25519MLKEM768', 'SecP256r1MLKEM768', 'SecP384r1MLKEM1024',
];
const PQ_SIG_ALGOS  = ['ML-DSA', 'SLH-DSA', 'Falcon', 'Dilithium'];
const VULN_KEY_ALGOS = ['RSA', 'ECDSA', 'ECDH', 'DSA', 'Ed25519', 'Ed448'];

/* ── PQC Verdict ─────────────────────────────────────────────── */
function computeVerdict(tls, cert) {
  const selected  = tls.selected_group  || '';
  const supported = tls.supported_groups || [];
  const sigAlgo   = cert.signature_algorithm || '';
  const pubKeyAlgo = cert.public_key_algorithm || '';

  const isPurePQ   = PQ_GROUPS.filter(g => !HYBRID_GROUPS.includes(g)).some(g =>
    selected === g || supported.includes(g));
  const isHybrid   = HYBRID_GROUPS.some(g => selected === g || supported.includes(g));
  const hasPQSig   = PQ_SIG_ALGOS.some(a => sigAlgo.includes(a));
  const hasVulnSig = VULN_KEY_ALGOS.some(a =>
    pubKeyAlgo.toUpperCase().includes(a.toUpperCase()) || sigAlgo.toUpperCase().includes(a.toUpperCase()));

  if ((isPurePQ || isHybrid) && !hasVulnSig) {
    return { cls: 'safe',   icon: '🟢', label: 'Post-Quantum Safe' };
  }
  if (isHybrid && hasVulnSig) {
    return { cls: 'hybrid', icon: '🟡', label: 'Hybrid PQ — Partially Safe' };
  }
  if (isPurePQ && hasVulnSig) {
    return { cls: 'hybrid', icon: '🟡', label: 'Hybrid PQ — Cert Vulnerable' };
  }
  return { cls: 'vuln', icon: '🔴', label: 'Quantum Vulnerable' };
}

/* ── Classify a group tag ────────────────────────────────────── */
function groupClass(g) {
  if (PQ_GROUPS.filter(x => !HYBRID_GROUPS.includes(x)).includes(g)) return 'pq';
  if (HYBRID_GROUPS.includes(g)) return 'hybrid';
  return 'classic';
}

/* ── Helpers ─────────────────────────────────────────────────── */
function fmt(d) {
  if (!d) return '—';
  return new Date(d).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
}
function val(v)   { return v || '<span style="color:var(--muted)">—</span>'; }
function mono(v)  { return `<span class="info-value highlight">${val(v)}</span>`; }

let activeTabState = {};

function switchTab(cardId, tab) {
  activeTabState[cardId] = tab;
  ['network','tls','cert'].forEach(t => {
    document.getElementById(`${t}-${cardId}`).classList.remove('active');
    document.getElementById(`tab-${t}-${cardId}`).classList.remove('active');
  });
  document.getElementById(`${tab}-${cardId}`).classList.add('active');
  document.getElementById(`tab-${tab}-${cardId}`).classList.add('active');
}

function filterDNS(id, q) {
  const list = document.getElementById(id);
  for (const item of list.children) {
    item.style.display = item.textContent.toLowerCase().includes(q.toLowerCase()) ? '' : 'none';
  }
}

/* ── Quick scan shortcut ─────────────────────────────────────── */
function quickScan(target) {
  document.getElementById('target').value = target;
  scan();
}

/* ── Set scanning state ─────────────────────────────────────── */
function setScanning(yes) {
  const btn    = document.getElementById('scanBtn');
  const text   = document.getElementById('btnText');
  const loader = document.getElementById('btnLoader');
  btn.disabled = yes;
  text.classList.toggle('hidden', yes);
  loader.classList.toggle('hidden', !yes);
}

function setStatus(msg, type) {
  const el = document.getElementById('status');
  el.className = `status-bar ${type}`;
  el.classList.remove('hidden');
  el.innerHTML = msg;
}

/* ── Main scan function ──────────────────────────────────────── */
async function scan() {
  const target = document.getElementById('target').value.trim();
  if (!target) return;

  document.getElementById('result').innerHTML = '';
  setScanning(true);
  setStatus('⏳ &nbsp;Scanning <b>' + target + '</b>…', 'scanning');

  try {
    const res  = await fetch(`http://localhost:8080/scan?target=${encodeURIComponent(target)}`);
    const data = await res.json();

    if (data.error) {
      setStatus(`❌ &nbsp;${data.error}`, 'error');
      setScanning(false);
      return;
    }

    setStatus(`✅ &nbsp;Scan complete — <b>${(data.assets || []).length}</b> asset(s) found`, 'success');
    render(data);
  } catch (err) {
    console.error(err);
    setStatus(`❌ &nbsp;Request failed: ${err.message}`, 'error');
  } finally {
    setScanning(false);
  }
}

/* ── Render results ──────────────────────────────────────────── */
function render(data) {
  const container = document.getElementById('result');
  container.innerHTML = '';

  (data.assets || []).forEach((asset, idx) => {
    const net  = asset.network       || {};
    const tls  = (asset.protocols    || [])[0] || {};
    const cert = (asset.certificates || [])[0] || {};
    const id   = `asset-${idx}`;

    const verdict = computeVerdict(tls, cert);

    /* ── Supported Groups ── */
    const groupTags = (tls.supported_groups || []).map(g =>
      `<span class="tag ${groupClass(g)}">${g}</span>`
    ).join('') || '<span class="tag classic">none captured</span>';

    /* ── Algorithms ── */
    const algoCards = (tls.algorithms || []).map(a => `
      <div class="algo-card">
        <div class="algo-name">${a.name}</div>
        <div class="algo-mode">${a.mode ? a.mode + ' mode' : a.primitive}</div>
        <div class="algo-bits">${a.security_bits ? a.security_bits + ' bits' : ''}</div>
      </div>`).join('') || '<span style="color:var(--muted);font-size:.85rem">No algorithms parsed</span>';

    /* ── OIDs ── */
    const oidPills = (cert.oids || []).map(o =>
      `<span class="oid-pill">${o}</span>`).join('');

    /* ── DNS list ── */
    const dnsList = (cert.dns_names || []).map(d =>
      `<div class="dns-item">${d}</div>`).join('');

    /* ── KEM group classification ── */
    const selectedGroupClass = groupClass(tls.selected_group || '');
    const selectedGroupColor =
      selectedGroupClass === 'pq'     ? 'safe'  :
      selectedGroupClass === 'hybrid' ? 'hybrid': 'vuln';

    container.innerHTML += `
    <div class="asset-card">

      <!-- Header -->
      <div class="card-header">
        <div>
          <div class="card-title">Asset ${idx + 1}</div>
          <div class="card-host">${asset.host || data.target || '—'}</div>
        </div>
        <div class="verdict ${verdict.cls}">
          <span class="verdict-dot"></span>
          ${verdict.icon} ${verdict.label}
        </div>
      </div>

      <!-- Tabs -->
      <div class="tabs">
        <button class="tab-btn active" id="tab-network-${id}" onclick="switchTab('${id}','network')">🌐 Network</button>
        <button class="tab-btn"        id="tab-tls-${id}"     onclick="switchTab('${id}','tls')">🔐 TLS</button>
        <button class="tab-btn"        id="tab-cert-${id}"    onclick="switchTab('${id}','cert')">📜 Certificate</button>
      </div>

      <!-- NETWORK panel -->
      <div class="tab-panel active" id="network-${id}">
        <div class="info-grid">
          <div class="info-item"><div class="info-label">Source IP</div><div class="info-value">${val(net.source_ip)}</div></div>
          <div class="info-item"><div class="info-label">Destination IP</div><div class="info-value">${val(net.destination_ip)}</div></div>
          <div class="info-item"><div class="info-label">SNI</div><div class="info-value highlight">${val(net.sni)}</div></div>
          <div class="info-item"><div class="info-label">ALPN</div><div class="info-value">${val(tls.alpn)}</div></div>
        </div>
      </div>

      <!-- TLS panel -->
      <div class="tab-panel" id="tls-${id}">
        <div class="info-grid">
          <div class="info-item"><div class="info-label">TLS Version</div><div class="info-value highlight">${val(tls.version)}</div></div>
          <div class="info-item"><div class="info-label">Cipher Suite</div><div class="info-value" style="font-size:.8rem">${val(tls.cipher_suite)}</div></div>
          <div class="info-item" style="grid-column:1/-1">
            <div class="info-label">Selected Key Exchange Group (KEM)</div>
            <div class="info-value ${selectedGroupColor}">${val(tls.selected_group)}</div>
          </div>
        </div>

        <div class="section-label">Supported Groups (advertised in ClientHello)</div>
        <div class="tags">${groupTags}</div>

        <div class="section-label">Algorithms in Cipher Suite</div>
        <div class="algo-grid">${algoCards}</div>
      </div>

      <!-- CERT panel -->
      <div class="tab-panel" id="cert-${id}">
        <div class="info-grid">
          <div class="info-item" style="grid-column:1/-1">
            <div class="info-label">Subject</div>
            <div class="info-value highlight">${val(cert.subject)}</div>
          </div>
          <div class="info-item" style="grid-column:1/-1">
            <div class="info-label">Issuer</div>
            <div class="info-value">${val(cert.issuer)}</div>
          </div>
          <div class="info-item"><div class="info-label">Public Key</div><div class="info-value">${val(cert.public_key_algorithm)} (${cert.public_key_size || '?'} bits)</div></div>
          <div class="info-item"><div class="info-label">Signature Algorithm</div><div class="info-value">${val(cert.signature_algorithm)}</div></div>
          <div class="info-item"><div class="info-label">Valid From</div><div class="info-value">${fmt(cert.valid_from)}</div></div>
          <div class="info-item"><div class="info-label">Valid To</div><div class="info-value">${fmt(cert.valid_to)}</div></div>
          <div class="info-item"><div class="info-label">Serial Number</div><div class="info-value" style="font-size:.75rem">${val(cert.serial_number)}</div></div>
          <div class="info-item"><div class="info-label">Is CA</div><div class="info-value">${cert.is_ca ? '✅ Yes' : '— No'}</div></div>
        </div>

        <div class="section-label">Key Usage</div>
        <div class="tags">${(cert.key_usage || []).map(k => `<span class="tag">${k}</span>`).join('') || '—'}</div>

        <div class="section-label">Extension OIDs</div>
        <div class="tags">${oidPills || '—'}</div>

        <div class="divider"></div>

        <div class="section-label">DNS Names (${(cert.dns_names || []).length})</div>
        <input class="dns-search" placeholder="Search DNS names…" oninput="filterDNS('dns-${id}', this.value)" />
        <div class="dns-list" id="dns-${id}">${dnsList}</div>
      </div>

    </div>`;
  });
}

/* ── Enter key support ───────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('target').addEventListener('keydown', e => {
    if (e.key === 'Enter') scan();
  });
});