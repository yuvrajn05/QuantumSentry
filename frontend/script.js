async function scan() {
  const target = document.getElementById("target").value;
  const result = document.getElementById("result");
  const status = document.getElementById("status");

  if (!target) return;

  result.innerHTML = "";
  status.innerText = "⏳ Scanning...";

  try {
    const res = await fetch(`http://localhost:8080/scan?target=${target}`);
    const data = await res.json();
    console.log(data);
    if (data.error) {
      status.innerHTML = `<span class="text-red-500">${data.error}</span>`;
      return;
    }

    status.innerText = "✅ Scan complete";
    render(data);

  } catch (err) {
    status.innerHTML = `<span class="text-red-500">Request failed</span>`;
  }
}

function render(data) {
  const container = document.getElementById("result");
  container.innerHTML = "";

  data.assets.forEach((asset, index) => {
    const net = asset.network;
    const tls = asset.protocols[0];
    const cert = asset.certificates[0];

    const dnsListId = `dns-${index}`;

    const supportedGroups = tls.supported_groups.map(tag).join("");
    const oids = cert.oids.map(tagSmall).join("");
    const keyUsage = cert.key_usage.map(tagSmall).join("");

    const algorithms = tls.algorithms.map(a => `
      <div class="border p-3 rounded bg-gray-50">
        <p><b>${a.name}</b> (${a.mode})</p>
        <p class="text-sm text-gray-600">${a.security_bits} bits</p>
      </div>
    `).join("");

    container.innerHTML += `
      <div class="bg-white rounded-xl shadow p-5">

        <h2 class="text-xl font-bold mb-4">Asset ${index + 1}</h2>

        <!-- TABS -->
        <div class="flex gap-4 border-b mb-4">
            ${tabButton("Network", "network", index, true)}
            ${tabButton("TLS", "tls", index)}
            ${tabButton("Certificate", "cert", index)}
        </div>

        <!-- NETWORK -->
        <div id="network-${index}" class="tab-content">
          <p><b>Source IP:</b> ${net.source_ip}</p>
          <p><b>Destination IP:</b> ${net.destination_ip}</p>
          <p><b>SNI:</b> ${net.sni}</p>
        </div>

        <!-- TLS -->
        <div id="tls-${index}" class="tab-content hidden">
          <p><b>Version:</b> ${tls.version}</p>
          <p><b>Cipher:</b> ${tls.cipher_suite}</p>
          <p><b>Selected Group:</b> ${tls.selected_group}</p>

          <div class="mt-3">
            <b>Supported Groups:</b><br/>
            ${supportedGroups}
          </div>

          <div class="mt-3">
            <b>Algorithms:</b>
            <div class="grid grid-cols-2 gap-2 mt-2">
              ${algorithms}
            </div>
          </div>
        </div>

        <!-- CERT -->
        <div id="cert-${index}" class="tab-content hidden">
          <p><b>Subject:</b> ${cert.subject}</p>
          <p><b>Issuer:</b> ${cert.issuer}</p>
          <p><b>Serial:</b> ${cert.serial_number}</p>
          <p><b>Valid:</b> ${formatDate(cert.valid_from)} → ${formatDate(cert.valid_to)}</p>
          <p><b>Public Key:</b> ${cert.public_key_algorithm} (${cert.public_key_size})</p>
          <p><b>Is CA:</b> ${cert.is_ca}</p>

          <div class="mt-3">
            <b>Key Usage:</b><br/>
            ${keyUsage}
          </div>

          <div class="mt-3">
            <b>OIDs:</b><br/>
            ${oids}
          </div>

          <div class="mt-4">
            <b>DNS Names (${cert.dns_names.length}):</b>

            <input 
              placeholder="Search DNS..." 
              class="border p-1 mt-2 mb-2 w-full"
              oninput="filterDNS('${dnsListId}', this.value)"
            />

            <div id="${dnsListId}" class="max-h-40 overflow-auto border rounded p-2 text-sm">
              ${cert.dns_names.map(d => `<div>${d}</div>`).join("")}
            </div>
          </div>
        </div>

      </div>
    `;
  });
}

/* ---------- Helpers ---------- */

function tabButton(label, id, index, active=false) {
  return `
    <button 
      onclick="switchTab('${id}', ${index})"
      class="pb-2 ${active ? 'border-b-2 border-blue-500 font-semibold' : ''}"
      id="tab-${id}-${index}"
    >
      ${label}
    </button>
  `;
}

function switchTab(tab, index) {
  ["network", "tls", "cert"].forEach(t => {
    document.getElementById(`${t}-${index}`).classList.add("hidden");
    document.getElementById(`tab-${t}-${index}`).classList.remove("border-blue-500","font-semibold");
  });

  document.getElementById(`${tab}-${index}`).classList.remove("hidden");
  document.getElementById(`tab-${tab}-${index}`).classList.add("border-blue-500","font-semibold");
}

function tag(text) {
  return `<span class="inline-block bg-gray-200 px-2 py-1 m-1 rounded text-sm">${text}</span>`;
}

function tagSmall(text) {
  return `<span class="inline-block bg-gray-100 px-2 py-1 m-1 rounded text-xs">${text}</span>`;
}

function formatDate(d) {
  return new Date(d).toLocaleString();
}

function filterDNS(containerId, query) {
  const container = document.getElementById(containerId);
  const items = container.children;

  for (let item of items) {
    item.style.display = item.innerText.toLowerCase().includes(query.toLowerCase())
      ? "block"
      : "none";
  }
}