<div align="center">

<img src="https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge&logo=go" />
<img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-0078D4?style=for-the-badge&logo=windows" />
<img src="https://img.shields.io/badge/TLS-1.3-blueviolet?style=for-the-badge" />
<img src="https://img.shields.io/badge/PQC-ML--KEM%20Ready-success?style=for-the-badge" />
<img src="https://img.shields.io/badge/CERT--In-CBOM%20Compliant-orange?style=for-the-badge" />
<img src="https://img.shields.io/badge/Hackathon-PSB%202026-crimson?style=for-the-badge" />

<br/><br/>

# ⚛ QuantumSentry

### PQC Readiness Platform for PNB

**A full-stack enterprise dashboard for Post-Quantum Cryptography (PQC) readiness assessment, asset discovery, CBOM generation, and compliance reporting — built for the PSB Cybersecurity Hackathon 2026.**

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features & Modules](#-features--modules)
- [Architecture](#-architecture)
- [Repository Structure](#-repository-structure)
- [Prerequisites](#-prerequisites)
- [Quick Start](#-quick-start)
- [Build Instructions](#-build-instructions)
- [Configuration](#-configuration)
- [Default Credentials & RBAC](#-default-credentials--rbac)
- [API Reference](#-api-reference)
- [CBOM Schema](#-cbom-schema)
- [Data Sources & Transparency](#-data-sources--transparency)
- [Troubleshooting](#-troubleshooting)
- [Roadmap](#-roadmap)
- [Changelog](#-changelog)

---

## 📝 Changelog

### v1.1.0 — 2026-03-30 · Final Hackathon Build

#### 🐛 Bug Fixes

| Fix | Root Cause | Resolution |
|---|---|---|
| **Export JSON button silently broken** | `JSON.stringify()` output embedded directly in `onclick="..."` — double-quotes broke the HTML attribute | Replaced with module-level `_cbomCache`; `exportCBOMJSON()` reads from cache |
| **CBOM modal: ~10 fields shown, 30+ empty** | Frontend read wrong JSON paths: `asset.algorithms` (should be `proto.algorithms`), `asset.source_ip` (should be `asset.network.source_ip`), `cert.not_before` (should be `cert.valid_from`), `proto.server_groups` (should be `proto.supported_groups`), etc. | All 7 field path mismatches corrected in both modal renderer and PDF generator |
| **Cipher Suite names truncated/overlapping** | Fixed `width:200px` label + JS 30-char hard slice clashed with names like `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` | Switched to two-row stacked layout (name on top, bar+count below); removed JS truncation |
| **PDF generator had same wrong field paths** | `downloadCBOMPDF()` copied same incorrect field references | Fixed in sync with modal |

#### ✨ Enhancements

| Feature | Details |
|---|---|
| **CBOM modal — all 7 Annexure A sections** | Scan Metadata · PQC Verdict + HNDL explanation · Network Endpoint · TLS Protocols (with `supported_groups` chips) · Algorithms (primitive/mode/OID per entry) · X.509 Certificate (12 fields + live expiry countdown) · Cryptographic Keys (7 fields) |
| **CBOM PDF Download** | New `📄 Download PDF` button — branded A4 PDF per asset with coloured verdict banner, 8 content sections, contextual remediation recommendations, PNB red footer + page count |
| **Certificate expiry countdown** | Valid To field shows coloured badge: 🔴 ≤30d · 🟡 ≤90d · 🟢 >90d |
| **Extended cert fields** | Added: Is CA, DNS Names (first 5), Key Usage, Extended Key Usage |

---



## 🔍 Overview

QuantumSentry is an enterprise-grade **Post-Quantum Cryptography Readiness Platform** designed to help the Punjab National Bank (PNB) assess, monitor, and remediate cryptographic vulnerabilities before the quantum computing threat materialises.

The system performs **live TLS handshake inspection** via raw packet capture (Npcap), extracts cryptographic parameters, and feeds them into a 7-module analytics dashboard. All scan data is persisted to SQLite and surfaced through aggregated compliance dashboards aligned with CERT-In's SRS Annexure A specification.

### What it does at a glance

```
Scan endpoint → Extract TLS parameters → Build CBOM → 
Compute PQC verdict → Aggregate into dashboards → Generate PDF report
```

---

## 🏛️ Features & Modules

The platform is a **Single-Page Application (SPA)** with 7 modules accessible via a PNB-branded sidebar:

### 1. 🏠 Home Dashboard
- **Enterprise KPI row** — total assets, safe/hybrid/vulnerable counts, expiring certs, high-risk
- **PQC Posture donut chart** — Elite / Standard / Legacy / Critical tier breakdown
- **CBOM Key-Length bar** — distribution of public key sizes across all scanned assets
- **IP Version breakdown** — IPv4 vs IPv6 adoption
- **Certificate Expiry timeline** — certs expiring in 30 / 90 days
- **Nameserver Records** — live PNB domain DNS data
- **Geographic Asset Distribution map** — SVG world map with animated bubbles per region (India, US, EU, APAC)
- **Recent Scans feed** — last 5 scans with live verdicts

### 2. 📦 Asset Inventory
- Full table of all scanned assets with PQC verdict, TLS version, cipher suite, key size, cert expiry
- KPI row: total assets, PQC-safe count, expiring-soon count, critical count
- Click any row to open a CBOM detail modal
- **Re-scan All** bulk action button

### 3. 🔍 Asset Discovery
- **Domains tab** — Discovered PNB subdomains (passive DNS / certificate transparency)
- **SSL tab** — SSL certificates with SHA fingerprint, validity, CA
- **IP / Subnets tab** — IP addresses with ASN, netblock, geolocation
- **Software tab** — Fingerprinted web servers and software versions
- **Network Map tab** — Interactive D3.js force-directed topology graph (PNB Hub → domain/IP nodes, coloured by PQC status)
- Global search bar + status filter buttons (New / False Positive / Confirmed)

> ⚠️ **Demo Note:** The Domains, SSL, IP, and Software tabs display representative discovery data (as would be collected by passive DNS enumeration, certificate transparency logs, and Shodan in a live deployment). The Network Map and all real-time scan data are fully live from the backend engine.

### 4. 📋 CBOM Dashboard
Aggregated Cryptographic Bill of Materials across **all** scanned assets:
- KPI row: Sites Surveyed, Active Certs, Weak Crypto instances, Distinct KEM Groups
- **Key Length Distribution** bar chart
- **Cipher Suite Usage** ranked list
- **Top Certificate Authorities** doughnut chart
- **Encryption Protocols** (TLS 1.1 / 1.2 / 1.3) doughnut chart
- **KEM Groups** ranked list

### 5. 🛡️ Posture of PQC
- **Tier classification** — all assets mapped to Elite-PQC / Standard / Legacy / Critical
- Progress bars per tier with percentage and asset count
- Full asset table with compliance grade, cert expiry, recommended action
- Improvement recommendations panel

### 6. ⭐ Cyber Rating
- **Enterprise score 0–1000** computed from weighted tier distribution
- Score tier badge: Legacy (<400), Standard (400–700), Elite-PQC (>700)
- **PQC Tier Thresholds** table with compliance criteria per tier
- **Per-Asset PQC Scores** table with individual scores

### 7. 📊 Reporting
Three report types accessible via clickable tiles:
- **Executive Summary** — generates a 2-page PDF with KPIs, posture data, recommendations, and embedded Chart.js charts
- **Scheduled Reporting** — configure frequency (daily/weekly/monthly), asset selection, sections to include, and delivery options (email, save path, download link)
- **On-Demand Reporting** — request any report type (Executive, CBOM, Posture, Cyber Rating) with format and delivery options

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                    Browser / Frontend (Vanilla JS)                   │
│   index.html   script.js   style.css                                 │
│   ├── Auth (JWT login/logout, role-based UI gating)                  │
│   ├── SPA Router (7 pages, no page reload)                           │
│   ├── Chart.js — KPI charts, donut, bar, timeline                   │
│   ├── D3.js   — Force-directed network topology graph                │
│   ├── jsPDF   — 2-page executive PDF with embedded chart images      │
│   └── SVG     — Geographic asset distribution world map              │
└──────────────────────────────┬───────────────────────────────────────┘
                               │ HTTP REST (localhost:8080)
                               │ Authorization: Bearer <JWT>
┌──────────────────────────────▼───────────────────────────────────────┐
│                     Backend API Server (Go / Gin)                    │
│   main.go      — Route registration, static file serving             │
│   auth.go      — JWT (HS256), bcrypt passwords, RBAC middleware      │
│   db.go        — SQLite schema migrations, query helpers             │
│   aggregate.go — Analytical endpoints (/stats, /cbom/summary, etc.)  │
│                                                                      │
│   SQLite DB: scans · audit_log · users                               │
└──────────────────────────────┬───────────────────────────────────────┘
                               │ subprocess (os/exec)
┌──────────────────────────────▼───────────────────────────────────────┐
│                     Scanner Engine (Go / Npcap)                      │
│   main.go      — TLS dialer + raw packet capture                     │
│   cbom/        — CERT-In Annexure A CBOM builder                     │
│     types.go        Schema types                                     │
│     algorithms.go   OID registry, algorithm/protocol parsing         │
│     builder.go      Assembles CBOM from TLS session data             │
│     input.go        CLI argument parsing                             │
│     utils.go        Scan ID generation helpers                       │
│   utility/     — Npcap interface enumeration                         │
└──────────────────────────────────────────────────────────────────────┘
```

**Data flow — single scan request:**
1. Frontend sends `GET /scan?target=host:port` with `Authorization: Bearer <token>`
2. Backend validates JWT → invokes `scanner.exe host:port` as subprocess
3. Scanner dials TLS connection + captures raw Npcap packets → prints CBOM JSON to stdout
4. Backend parses CBOM, computes PQC verdict, persists record to SQLite, logs to audit trail
5. CBOM JSON returned to frontend → rendered across Dashboard, Inventory, CBOM, Posture, Cyber Rating

---

## 📁 Repository Structure

```
QuantumSentry/
│
├── README.md                       ← You are here
├── .gitignore
│
├── scanner/                        ← TLS inspection engine (Go)
│   ├── main.go                     # Entry: TLS dial + Npcap capture + CBOM output
│   ├── cbom/
│   │   ├── types.go                # CERT-In Annexure A schema structs
│   │   ├── algorithms.go           # OID registry, cipher/KEM parsing
│   │   ├── builder.go              # Assembles CBOM from captured TLS data
│   │   ├── input.go                # CLI flag parsing (target, iface)
│   │   └── utils.go                # Scan ID, timestamp helpers
│   ├── utility/                    # Npcap interface lister helper
│   ├── go.mod
│   └── go.sum
│
├── backend/                        ← REST API server (Go / Gin)
│   ├── main.go                     # Route registration, static serving, scan handler
│   ├── auth.go                     # JWT minting/validation, bcrypt, RBAC middleware
│   ├── db.go                       # SQLite init, schema migrations, query helpers
│   ├── aggregate.go                # Analytical APIs: /stats /cbom/summary /posture /cyber-rating
│   ├── go.mod
│   ├── go.sum
│   ├── server.exe                  # Pre-built Windows binary (run as Administrator)
│   └── quantumsentry.db            # SQLite DB (auto-created on first run)
│
└── frontend/                       ← SPA dashboard (Vanilla JS)
    ├── index.html                  # App shell: login modal, sidebar nav, 7 page sections
    ├── script.js                   # SPA router, auth, data fetching, charts, maps, PDF
    └── style.css                   # PNB red/gold design system, dark cards, animations
```

---

## ⚙️ Prerequisites

| Dependency | Version | Notes |
|---|---|---|
| **Go** | 1.22+ | [golang.org/dl](https://golang.org/dl/) — needed to build from source |
| **Npcap** | Latest | [npcap.com](https://npcap.com/) — install with **WinPcap API-compatible mode** checked |
| **Administrator rights** | Required | Raw packet capture requires elevated privileges |
| **Windows** | 10 / 11 | Linux also supported (use `libpcap-dev` instead of Npcap) |
| **Modern browser** | Chrome / Edge / Firefox | Required for SVG animations and D3.js |

> **Important (Windows):** Npcap must be installed with _"Install Npcap in WinPcap API-compatible Mode"_ checked. The server and scanner must be run from an **Administrator** terminal.

---

## 🚀 Quick Start

### Option A — Use Pre-built Binaries (Fastest)

```powershell
# Run as Administrator
cd QuantumSentry\backend
.\server.exe
```

Open **http://localhost:8080** → Login: `admin` / `QuantumSentry@Admin2026`

---

### Option B — Build from Source

```powershell
# 1. Clone the repository
git clone https://github.com/yuvrajn05/QuantumSentry.git
cd QuantumSentry

# 2. Build the scanner (run as Administrator — required for Npcap)
cd scanner
go build -o scanner.exe .

# 3. Build the backend
cd ..\backend
go build -o server.exe .

# 4. Start the server (must remain in the backend\ directory)
.\server.exe
```

Open **http://localhost:8080** in your browser.

---

### Linux / macOS

```bash
# Build scanner
cd scanner && go build -o scanner .

# Build backend
cd ../backend && go build -o server .

# Run (sudo required for raw packet capture)
sudo ./server
```

---

## 💻 Running on Another System (Copy & Run)

You **can** copy the project to another Windows machine and run it — with two mandatory steps on the target machine:

### Step 1 — Copy these files/folders
```
QuantumSentry/
├── backend/
│   ├── server.exe          ← Pre-built binary (no Go needed)
│   ├── quantumsentry.db    ← Copy this too to transfer all scan history
│   └── frontend/           ← Must be next to server.exe
│       ├── index.html
│       ├── script.js
│       └── style.css
└── scanner/
    └── scanner.exe         ← Pre-built scanner binary
```

> **Minimum to copy:** `backend/server.exe` + `backend/frontend/` folder.
> The `scanner.exe` and `quantumsentry.db` are optional but recommended.

### Step 2 — Install on the target machine (mandatory)

| Required | Download | Notes |
|---|---|---|
| **Npcap** | [npcap.com/#download](https://npcap.com/#download) | ✅ Check **"WinPcap API-compatible mode"** during install |
| **Administrator terminal** | Built-in to Windows | Raw packet capture requires elevated privileges |

> **Go is NOT required** if you use the pre-built `server.exe` and `scanner.exe` binaries.

### Step 3 — Run
```powershell
# Open PowerShell as Administrator
cd path\to\backend
.\server.exe
# Open http://localhost:8080 in browser
```

### ⚠️ Common Issues on a New Machine

| Problem | Cause | Fix |
|---|---|---|
| Scans all fail with `exit status 1` | Npcap not installed | Install Npcap from npcap.com |
| Scans fail with `permission denied` | Not running as Administrator | Right-click PowerShell → "Run as Administrator" |
| Blank dashboard (no data) | Fresh `quantumsentry.db` | Copy your existing `.db` file, or run some scans |
| `server.exe` not found | Wrong directory | Must run from inside the `backend/` folder |
| Port 8080 already in use | Another app on port 8080 | Set `$env:PORT=9090` before running |

### Linux / macOS (instead of Npcap)
```bash
sudo apt install libpcap-dev   # Ubuntu/Debian
# OR
brew install libpcap           # macOS

cd scanner && go build -o scanner .
cd ../backend && go build -o server .
sudo ./server
```

---

## 🔧 Configuration

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `QS_JWT_SECRET` | `qs-pqc-secret-2026-change-in-prod` | JWT signing secret — **always set this in production** |
| `PORT` | `8080` | Server listen port |

**Set the JWT secret before deploying:**
```powershell
# Windows
$env:QS_JWT_SECRET = "your-strong-random-64-char-secret"
.\server.exe

# Linux / macOS
QS_JWT_SECRET="your-strong-random-64-char-secret" ./server
```

### Interface Selection (Windows)

If the scanner cannot auto-detect the network interface, use the interface lister:
```powershell
cd iface_lister
.\iface_lister.exe        # Lists all Npcap interfaces with their GUIDs
```

Then run a scan targeting a specific interface (advanced use — normally not required).

---

## 🔐 Default Credentials & RBAC

| Username | Password | Role | Permissions |
|---|---|---|---|
| `admin` | `QuantumSentry@Admin2026` | **Admin** | Full access: scan, bulk scan, history, audit, aggregated dashboards |
| `auditor` | `QuantumSentry@Audit2026` | **Auditor** | Read-only: history, audit trail, all dashboards (no scanning) |
| `viewer` | `QuantumSentry@View2026` | **Viewer** | Scan only: run scans, see results (no history/audit) |

> ⚠️ **Change all passwords before any public or production deployment.**

### RBAC Matrix

```
Endpoint                    admin   auditor   viewer
──────────────────────────────────────────────────────
POST /auth/login              ✓       ✓         ✓
GET  /auth/me                 ✓       ✓         ✓
GET  /scan                    ✓       ✗         ✓
POST /scan/bulk               ✓       ✗         ✓
GET  /history                 ✓       ✓         ✗
GET  /history/:id             ✓       ✓         ✗
GET  /audit                   ✓       ✓         ✗
GET  /stats                   ✓       ✓         ✗
GET  /cbom/summary            ✓       ✓         ✗
GET  /posture                 ✓       ✓         ✗
GET  /cyber-rating            ✓       ✓         ✗
```

---

## 📡 API Reference

All endpoints except `/auth/login` require:
```http
Authorization: Bearer <jwt_token>
```

### Authentication

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/auth/login` | Public | Validate credentials, returns JWT |
| `GET` | `/auth/me` | Any role | Returns username + role from JWT |

```json
// POST /auth/login
{ "username": "admin", "password": "QuantumSentry@Admin2026" }

// Response
{ "token": "eyJ...", "username": "admin", "role": "admin" }
```

### Scanning

| Method | Endpoint | Role | Description |
|---|---|---|---|
| `GET` | `/scan?target=host:port` | admin, viewer | Single TLS scan → CBOM JSON |
| `POST` | `/scan/bulk` | admin, viewer | Scan up to 20 targets (3 concurrent) |

```json
// POST /scan/bulk
{ "targets": ["google.com:443", "cloudflare.com:443", "github.com:443"] }

// Response
{
  "total": 3,
  "results": [
    { "target": "google.com:443", "status": "ok", "cbom": { ... } },
    { "target": "cloudflare.com:443", "status": "ok", "cbom": { ... } },
    { "target": "github.com:443", "status": "error", "error": "..." }
  ]
}
```

### History & Audit

| Method | Endpoint | Role | Description |
|---|---|---|---|
| `GET` | `/history` | admin, auditor | Last 50 scan summaries |
| `GET` | `/history/:id` | admin, auditor | Full CBOM for a specific scan |
| `GET` | `/audit` | admin, auditor | Last 200 audit log entries |

### Aggregation APIs (Dashboard)

| Method | Endpoint | Role | Description |
|---|---|---|---|
| `GET` | `/stats` | admin, auditor | Home dashboard KPIs |
| `GET` | `/cbom/summary` | admin, auditor | Cipher, key-length, CA, TLS version distributions |
| `GET` | `/posture` | admin, auditor | PQC tier breakdown (Elite/Standard/Legacy/Critical) |
| `GET` | `/cyber-rating` | admin, auditor | Enterprise score + per-asset scores |

---

## 📄 CBOM Schema

QuantumSentry generates a **Cryptographic Bill of Materials** fully compliant with CERT-In SRS Annexure A:

```json
{
  "scan_id": "google.com:443-1711623001",
  "timestamp": "2026-03-28T17:38:00Z",
  "generator": "QuantumSentry v1.0",
  "assets": [{
    "asset_type": "network-endpoint",
    "host": "google.com",
    "port": 443,
    "source_ip": "192.168.1.5",
    "destination_ip": "142.250.192.46",
    "sni": "google.com",
    "alpn": ["h2", "http/1.1"],

    "algorithms": [{
      "asset_type": "algorithm",
      "name": "AES-128-GCM",
      "primitive": "symmetric",
      "mode": "GCM",
      "oid": "2.16.840.1.101.3.4.1.6"
    }],

    "protocols": [{
      "asset_type": "protocol",
      "name": "TLS",
      "version": "TLS 1.3",
      "oid": "1.3.18.0.2.32.104",
      "cipher_suite": "TLS_AES_128_GCM_SHA256",
      "selected_group": "X25519MLKEM768",
      "server_groups": ["X25519MLKEM768", "x25519"]
    }],

    "certificates": [{
      "asset_type": "certificate",
      "subject": "CN=*.google.com",
      "issuer": "CN=GTS CA 1C3",
      "serial_number": "...",
      "not_before": "2026-01-01T00:00:00Z",
      "not_after": "2026-03-31T00:00:00Z",
      "signature_algorithm": "ECDSA-SHA256",
      "signature_algorithm_ref": "1.2.840.10045.4.3.2",
      "public_key_algorithm": "EC P-256",
      "public_key_bits": 256,
      "certificate_format": "X.509",
      "certificate_extension": ".cer"
    }],

    "keys": [{
      "asset_type": "key",
      "name": "Server Public Key",
      "id": "sha256:ab12cd34ef56...",
      "algorithm": "EC P-256",
      "size": 256,
      "state": "active",
      "creation_date": "2026-01-01",
      "activation_date": "2026-01-01"
    }]
  }]
}
```

### PQC Verdict Logic

| Verdict | Condition |
|---|---|
| 🟢 **Post-Quantum Safe** | KEM group contains `MLKEM` or `Kyber`; TLS 1.3 |
| 🟡 **Hybrid PQ — Partially Safe** | KEM group is `X25519MLKEM768`, `X25519Kyber768`; TLS 1.3 |
| 🔴 **Quantum Vulnerable** | No PQC KEM group; any TLS version |

---

## 🗃️ Data Sources & Transparency

| Module | Data Source | Notes |
|---|---|---|
| Asset Inventory | ✅ **100% live** — SQLite scan history | Real scans only |
| CBOM Dashboard | ✅ **100% live** — aggregated scan data | All metrics from real scans |
| Posture of PQC | ✅ **100% live** — computed from verdicts | |
| Cyber Rating | ✅ **100% live** — weighted scoring algorithm | |
| Discovery: Domains / SSL / IP / Software | ⚠️ **Representative data** | As would be collected by passive DNS, cert transparency, Shodan |
| Discovery: Network Map | ✅ **Live scan hosts** + topology | Hub topology is representative |
| Geographic Map | ⚠️ **Base counts estimated** + live scans added | `†` footnote shown in UI |

The Asset Discovery tabs display a clearly labelled **"Demo Discovery Dataset"** banner explaining the data source. All real-time scanning data feeds directly from the backend.

---

## 🛠️ Troubleshooting

### Scanner produces no output / `pcap open` error
- **Cause:** Npcap not installed, or not running as Administrator
- **Fix:** Open PowerShell as Administrator. Verify Npcap is installed with WinPcap-compatible mode enabled.

### `listen tcp :8080: bind: address already in use`
- **Cause:** Previous `server.exe` instance still running
- **Fix:** In PowerShell: `Get-Process server | Stop-Process -Force`

### `401 Unauthorized` on all API calls
- **Cause:** JWT token missing or expired (24-hour TTL)
- **Fix:** Sign out and sign back in from the UI

### Scan returns `error: exit status 1`
- **Cause:** `scanner.exe` not found at `../scanner/scanner.exe` (relative to `backend/`)
- **Fix:** Ensure you built the scanner with `go build -o scanner.exe .` inside the `scanner/` directory and run the backend server from inside `backend/`

### Interface not auto-detected (Windows)
- **Cause:** Npcap interface GUID not discoverable automatically
- **Fix:** Run `iface_lister/iface_lister.exe` to list all available interfaces; note the GUID of your active Ethernet/Wi-Fi adapter

### Charts appear empty / no data
- **Cause:** No scans in the database yet
- **Fix:** Navigate to Asset Inventory → click **Re-scan All**, or use the Quick Scan widget on the Home dashboard to scan `google.com:443`

---

## 🗺️ Roadmap

### ✅ Completed (v1.1.0)
| Item | Notes |
|---|---|
| Full CBOM modal (all 7 Annexure A sections) | All scanner JSON fields correctly mapped |
| CBOM PDF Download per asset | Branded, multi-page, with recommendations |
| Export JSON fix | Module-level cache replaces broken inline onclick |
| Cipher suite label layout | Two-row stacked — no truncation |
| Certificate expiry countdown badge | Colour-coded 30/90 day warnings |

### 🔜 Phase 1 — Production Hardening (Q2 2026)
| Priority | Item |
|---|---|
| 🔴 High | HTTPS / TLS on the server (Let's Encrypt or internal CA) |
| 🔴 High | Docker + docker-compose deployment |
| 🔴 High | SMTP delivery for scheduled PDF reports |
| 🟡 Medium | Fix N+1 query in `/cbom/summary` (pre-aggregation table) |
| 🟡 Medium | Background cron goroutine for daily auto-scans |

### 🔜 Phase 2 — Intelligence Layer (Q3 2026)
| Priority | Item |
|---|---|
| 🟡 Medium | Shodan API + Certificate Transparency passive discovery |
| 🟡 Medium | Delta alerting (notify when verdict degrades) |
| 🟡 Medium | Real-time scan progress via WebSocket |

### 🔜 Phase 3 — Enterprise Integration (Q4 2026)
| Priority | Item |
|---|---|
| 🟢 Low | PostgreSQL migration (drop-in via `database/sql`) |
| 🟢 Low | SAML/SSO (Active Directory) |
| 🟢 Low | SIEM export (Splunk/QRadar via syslog/CEF) |
| 🟢 Low | OpenAPI 3.0 documentation |

---

## 📚 References

- [NIST SP 800-208](https://csrc.nist.gov/publications/detail/sp/800-208/final) — Recommendation for Stateful Hash-Based Signature Schemes
- [NIST PQC Standards](https://csrc.nist.gov/projects/post-quantum-cryptography) — ML-KEM (CRYSTALS-Kyber), ML-DSA, SLH-DSA
- [CERT-In SRS](https://www.cert-in.org.in/) — Security Requirements Specification for CBOM
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) — The Transport Layer Security (TLS) Protocol Version 1.3
- [Npcap](https://npcap.com/) — Windows packet capture library

---

<div align="center">

**Built for the PSB Cybersecurity Hackathon 2026**

_QuantumSentry — Securing India's banking infrastructure for the post-quantum era_

[![PNB](https://img.shields.io/badge/PNB-PQC%20Ready-crimson?style=flat-square)](https://www.pnbindia.in/)
[![CERT-In](https://img.shields.io/badge/CERT--In-Annexure%20A-orange?style=flat-square)](https://www.cert-in.org.in/)
[![NIST](https://img.shields.io/badge/NIST-ML--KEM%20Aligned-blue?style=flat-square)](https://csrc.nist.gov/projects/post-quantum-cryptography)

</div>
