# QuantumSentry 🔐⚛

> **Post-Quantum Cryptography (PQC) Readiness Scanner for TLS Endpoints**

QuantumSentry helps security teams audit their TLS infrastructure against quantum computing threats. It connects to any HTTPS endpoint, captures the full TLS handshake via raw packet inspection, and generates a structured **Cryptographic Bill of Materials (CBOM)** — giving you a clear verdict on whether your encryption is quantum-safe.

![QuantumSentry Dashboard](docs/screenshot.png)

---

## 🔍 What It Does

For any `host:port` target, QuantumSentry reports:

| Category | Details |
|---|---|
| **Network** | Source IP, Destination IP, SNI, ALPN protocol |
| **TLS Session** | Protocol version, cipher suite, selected KEM group |
| **PQC Groups** | All key exchange groups from the ClientHello (including ML-KEM hybrids) |
| **Certificate** | Subject, issuer, validity, public key algo & size, key usage, OIDs, SANs |
| **PQC Verdict** | 🔴 Quantum Vulnerable / 🟡 Hybrid PQ / 🟢 Post-Quantum Safe |

---

## 🏗️ Architecture

```
QuantumSentry/
├── scanner/          ← Go CLI binary (core engine)
│   ├── main.go       ← Dual-mode scanner: pcap + TLS dial → CBOM JSON
│   └── cbom/         ← Cryptographic Bill of Materials data model
│       ├── types.go  ← ScanRun, Asset, Protocol, Certificate, Algorithm structs
│       ├── input.go  ← Flat ScanInput struct (raw scanner data)
│       ├── builder.go← Assembles structured CBOM from flat input
│       ├── algorithms.go ← Parses cipher suite string → Algorithm objects
│       └── utils.go  ← Scan ID generator
│
├── backend/          ← Go HTTP server (REST API)
│   └── main.go       ← Gin server: serves frontend + GET /scan endpoint
│
└── frontend/         ← Web dashboard (HTML + CSS + Vanilla JS)
    ├── index.html    ← App shell
    ├── style.css     ← Dark-mode design system
    └── script.js     ← PQC verdict engine + result rendering
```

### How It Works

```
Browser → GET /scan?target=google.com:443
             ↓
         Backend spawns: ./scanner/scanner.exe google.com:443
             ↓
         Scanner runs two threads simultaneously:
           [1] pcap capture → reads raw ClientHello → extracts supported groups + SNI + IPs
           [2] tls.Dial     → establishes TLS → extracts version, cipher, KEM, cert
             ↓
         Builds CBOM JSON → backend returns to browser
             ↓
         Frontend renders tabbed cards with PQC verdict badge
```

---

## 🚀 Getting Started

### Prerequisites

| Requirement | Notes |
|---|---|
| **Go 1.21+** | [golang.org/dl](https://golang.org/dl/) |
| **Npcap** (Windows) | [npcap.com](https://npcap.com) — required for packet capture |
| **libpcap** (Linux/macOS) | `sudo apt install libpcap-dev` / `brew install libpcap` |

### 1. Find Your Network Interface

On Windows, pcap uses device GUIDs instead of names like `eth0`. Run the helper:

```powershell
cd iface_lister
go run main.go
```

Note the `Name` of the interface with your active internet IP (e.g. your Wi-Fi adapter).

### 2. Set Your Interface

Edit the default in `scanner/main.go`:

```go
deviceFlag := flag.String("iface", `\Device\NPF_{YOUR-GUID-HERE}`, ...)
```

Or pass it as a flag at runtime:

```bash
./scanner.exe --iface "\Device\NPF_{YOUR-GUID}" google.com:443
```

### 3. Build

```bash
# Build scanner
cd scanner
go build -o scanner.exe .

# Build backend
cd ../backend
go build -o server.exe .
```

### 4. Run

```bash
# Start the backend server (serves frontend + API on :8080)
cd backend
./server.exe
```

Open **http://localhost:8080** in your browser.

> **Note:** On Windows, the backend must be run as **Administrator** (or by a user with Npcap permissions) for raw packet capture to work.

### 5. Scan from CLI (optional)

You can also invoke the scanner directly:

```bash
cd scanner
./scanner.exe google.com:443
```

This outputs the CBOM JSON to stdout.

---

## 📊 PQC Verdict Logic

The frontend verdict engine classifies each scan result:

| Verdict | Condition |
|---|---|
| 🟢 **Post-Quantum Safe** | PQC KEM group used AND no classical signature algorithm in cert |
| 🟡 **Hybrid PQ — Partially Safe** | Hybrid KEM (e.g. X25519MLKEM768) but classical cert signature (RSA/ECDSA) |
| 🔴 **Quantum Vulnerable** | Classical-only KEM groups and classical cert |

### Known PQC Groups

| Group | Type |
|---|---|
| `X25519MLKEM768` | Hybrid (most common — used by Google, Cloudflare) |
| `SecP256r1MLKEM768` | Hybrid |
| `SecP384r1MLKEM1024` | Hybrid |
| `MLKEM512` / `MLKEM768` / `MLKEM1024` | Pure PQ (NIST FIPS 203) |

---

## 📦 CBOM Output Format

```json
{
  "scan_id": "google.com:443-1711623001",
  "timestamp": "2026-03-28T21:00:00+05:30",
  "target": "google.com:443",
  "assets": [{
    "host": "google.com:443",
    "network": {
      "source_ip": "192.168.1.5",
      "destination_ip": "142.250.183.46",
      "sni": "google.com"
    },
    "protocols": [{
      "name": "TLS",
      "version": "TLS 1.3",
      "cipher_suite": "TLS_AES_128_GCM_SHA256",
      "selected_group": "X25519MLKEM768",
      "supported_groups": ["X25519MLKEM768", "X25519", "secp256r1"],
      "alpn": "h2",
      "algorithms": [
        { "name": "AES", "primitive": "symmetric", "mode": "GCM", "security_bits": 128 }
      ]
    }],
    "certificates": [{
      "subject": "CN=*.google.com",
      "issuer": "CN=WR2,O=Google Trust Services,C=US",
      "signature_algorithm": "SHA256-RSA",
      "public_key_algorithm": "ECDSA",
      "public_key_size": 256,
      "valid_from": "2026-03-09T08:36:15Z",
      "valid_to": "2026-06-01T08:36:14Z",
      "dns_names": ["*.google.com", "google.com", "..."],
      "key_usage": ["DigitalSignature"],
      "oids": ["2.5.29.15", "2.5.29.37", "..."]
    }]
  }]
}
```

---

## 🗺️ Roadmap

- [ ] Auto-detect network interface (no hardcoding)
- [ ] Batch scanning (multiple hosts from CSV/file)
- [ ] Scan history with SQLite persistence
- [ ] Export CBOM as downloadable JSON / PDF report
- [ ] Align with CycloneDX CBOM spec
- [ ] Docker / container deployment
- [ ] PQC migration advisor (specific remediation steps)
- [ ] Passive network listener mode

---

## 📄 License

MIT — see [LICENSE](LICENSE)

---

## 🏦 Context

Built as a prototype for **Punjab National Bank (PNB)** to assess TLS cryptographic posture ahead of the post-quantum transition mandated by NIST's PQC standardisation (FIPS 203/204/205).
