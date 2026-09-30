# DNS Tunneling Attack Incident Detection System

A cybersecurity tool that analyzes DNS traffic from PCAP files, detects patterns indicative of DNS tunneling, calculates risk scores, and stores incidents for review. Built for **educational and controlled-lab use only**.

---

## ⚠️ Controlled-Lab Safety Notice

This system is for **educational and isolated-lab use ONLY**:
- **Do NOT** run against production, college/hostel, or public networks
- **Do NOT** upload PCAPs from networks you do not own/operate
- **Do NOT** use the synthetic PCAP generator on a live network interface — it writes to a file only and never transmits
- All synthetic test data uses RFC 1918 private addresses, RFC 5737 TEST-NET-1, and the IANA `.test` reserved TLD

---

## Architecture Overview

```
dns-tunneling-detection/
├── dataset/
│   ├── normal_dns.pcapng         # Real normal DNS traffic (baseline reference)
│   ├── synthetic_dns_tunnel.pcap # Controlled synthetic tunneling traffic (generated offline)
│   ├── features_normal_dns.csv   # Pre-extracted feature CSV for normal traffic
│   ├── uploads/                  # Runtime upload directory (auto-created)
│   └── test/
│       └── generate_tunnel_pcap.py  # Offline-only synthetic PCAP generator (seed 1337)
├── backend/
│   ├── app/
│   │   ├── core/          # Configuration and shared settings
│   │   ├── parser/        # PCAP/DNS packet parsing (Phase 2A)
│   │   ├── features/      # Feature extraction, entropy, encoding & baseline (Phase 2B & 4)
│   │   ├── detection/     # Multi-category rule engine & baseline anomaly detector (Phase 2C & 4)
│   │   ├── database/      # SQLAlchemy models & session (Phase 2D)
│   │   └── api/           # FastAPI routers (Phase 2E)
│   │       └── routes/    # health, upload, incidents, analytics, processings
│   ├── data/
│   │   ├── baseline_v1.json      # Baseline statistics (from real normal traffic only)
│   │   └── dns_tunneling.db      # SQLite database (auto-created)
│   ├── tests/             # 122 unit & integration tests (106 pre-phase5 + 16 phase5)
│   ├── run_detection.py   # CLI audit runner
│   ├── run_phase5_validation.py  # Phase 5 pipeline validation script
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── pages/Dashboard.jsx
│   │   └── components/   # Header, SummaryCards, IncidentsTable, Charts, UploadWidget, etc.
│   └── package.json
└── README.md
```

---

## Tech Stack

| Layer      | Technology                              |
|------------|-----------------------------------------|
| Backend    | Python 3.13, FastAPI, Uvicorn           |
| Frontend   | React 19, Vite 8, Recharts, Lucide      |
| Database   | SQLite (dev) / PostgreSQL (prod-ready)  |
| Analysis   | Scapy, Pandas, tldextract               |
| Testing    | pytest, FastAPI TestClient, Vitest      |

---

## Quick Start

### Prerequisites

```bash
cd backend
# Windows:
..\venv\Scripts\activate
# Linux/macOS:
source ../venv/bin/activate

pip install -r requirements.txt
```

### Backend

```bash
cd backend
uvicorn app.main:app --reload --port 8000
```

- API: `http://127.0.0.1:8000`
- Swagger UI: `http://127.0.0.1:8000/docs`
- Health check: `GET /health` → `{"status": "ok"}`

### Frontend

```bash
cd frontend
npm install
npm run dev
```

- Dashboard: `http://localhost:5173`

---

## Processing a Normal PCAP (Demo 1)

```bash
# Via API (with backend running):
curl -X POST http://127.0.0.1:8000/api/upload \
  -F "file=@dataset/normal_dns.pcapng"

# Expected: {"incident_count": 0, "processing_status": "completed", ...}
```

**Or** use the CLI audit runner:

```bash
cd backend
python run_detection.py ../dataset/features_normal_dns.csv
# Expected: 100% LOW, 0 flagged incidents
```

---

## Generating the Offline Synthetic Test PCAP (Demo 2)

```bash
# From project root — SAFE: writes to file only, no packets transmitted
python dataset/test/generate_tunnel_pcap.py \
  --output dataset/synthetic_dns_tunnel.pcap
```

**Key parameters (hardcoded for reproducibility):**

| Parameter              | Value              | Why                                                  |
|------------------------|--------------------|------------------------------------------------------|
| `RANDOM_SEED`          | `1337`             | Byte-for-byte reproducibility across runs            |
| Source hosts           | `10.10.10.10-19`   | RFC 1918 — never routable on public internet         |
| Resolver               | `192.0.2.1`        | RFC 5737 TEST-NET-1 — documentation-only block       |
| Domain                 | `attacker.test`    | IANA special-use reserved TLD — never registerable   |
| Total queries          | 320                | Exceeds 300-query minimum threshold                  |
| Unique subdomains      | 80 in one burst    | Exceeds 60-unique/60s threshold by 33%               |
| TXT query fraction     | ~28–30%            | Exceeds 25% minimum                                  |
| Subdomain entropy      | >3.8 bits/char     | 93.8% of labels exceed 3.5 threshold                 |
| NXDOMAIN fraction      | ~15–17%            | Realistic C2 subdomain probing rate                  |

---

## How Detection Works

### Pipeline

```
PCAP file → DNSParser → DNSRecord stream
          → FeatureExtractor → DNSFeatures (per 60-second window)
          → DNSDetector → DetectionResult (risk_score, severity, evidence)
          → SQLite (ProcessingRecord, DNSQueryRecord, DNSFeatureWindow, Incident)
          → REST API → React Dashboard
```

### Detection Engine — 9 Rules across 4 Signal Categories

| Category           | Rules                                                  |
|--------------------|--------------------------------------------------------|
| **RANDOMNESS**     | `RULE_HIGH_ENTROPY`, `RULE_ENCODING_PATTERN`          |
| **VOLUME**         | `RULE_HIGH_FREQUENCY`, `RULE_HIGH_UNIQUE_SUBDOMAINS`  |
| **STRUCTURE**      | `RULE_HIGH_LENGTH`, `RULE_UNUSUAL_DOMAIN_COMMUNICATION` |
| **PROTOCOL_MISUSE**| `RULE_SUSPICIOUS_QUERY_TYPE`, `RULE_HIGH_NXDOMAIN`    |
| *(Phase 4)*        | `RULE_ANOMALY_DEVIATION` (statistical baseline)        |

**Anti-Double-Counting Rule** (Phase 4):
```
Category Score = max(score_r for r in Category)
Total Risk Score = min(100, sum(Category Scores))
```
Within each category, only the single highest-scoring triggered indicator contributes. Categories are then summed across four orthogonal dimensions.

### Severity Model (4-Tier)

| Severity     | Score Range | Classification          |
|:-------------|:-----------:|:------------------------|
| **LOW**      | 0–29        | Normal DNS Activity     |
| **MEDIUM**   | 30–59       | Suspicious DNS Activity |
| **HIGH**     | 60–79       | Possible DNS Tunneling  |
| **CRITICAL** | 80–100      | Possible DNS Tunneling  |

**"High-risk" in API/analytics**: incidents with severity `HIGH` or `CRITICAL` (combined count).

---

## Baseline / Anomaly Detection Logic (Phase 4)

The baseline (`backend/data/baseline_v1.json`) is computed from the real normal traffic dataset only (`dataset/features_normal_dns.csv`, 30 records).

**Algorithm**: Modified Z-score (Iglewicz & Hoaglin):
```
M_i = 0.6745 × (x_i − median(X)) / MAD
```
Flag when |M_i| ≥ 3.5 (established outlier detection threshold).

**MAD = median(|x_i − median(X)|)** — resistant to outlier leverage (CDN lookups, DKIM/SPF).

**Important**: The baseline is sourced only from real normal DNS traffic. It must never be regenerated with synthetic/suspicious data, which would silently teach the detector to treat tunneling as normal.

---

## API Endpoints

| Method | Path                    | Description                                          |
|--------|-------------------------|------------------------------------------------------|
| GET    | `/health`               | Legacy health check → `{"status": "ok"}`            |
| GET    | `/api/health`           | Health check → `{"status": "ok"}`                   |
| POST   | `/api/upload`           | Upload and analyze PCAP file                         |
| GET    | `/api/incidents`        | Paginated incidents list (filters: severity, source_ip, domain, status) |
| GET    | `/api/incidents/{id}`   | Single incident detail with deserialized evidence    |
| GET    | `/api/analytics`        | Aggregate statistics (counts, severity distribution, top domains) |
| GET    | `/api/processings`      | PCAP processing history (paginated, no path exposure)|

### Standard Error Schema (all error paths):
```json
{"error": "Bad Request", "detail": "...", "status_code": 400}
```

### Upload Constraints:
- Extensions: `.pcap`, `.pcapng` only
- Max file size: 50 MB
- Header magic bytes validated before processing

---

## Database Structure

| Table                | Purpose                                                    |
|----------------------|------------------------------------------------------------|
| `processing_records` | One row per uploaded PCAP; tracks packet/query counts      |
| `dns_query_records`  | One row per parsed DNS query (source IP, type, entropy...) |
| `dns_feature_windows`| One row per 60-second aggregated window per (IP, domain)   |
| `incidents`          | Flagged detections with JSON-serialized evidence reasons   |

Indexes: `source_ip + timestamp`, `domain`, `severity`, `incident_timestamp`, `source_ip`.
Cascading deletes: deleting a `processing_record` removes all associated rows.

---

## Testing

```bash
cd backend

# Full test suite (122 tests after Phase 5):
..\venv\Scripts\pytest.exe -v

# Phase 5 tests only:
..\venv\Scripts\pytest.exe tests/test_phase5_validation.py -v

# CLI detection audit:
python run_detection.py ../dataset/features_normal_dns.csv
```

### Test Breakdown (Phase 5 final):

| Module                         | Tests | Coverage                                                |
|-------------------------------|-------|---------------------------------------------------------|
| `test_api.py`                 | 12    | Upload, incidents, analytics, processings endpoints     |
| `test_database.py`            | 13    | Schema, persistence, cascade deletes                    |
| `test_detection.py`           | 32    | Rule logic, scoring, anti-double-counting               |
| `test_features.py`            | 11    | Entropy, char ratios, encoding detection                |
| `test_parser.py`              | 18    | PCAP parsing, malformed packets                         |
| `test_phase4_advanced_detection.py` | 20 | Modified Z-score, MAD baseline, anomaly correlation  |
| `test_phase5_validation.py`   | 16    | End-to-end normal PCAP, tunneling PCAP, API regression  |
| **Total**                     | **122** | **0 failures**                                        |

---

## Known Limitations

1. **Baseline Sample Size**: 30 records (minimum recommended: 200+). Results are valid for lab demonstration but not production calibration.
2. **False Positive Rate (measured)**: 0.00% on normal traffic at MEDIUM+ severity. 2 records scored LOW (20/100) — within normal tier.
3. **No Real PCAP Attack Traffic**: Detection validated on synthetic offline data, not real-world attack captures.
4. **Legitimate High-Entropy Services**: CDNs, DKIM/SPF, antivirus lookups naturally show high entropy. Production deployment requires whitelisting/zone profiling.
5. **Single-Client Architecture**: The FastAPI server is single-process; use Gunicorn workers for production.
6. **SQLite Only**: Production deployment should migrate to PostgreSQL using the same SQLAlchemy models.

---

## Development Phases

- **Phase 1** – FastAPI skeleton, React frontend shell ✅
- **Phase 2** – PCAP parsing, feature extraction, detection engine, DB schema, REST API ✅
- **Phase 3** – React Cyber Dashboard UI, charts, incident table & modal ✅
- **Phase 4** – Advanced Behavioral Detection, baseline anomaly correlation (MAD/Z-score), encoding analysis ✅
- **Phase 5** – Final validation, controlled attack simulation, end-to-end demo, comprehensive test suite ✅

---

## License

This project is for educational purposes only. Not for use on production networks.
