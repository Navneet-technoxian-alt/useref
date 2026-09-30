# DNS Tunneling Detection System — Demo Guide

**Phase 5 Validated Checkpoint | Seed: 1337 | Date: 2026-09-30**

> ⚠️ **Controlled Lab Only.** All demos use RFC 1918/5737 reserved addresses and the IANA `.test` TLD. Do not run on public networks.

---

## Pre-Demo Setup

```bash
# Terminal 1 — Start Backend
cd backend
..\venv\Scripts\activate        # Windows
uvicorn app.main:app --reload --port 8000

# Terminal 2 — Start Frontend
cd frontend
npm run dev
# Dashboard: http://localhost:5173
```

Wait for both servers to be ready. Verify: `http://127.0.0.1:8000/health` returns `{"status": "ok"}`.

**Generate synthetic PCAP if not already present:**
```bash
python dataset/test/generate_tunnel_pcap.py --output dataset/synthetic_dns_tunnel.pcap
# Seed: 1337 | No packets transmitted | Safe offline generation
```

---

## DEMO 1 — Normal DNS Traffic: Zero Incidents

**Goal**: Show the pipeline correctly classifies real normal DNS traffic as benign (0 incidents, all LOW severity).

### Step 1: Upload via Dashboard

1. Open `http://localhost:5173`
2. Click **"Upload PCAP File"** / drag-and-drop area
3. Select `dataset/normal_dns.pcapng`
4. Click **Upload**

### Step 2: Observe Results

**Upload response** (API):
```json
{
  "processing_id": 1,
  "filename": "normal_dns.pcapng",
  "packet_count": 1550,
  "dns_packet_count": 60,
  "query_count": 30,
  "incident_count": 0,
  "processing_status": "completed"
}
```

**Dashboard state after upload:**
- Total Incidents: **0**
- High-Risk Incidents: **0**
- Affected Hosts: **0**
- Severity Distribution: **30 LOW, 0 MEDIUM, 0 HIGH, 0 CRITICAL**
- Top Suspicious Domains: **empty**

### Step 3: Verify via CLI (optional)
```bash
cd backend
python run_detection.py ../dataset/features_normal_dns.csv
```
Expected output: `100.0% LOW | 0 flagged | Zero rules triggered (except 1 ENCODING_PATTERN hit, score 20, stays in LOW)`

### What This Demonstrates
- False positive rate: **0.00%** on standard DNS traffic
- The baseline (MAD-based modified Z-score) correctly characterizes real traffic as normal
- 1 ENCODING_PATTERN flag scored 20 — correctly clamped within LOW tier (score < 30)
- Parser handled 1,550 packets cleanly in ~118 seconds

---

## DEMO 2 — Synthetic DNS Tunneling: Detected End-to-End

**Goal**: Show the complete pipeline detecting suspicious activity in controlled synthetic tunnel traffic, from PCAP upload through database persistence to dashboard visualization.

### Traffic Profile (seed 1337, offline-generated)
- **Source:** `10.10.10.10-19` (RFC 1918 private range)
- **Resolver:** `192.0.2.1` (RFC 5737 TEST-NET-1)
- **Domain:** `attacker.test` (IANA reserved)
- **320 queries** | 80 unique high-entropy subdomains | ~28% TXT | ~17% NXDOMAIN

### Step 1: Upload via Dashboard

1. Open `http://localhost:5173`
2. Upload `dataset/synthetic_dns_tunnel.pcap`
3. Click **Upload**

### Step 2: Observe Detection Results

**Upload response:**
```json
{
  "processing_id": 2,
  "filename": "synthetic_dns_tunnel.pcap",
  "packet_count": 640,
  "dns_packet_count": 640,
  "query_count": 320,
  "incident_count": 256,
  "processing_status": "completed"
}
```

**Dashboard state after upload:**
- Total Incidents: **256**
- High-Risk Incidents: **163** (HIGH: 127 + CRITICAL: 36)
- Affected Hosts: **10** (10.10.10.10 through 10.10.10.19)
- Severity Distribution:
  - CRITICAL: 36 (11.2%)
  - HIGH: 127 (39.7%)
  - MEDIUM: 93 (29.1%)
  - LOW: 64 (20.0%)
- Top Suspicious Domains: **attacker.test** (256 incidents, max risk score ~85)

### Step 3: Verify Triggered Rules

Rules fired across 320 records:

| Rule                            | Hits | Signal Category  |
|---------------------------------|------|------------------|
| `RULE_HIGH_UNIQUE_SUBDOMAINS`   | 280  | VOLUME           |
| `RULE_ENCODING_PATTERN`         | 212  | RANDOMNESS       |
| `RULE_HIGH_ENTROPY`             | 196  | RANDOMNESS       |
| `RULE_HIGH_FREQUENCY`           | 180  | VOLUME           |
| `RULE_HIGH_LENGTH`              | 116  | STRUCTURE        |
| `RULE_UNUSUAL_DOMAIN_COMMUNICATION` | 95 | STRUCTURE     |
| `RULE_SUSPICIOUS_QUERY_TYPE`    | 90   | PROTOCOL_MISUSE  |

All 4 signal categories triggered → robust multi-dimensional detection, not a single-indicator alert.

### Step 4: Verify via API

```bash
# Check incident count
curl http://127.0.0.1:8000/api/incidents
# {"total": 256, "items": [...], "page": 1, ...}

# Check analytics
curl http://127.0.0.1:8000/api/analytics
# {"total_incidents": 256, "high_risk_incidents": 163, ...}

# Check processing record
curl http://127.0.0.1:8000/api/processings
# Shows processing_id=2, query_count=320, status=completed
```

---

## DEMO 3 — Incident Deep Dive: Explainability Walkthrough

**Goal**: Open a single incident and walk through every piece of evidence across all four signal categories.

### Step 1: Open the Incidents Table

In the dashboard, click **"Incidents"** or scroll to the Incidents table. Filter by severity **"HIGH"** or **"CRITICAL"**.

### Step 2: Open Incident Detail

Click any CRITICAL incident (e.g., Incident #1). The detail modal shows:

**Example Incident:**
```
Domain:     attacker.test
Source IP:  10.10.10.12
Timestamp:  [burst window start + offset]
Query Type: TXT
Risk Score: 60 → HIGH
Status:     NEW
```

### Step 3: Walk Through Evidence by Signal Category

#### STRUCTURE (RULE_HIGH_LENGTH — score 15)
```
"Query or subdomain length is unusually high
 (query_len=51, subdomain_len=37, longest_label=37)"
```
→ Baseline normal max query_length was 33. A 51-char query is 54% above baseline max. The 37-char subdomain label approaches the 40-char threshold for data chunking.

#### RANDOMNESS (RULE_HIGH_ENTROPY — score 25)
```
"Subdomain Shannon entropy is exceptionally high
 (entropy=4.59, length=37, hex_ratio=0.27)"
```
→ Normal baseline subdomain entropy: median 0.0, max 3.35. An entropy of 4.59 bits/char is far above natural language patterns — consistent with encrypted or compressed binary data encoded as a DNS label.

#### PROTOCOL_MISUSE (RULE_SUSPICIOUS_QUERY_TYPE — score 20)
```
"Suspicious TXT query observed with elevated activity
 (query_length=51, query_count_60s=1)"
```
→ Baseline contained 0 TXT queries. TXT records support large arbitrary payloads and are the preferred DNS tunneling vehicle for C2 command staging.

#### RANDOMNESS (RULE_ENCODING_PATTERN — score 20, capped by anti-double-counting)
```
"Obfuscated data encoding pattern detected (BASE64):
 High base64 character concentration (base64_ratio=0.95 >= 0.9)
 with characteristic charset in subdomain (length=37)"
```
→ Base64 encoding ratio > 0.95 with subdomain length > 30 chars indicates structured binary payload encoding.

#### Statistical Baseline Deviation (Phase 4)
```
"Behavioral anomaly in 'subdomain_length': value=37.0 deviates significantly
 from baseline (median=0.0, MAD=2.2239, modified_z=11.2 > 3.5)"
```
→ Modified Z-score: M = 0.6745 × (37 − 0) / 2.2239 = 11.2 — an 11.2-sigma deviation from normal. This quantifies the behavioral distance from the established baseline with a precise statistical measure.

### Step 4: Verify Anti-Double-Counting

Final score breakdown:
- RANDOMNESS: max(25 entropy, 20 encoding) = **25**
- VOLUME: 0 (this record is early in the burst window)
- STRUCTURE: max(15 length) = **15**
- PROTOCOL_MISUSE: max(20 TXT) = **20**
- **Total: 25 + 0 + 15 + 20 = 60 → HIGH**

Both `RULE_HIGH_ENTROPY` (25) and `RULE_ENCODING_PATTERN` (20) triggered within RANDOMNESS, but only the maximum (25) contributed to the score — preventing multi-collinear inflation.

### Key Takeaways for the Demo Audience

1. **False positive rate is 0%** on standard DNS traffic (Demo 1 baseline validation)
2. **80% of synthetic tunnel records** trigger at least MEDIUM severity — the detector is sensitive to real tunneling patterns
3. **Evidence is explicit and explainable** — every scored indicator has human-readable justification
4. **Anti-double-counting is enforced** — correlated signals reinforce without duplicating
5. **All 4 signal categories fired** — no single-indicator alarm; multi-dimensional behavioral fingerprint

---

## API Regression Checklist (Phase 5 Step 8)

All error paths confirmed to return `{"error": str, "detail": str, "status_code": int}`:

| Scenario                     | Status | Error Field    |
|------------------------------|--------|----------------|
| Bad extension (.txt)         | 400    | Bad Request    |
| Invalid magic bytes          | 400    | Bad Request    |
| File > 50 MB                 | 413    | Payload Too Large |
| Incident ID not found        | 404    | Not Found      |
| Unhandled internal error     | 500    | Internal Server Error |

---

## Performance Numbers (Phase 5 Step 11)

| Dataset                        | Packets | Queries | Time    | Peak Memory Delta |
|--------------------------------|---------|---------|---------|-------------------|
| `normal_dns.pcapng` (20.5 MB)  | 1,550   | 30      | 118.34s | 8.70 MB           |
| `synthetic_dns_tunnel.pcap` (87 KB) | 640 | 320   | 4.28s   | 4.87 MB           |

*Note: The normal PCAP processing time is dominated by Scapy reading a 20 MB PCAPNG with 1,550 mixed (DNS + non-DNS) frames. The synthetic PCAP is 87 KB PCAP-format with 640 pure DNS frames, processed 27× faster.*

---

## Quick Reference

| File                                  | Purpose                                      |
|---------------------------------------|----------------------------------------------|
| `dataset/normal_dns.pcapng`           | Real normal DNS capture (Demo 1)             |
| `dataset/synthetic_dns_tunnel.pcap`   | Offline synthetic tunnel traffic (Demo 2)    |
| `dataset/features_normal_dns.csv`     | Pre-extracted features for normal traffic    |
| `dataset/test/generate_tunnel_pcap.py`| PCAP generator (seed 1337, file-write only)  |
| `backend/data/baseline_v1.json`       | Baseline statistics from normal traffic only |
| `backend/data/dns_tunneling.db`       | SQLite database (auto-created on startup)    |
| `backend/run_detection.py`            | CLI audit runner for feature CSVs            |
| `backend/run_phase5_validation.py`    | Full pipeline validation script              |
