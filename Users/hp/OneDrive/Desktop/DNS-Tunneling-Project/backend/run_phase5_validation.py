"""
Phase 5 Full Pipeline Validation Script.
Runs: normal PCAP -> parser -> features -> detection -> DB -> summary
Then: suspicious PCAP -> same pipeline.
Reports real numbers for the Phase 5 validation report.
"""
import sys
import time
import tracemalloc
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app.database import init_db, get_default_engine, get_session
from app.database.connection import DEFAULT_DB_FILE
from app.database import (
    ProcessingRecord, DNSQueryRecord, DNSFeatureWindow, Incident,
    create_processing_record, save_query_records, save_feature_windows,
    save_incidents, FeatureWindow,
)
from app.parser.dns_parser import DNSParser, TrafficType
from app.features import FeatureExtractor
from app.detection import DNSDetector, DetectionResult

# Initialize fresh DB
engine = get_default_engine()
init_db(engine)

def run_pipeline(pcap_path: Path, label: str) -> dict:
    print(f"\n{'='*70}")
    print(f"[{label}] Processing: {pcap_path.name}")
    print(f"{'='*70}")

    t0 = time.perf_counter()
    tracemalloc.start()
    mem_before = tracemalloc.get_traced_memory()[0]

    parser = DNSParser()
    raw_records = list(parser.stream_records(str(pcap_path)))
    packet_count = len(raw_records)
    dns_packets = [r for r in raw_records if r.traffic_type == TrafficType.DNS]
    dns_packet_count = len(dns_packets)
    print(f"  Total packets read  : {packet_count}")
    print(f"  DNS packets         : {dns_packet_count}")

    extractor = FeatureExtractor(window_seconds=60.0)
    extracted_features = []
    for r in raw_records:
        feat = extractor.extract_features(r)
        if feat is not None:
            extracted_features.append(feat)

    query_count = len(extracted_features)
    print(f"  Feature records     : {query_count}")

    detector = DNSDetector()
    detection_results = [detector.detect(f) for f in extracted_features]

    severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    all_triggered_rules = {}
    flagged = []

    for res in detection_results:
        severity_counts[res.severity] = severity_counts.get(res.severity, 0) + 1
        for rule_id in res.triggered_rules:
            all_triggered_rules[rule_id] = all_triggered_rules.get(rule_id, 0) + 1
        if res.severity in ("MEDIUM", "HIGH", "CRITICAL"):
            flagged.append(res)

    incident_count = len(flagged)
    print(f"\n  Severity distribution:")
    for sev, cnt in severity_counts.items():
        pct = cnt / query_count * 100 if query_count else 0
        print(f"    {sev:10s}: {cnt:4d}  ({pct:.1f}%)")

    print(f"\n  Triggered rules:")
    if all_triggered_rules:
        for rid, cnt in sorted(all_triggered_rules.items(), key=lambda x: -x[1]):
            print(f"    {rid}: {cnt} hits")
    else:
        print("    (none)")

    print(f"\n  Flagged incidents (MEDIUM+): {incident_count}")

    for i, inc in enumerate(flagged[:5], 1):
        print(f"\n  Incident #{i}:")
        print(f"    Domain      : {inc.domain}")
        print(f"    Source IP   : {inc.source_ip}")
        print(f"    Risk Score  : {inc.risk_score}")
        print(f"    Severity    : {inc.severity}")
        print(f"    Rules       : {', '.join(inc.triggered_rules)}")
        print(f"    Evidence    : {inc.evidence[:3]}")

    # Persist
    processing_id = create_processing_record(
        filename=pcap_path.name,
        file_path=str(pcap_path),
        packet_count=packet_count,
        dns_packet_count=dns_packet_count,
        query_count=query_count,
        processing_status="completed",
        engine=engine,
    )

    save_query_records(processing_id, raw_records[:query_count], engine=engine)

    windows = [
        FeatureWindow(
            window_start=f.timestamp,
            source_ip=f.source_ip,
            registered_domain=f.domain,
            query_count=f.query_count_60s,
            unique_subdomain_count=f.unique_subdomain_count_60s,
            avg_entropy=f.domain_entropy,
            max_entropy=f.subdomain_entropy,
            nxdomain_ratio=0.0,
            txt_ratio=1.0 if f.query_type == "TXT" else 0.0,
            is_local_traffic=False,
        )
        for f in extracted_features
    ]
    save_feature_windows(processing_id, windows, engine=engine)
    save_incidents(processing_id, flagged, engine=engine)

    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    t1 = time.perf_counter()
    elapsed = t1 - t0
    peak_delta_mb = (peak_mem - mem_before) / 1024 / 1024

    print(f"\n  Processing time     : {elapsed:.2f}s")
    print(f"  Peak memory delta   : {peak_delta_mb:.2f} MB")
    print(f"  Processing ID (DB)  : {processing_id}")

    return {
        "label": label,
        "pcap_name": pcap_path.name,
        "packet_count": packet_count,
        "dns_packet_count": dns_packet_count,
        "query_count": query_count,
        "severity_counts": severity_counts,
        "triggered_rules": all_triggered_rules,
        "incident_count": incident_count,
        "flagged": flagged,
        "processing_id": processing_id,
        "elapsed_s": elapsed,
        "peak_mem_mb": peak_delta_mb,
    }


project_root = Path(__file__).resolve().parent.parent
normal_pcap = project_root / "dataset" / "normal_dns.pcapng"
tunnel_pcap = project_root / "dataset" / "synthetic_dns_tunnel.pcap"

normal_result = run_pipeline(normal_pcap, "DEMO 1 — Normal DNS")
tunnel_result = run_pipeline(tunnel_pcap, "DEMO 2 — Suspicious Tunneling")

print("\n\n" + "="*70)
print("FINAL SUMMARY")
print("="*70)
print(f"\nNormal PCAP    : {normal_result['query_count']} records, "
      f"{normal_result['severity_counts']['LOW']} LOW, "
      f"{normal_result['incident_count']} incidents")
print(f"Suspicious PCAP: {tunnel_result['query_count']} records, "
      f"incidents={tunnel_result['incident_count']} "
      f"(HIGH={tunnel_result['severity_counts'].get('HIGH',0)}, "
      f"CRITICAL={tunnel_result['severity_counts'].get('CRITICAL',0)})")

high_risk = tunnel_result['severity_counts'].get('HIGH', 0) + tunnel_result['severity_counts'].get('CRITICAL', 0)
print(f"  High+Critical total: {high_risk} (definition: severity in HIGH or CRITICAL)")

# Final DB state
import sqlite3
conn = sqlite3.connect(str(DEFAULT_DB_FILE))
cur = conn.cursor()
cur.execute("SELECT count(*) FROM processing_records")
print(f"\nDB processing_records : {cur.fetchone()[0]}")
cur.execute("SELECT count(*) FROM dns_query_records")
print(f"DB dns_query_records  : {cur.fetchone()[0]}")
cur.execute("SELECT count(*) FROM dns_feature_windows")
print(f"DB dns_feature_windows: {cur.fetchone()[0]}")
cur.execute("SELECT count(*) FROM incidents")
print(f"DB incidents          : {cur.fetchone()[0]}")
cur.execute("SELECT id, filename, packet_count, query_count, processing_status FROM processing_records ORDER BY id")
for row in cur.fetchall():
    print(f"  Processing #{row[0]}: {row[1]}, pkts={row[2]}, queries={row[3]}, status={row[4]}")
cur.execute("SELECT id, domain, source_ip, risk_score, severity, status FROM incidents ORDER BY id")
incidents = cur.fetchall()
print(f"\nIncident records ({len(incidents)}):")
for row in incidents[:20]:
    print(f"  #{row[0]}: {row[1]} | {row[2]} | score={row[3]} | {row[4]} | {row[5]}")
conn.close()
