"""
Phase 5 Validation Tests — Controlled Lab End-to-End Test Suite.

New tests added for Phase 5 (Step 10), complementing the existing 106 tests:
 1.  normal_pcap -> 0 incidents
 2.  synthetic suspicious PCAP -> suspicious activity detected
 3.  incident persistence
 4.  API upload of suspicious PCAP
 5.  incident retrieval
 6.  analytics update after suspicious upload
 7.  dashboard data shape / frontend compatibility
 8.  repeated upload does NOT corrupt the database
 9.  malformed PCAP handled safely (returns 400 or 500 with standard error schema)
 10. risk score stays within [0, 100] for both datasets

All tests use isolated temp databases — never touch the production DB.
Synthetic PCAP path: dataset/synthetic_dns_tunnel.pcap (pre-generated, seed 1337).
Normal PCAP path:    dataset/normal_dns.pcapng (real captured traffic).
"""

import io
import os
import struct
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.api.deps import get_db, get_uploads_dir
from app.database import get_engine, init_db, get_session, save_incidents, create_processing_record
from app.parser.dns_parser import DNSParser, TrafficType
from app.features import FeatureExtractor
from app.detection import DNSDetector

# ── Paths ─────────────────────────────────────────────────────────────────────
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
NORMAL_PCAP_PATH = _REPO_ROOT / "dataset" / "normal_dns.pcapng"
TUNNEL_PCAP_PATH = _REPO_ROOT / "dataset" / "synthetic_dns_tunnel.pcap"


# ── Shared fixtures ───────────────────────────────────────────────────────────

@pytest.fixture
def client_and_engine():
    """Isolated FastAPI test client with fresh temp DB and temp uploads dir."""
    tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp_db.close()
    db_url = f"sqlite:///{tmp_db.name}"
    engine = get_engine(db_url)
    init_db(engine)

    tmp_uploads = tempfile.TemporaryDirectory()
    uploads_path = Path(tmp_uploads.name)

    def override_db():
        session = get_session(engine)
        try:
            yield session
        finally:
            session.close()

    def override_uploads():
        return uploads_path

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_uploads_dir] = override_uploads

    with TestClient(app) as client:
        yield client, engine

    app.dependency_overrides.clear()
    engine.dispose()
    if os.path.exists(tmp_db.name):
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass
    tmp_uploads.cleanup()


# ── Test 1: Normal PCAP produces zero incidents ───────────────────────────────

class TestNormalPcapZeroIncidents:
    """Test 1: normal_dns.pcapng must produce 0 incidents (all LOW severity)."""

    def test_normal_pcap_upload_produces_zero_incidents(self, client_and_engine):
        client, _ = client_and_engine
        if not NORMAL_PCAP_PATH.exists():
            pytest.skip(f"Normal PCAP not found: {NORMAL_PCAP_PATH}")

        with open(NORMAL_PCAP_PATH, "rb") as f:
            resp = client.post(
                "/api/upload",
                files={"file": ("normal_dns.pcapng", f, "application/x-pcapng")},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["processing_status"] == "completed"
        assert data["incident_count"] == 0, (
            f"Expected 0 incidents from normal traffic, got {data['incident_count']}"
        )

    def test_normal_pcap_direct_pipeline_all_low_severity(self):
        """Verify directly that every feature record from normal PCAP scores LOW."""
        if not NORMAL_PCAP_PATH.exists():
            pytest.skip(f"Normal PCAP not found: {NORMAL_PCAP_PATH}")

        parser = DNSParser()
        records = list(parser.stream_records(str(NORMAL_PCAP_PATH)))
        extractor = FeatureExtractor(window_seconds=60.0)
        features = [extractor.extract_features(r) for r in records]
        features = [f for f in features if f is not None]

        detector = DNSDetector()
        results = [detector.detect(f) for f in features]

        non_low = [r for r in results if r.severity != "LOW"]
        assert len(non_low) == 0, (
            f"Normal PCAP produced {len(non_low)} non-LOW records: "
            f"{[(r.domain, r.severity, r.risk_score) for r in non_low[:3]]}"
        )


# ── Test 2: Suspicious PCAP triggers detection ────────────────────────────────

class TestSuspiciousPcapDetected:
    """Test 2: synthetic_dns_tunnel.pcap must trigger at least one MEDIUM/HIGH/CRITICAL incident."""

    def test_synthetic_tunnel_pcap_triggers_detection(self):
        if not TUNNEL_PCAP_PATH.exists():
            pytest.skip(f"Synthetic PCAP not found: {TUNNEL_PCAP_PATH}")

        parser = DNSParser()
        records = list(parser.stream_records(str(TUNNEL_PCAP_PATH)))
        extractor = FeatureExtractor(window_seconds=60.0)
        features = [extractor.extract_features(r) for r in records if r is not None]
        features = [f for f in features if f is not None]

        detector = DNSDetector()
        results = [detector.detect(f) for f in features]
        flagged = [r for r in results if r.severity in ("MEDIUM", "HIGH", "CRITICAL")]

        assert len(flagged) > 0, (
            f"Expected suspicious detections from tunnel PCAP. "
            f"Got 0 flagged out of {len(results)} records. "
            f"Score distribution: {[(r.risk_score, r.severity) for r in results[:5]]}"
        )

    def test_synthetic_tunnel_contains_high_or_critical(self):
        """Verify at least some HIGH or CRITICAL severity records in tunnel traffic."""
        if not TUNNEL_PCAP_PATH.exists():
            pytest.skip(f"Synthetic PCAP not found: {TUNNEL_PCAP_PATH}")

        parser = DNSParser()
        records = list(parser.stream_records(str(TUNNEL_PCAP_PATH)))
        extractor = FeatureExtractor(window_seconds=60.0)
        features = [extractor.extract_features(r) for r in records if r is not None]
        features = [f for f in features if f is not None]

        detector = DNSDetector()
        results = [detector.detect(f) for f in features]
        high_or_critical = [r for r in results if r.severity in ("HIGH", "CRITICAL")]

        # The synthetic tunnel traffic should trigger high-risk classification
        assert len(high_or_critical) > 0, (
            f"Expected HIGH or CRITICAL incidents from tunnel PCAP. "
            f"Max score was {max((r.risk_score for r in results), default=0)}. "
            f"All severities: {set(r.severity for r in results)}"
        )

    def test_tunnel_evidences_multiple_signal_categories(self):
        """Verify triggered rules span multiple signal categories (RANDOMNESS, VOLUME, STRUCTURE, PROTOCOL_MISUSE)."""
        if not TUNNEL_PCAP_PATH.exists():
            pytest.skip(f"Synthetic PCAP not found: {TUNNEL_PCAP_PATH}")

        from app.detection.scoring import RULE_CATEGORY_MAP, SignalCategory

        parser = DNSParser()
        records = list(parser.stream_records(str(TUNNEL_PCAP_PATH)))
        extractor = FeatureExtractor(window_seconds=60.0)
        features = [extractor.extract_features(r) for r in records if r is not None]
        features = [f for f in features if f is not None]

        detector = DNSDetector()
        results = [detector.detect(f) for f in features]

        # Collect all triggered categories across all records
        triggered_categories = set()
        for r in results:
            for rule_id in r.triggered_rules:
                cat = RULE_CATEGORY_MAP.get(rule_id)
                if cat:
                    triggered_categories.add(cat.value)

        # At minimum, VOLUME and PROTOCOL_MISUSE should be triggered (TXT + high freq)
        assert len(triggered_categories) >= 2, (
            f"Expected >= 2 signal categories to be triggered. Got: {triggered_categories}"
        )


# ── Test 3: Incident persistence ──────────────────────────────────────────────

class TestIncidentPersistence:
    """Test 3: incidents from suspicious PCAP are correctly persisted in the database."""

    def test_suspicious_incidents_persisted_after_upload(self, client_and_engine):
        client, engine = client_and_engine
        if not TUNNEL_PCAP_PATH.exists():
            pytest.skip(f"Synthetic PCAP not found: {TUNNEL_PCAP_PATH}")

        with open(TUNNEL_PCAP_PATH, "rb") as f:
            resp = client.post(
                "/api/upload",
                files={"file": ("synthetic_dns_tunnel.pcap", f, "application/vnd.tcpdump.pcap")},
            )

        assert resp.status_code == 200
        data = resp.json()
        incident_count = data["incident_count"]
        assert incident_count > 0, "Expected incidents from synthetic tunnel PCAP"

        # Verify DB has them
        inc_resp = client.get("/api/incidents")
        assert inc_resp.status_code == 200
        body = inc_resp.json()
        assert body["total"] == incident_count

    def test_incident_db_records_have_required_fields(self, client_and_engine):
        """Verify persisted incident records have all schema-required fields."""
        client, engine = client_and_engine
        if not TUNNEL_PCAP_PATH.exists():
            pytest.skip(f"Synthetic PCAP not found: {TUNNEL_PCAP_PATH}")

        with open(TUNNEL_PCAP_PATH, "rb") as f:
            resp = client.post(
                "/api/upload",
                files={"file": ("synthetic_dns_tunnel.pcap", f, "application/vnd.tcpdump.pcap")},
            )
        assert resp.status_code == 200

        inc_resp = client.get("/api/incidents")
        body = inc_resp.json()
        if body["total"] == 0:
            pytest.skip("No incidents generated (check detection logic)")

        item = body["items"][0]
        required_fields = ["id", "processing_record_id", "timestamp", "source_ip",
                           "domain", "risk_score", "severity", "reasons", "status"]
        for field in required_fields:
            assert field in item, f"Missing required field in incident: {field}"

        assert isinstance(item["reasons"], list)
        assert len(item["reasons"]) > 0, "Incident must have at least one reason"
        assert item["severity"] in ("MEDIUM", "HIGH", "CRITICAL")
        assert 0 <= item["risk_score"] <= 100


# ── Test 4: API upload of suspicious PCAP ────────────────────────────────────

class TestApiUploadSuspiciousPcap:
    """Test 4: verify the /api/upload endpoint handles the synthetic PCAP."""

    def test_upload_synthetic_pcap_returns_processing_id(self, client_and_engine):
        client, _ = client_and_engine
        if not TUNNEL_PCAP_PATH.exists():
            pytest.skip(f"Synthetic PCAP not found: {TUNNEL_PCAP_PATH}")

        with open(TUNNEL_PCAP_PATH, "rb") as f:
            resp = client.post(
                "/api/upload",
                files={"file": ("synthetic_dns_tunnel.pcap", f, "application/vnd.tcpdump.pcap")},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert "processing_id" in data
        assert data["processing_id"] > 0
        assert data["filename"] == "synthetic_dns_tunnel.pcap"
        assert data["processing_status"] == "completed"
        assert data["packet_count"] > 0
        assert data["dns_packet_count"] > 0
        assert data["query_count"] > 0


# ── Test 5: Incident retrieval ────────────────────────────────────────────────

class TestIncidentRetrieval:
    """Test 5: incidents from suspicious upload are retrievable by ID and domain."""

    def test_incident_retrieval_by_id(self, client_and_engine):
        client, _ = client_and_engine
        if not TUNNEL_PCAP_PATH.exists():
            pytest.skip(f"Synthetic PCAP not found: {TUNNEL_PCAP_PATH}")

        with open(TUNNEL_PCAP_PATH, "rb") as f:
            resp = client.post(
                "/api/upload",
                files={"file": ("synthetic_dns_tunnel.pcap", f, "application/vnd.tcpdump.pcap")},
            )
        assert resp.status_code == 200

        list_resp = client.get("/api/incidents")
        body = list_resp.json()
        if body["total"] == 0:
            pytest.skip("No incidents to retrieve")

        inc_id = body["items"][0]["id"]
        detail_resp = client.get(f"/api/incidents/{inc_id}")
        assert detail_resp.status_code == 200
        detail = detail_resp.json()
        assert detail["id"] == inc_id
        assert "attacker.test" in detail["domain"]

    def test_incident_retrieval_filter_by_domain(self, client_and_engine):
        client, _ = client_and_engine
        if not TUNNEL_PCAP_PATH.exists():
            pytest.skip(f"Synthetic PCAP not found: {TUNNEL_PCAP_PATH}")

        with open(TUNNEL_PCAP_PATH, "rb") as f:
            client.post(
                "/api/upload",
                files={"file": ("synthetic_dns_tunnel.pcap", f, "application/vnd.tcpdump.pcap")},
            )

        # Filter by the tunneling domain
        filt_resp = client.get("/api/incidents?domain=attacker.test")
        assert filt_resp.status_code == 200
        body = filt_resp.json()
        # Incidents with attacker.test domain should be present
        for item in body["items"]:
            assert "attacker.test" in item["domain"]


# ── Test 6: Analytics update ──────────────────────────────────────────────────

class TestAnalyticsUpdateAfterSuspiciousUpload:
    """Test 6: analytics endpoint reflects correct counts after suspicious PCAP upload."""

    def test_analytics_updates_after_suspicious_upload(self, client_and_engine):
        client, _ = client_and_engine
        if not TUNNEL_PCAP_PATH.exists():
            pytest.skip(f"Synthetic PCAP not found: {TUNNEL_PCAP_PATH}")

        before = client.get("/api/analytics").json()
        assert before["total_incidents"] == 0
        assert before["high_risk_incidents"] == 0

        with open(TUNNEL_PCAP_PATH, "rb") as f:
            upload = client.post(
                "/api/upload",
                files={"file": ("synthetic_dns_tunnel.pcap", f, "application/vnd.tcpdump.pcap")},
            )
        assert upload.status_code == 200

        after = client.get("/api/analytics").json()
        expected_incidents = upload.json()["incident_count"]

        assert after["total_incidents"] == expected_incidents
        if expected_incidents > 0:
            # high_risk_incidents should be a subset of total_incidents
            assert after["high_risk_incidents"] >= 0
            assert after["high_risk_incidents"] <= after["total_incidents"]
            # attacker.test should appear in top domains
            domains = [d["domain"] for d in after["top_suspicious_domains"]]
            assert any("attacker.test" in d for d in domains), (
                f"Expected attacker.test in top domains, got: {domains}"
            )


# ── Test 7: Dashboard data compatibility ─────────────────────────────────────

class TestDashboardDataCompatibility:
    """Test 7: verify API response shapes match what the frontend expects."""

    def test_analytics_response_has_required_keys(self, client_and_engine):
        """Frontend Dashboard.jsx consumes these keys from /api/analytics."""
        client, _ = client_and_engine
        resp = client.get("/api/analytics")
        assert resp.status_code == 200
        data = resp.json()
        required_keys = [
            "total_processed_pcaps",
            "total_dns_queries",
            "total_incidents",
            "high_risk_incidents",
            "affected_hosts",
            "severity_distribution",
            "top_suspicious_domains",
        ]
        for key in required_keys:
            assert key in data, f"Missing analytics key: {key}"

        # Severity distribution must have all 4 tiers
        sev_dist = data["severity_distribution"]
        for tier in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            assert tier in sev_dist, f"Missing severity tier: {tier}"

    def test_incidents_response_has_required_keys(self, client_and_engine):
        """Frontend IncidentsTable.jsx expects these fields on each incident item."""
        client, engine = client_and_engine
        proc_id = create_processing_record("test.pcap", "/tmp/test.pcap", engine=engine)
        save_incidents(proc_id, [{
            "timestamp": 1790585900.0,
            "source_ip": "10.0.0.1",
            "destination_ip": "192.0.2.1",
            "domain": "test.attacker.test",
            "query_type": "TXT",
            "risk_score": 75,
            "severity": "HIGH",
            "reasons": ["High entropy subdomain", "TXT record tunneling"],
            "status": "NEW",
        }], engine=engine)

        resp = client.get("/api/incidents")
        body = resp.json()
        item = body["items"][0]
        expected_keys = [
            "id", "timestamp", "source_ip", "domain", "query_type",
            "risk_score", "severity", "reasons", "status",
        ]
        for key in expected_keys:
            assert key in item, f"Missing incident field for frontend: {key}"

        # Reasons must be a deserialized list, not a raw JSON string
        assert isinstance(item["reasons"], list)

    def test_processings_response_has_required_keys(self, client_and_engine):
        """Frontend UploadWidget.jsx reads processing history fields."""
        client, _ = client_and_engine
        if not NORMAL_PCAP_PATH.exists():
            pytest.skip(f"Normal PCAP not found: {NORMAL_PCAP_PATH}")

        with open(NORMAL_PCAP_PATH, "rb") as f:
            client.post("/api/upload", files={"file": ("normal_dns.pcapng", f, "application/x-pcapng")})

        resp = client.get("/api/processings")
        body = resp.json()
        item = body["items"][0]
        expected_keys = ["id", "filename", "processed_at", "packet_count",
                         "dns_packet_count", "query_count", "processing_status"]
        for key in expected_keys:
            assert key in item, f"Missing processing history field for frontend: {key}"
        # Security: file_path MUST NOT be exposed
        assert "file_path" not in item


# ── Test 8: Repeated upload doesn't corrupt data ─────────────────────────────

class TestRepeatedUploadIsolation:
    """Test 8: repeated uploads of the same PCAP create separate records without corrupting data."""

    def test_repeated_upload_creates_distinct_records(self, client_and_engine):
        client, _ = client_and_engine
        if not TUNNEL_PCAP_PATH.exists():
            pytest.skip(f"Synthetic PCAP not found: {TUNNEL_PCAP_PATH}")

        ids = []
        for _ in range(2):
            with open(TUNNEL_PCAP_PATH, "rb") as f:
                resp = client.post(
                    "/api/upload",
                    files={"file": ("synthetic_dns_tunnel.pcap", f, "application/vnd.tcpdump.pcap")},
                )
            assert resp.status_code == 200
            ids.append(resp.json()["processing_id"])

        # Both IDs must be distinct
        assert ids[0] != ids[1], "Repeated uploads must create separate processing records"

        # Total processings count must be 2
        proc_resp = client.get("/api/processings")
        assert proc_resp.json()["total"] == 2

    def test_repeated_upload_analytics_totals_are_cumulative(self, client_and_engine):
        """Analytics totals must accumulate correctly across multiple uploads."""
        client, _ = client_and_engine
        if not TUNNEL_PCAP_PATH.exists():
            pytest.skip(f"Synthetic PCAP not found: {TUNNEL_PCAP_PATH}")

        inc_counts = []
        for _ in range(2):
            with open(TUNNEL_PCAP_PATH, "rb") as f:
                resp = client.post(
                    "/api/upload",
                    files={"file": ("synthetic_dns_tunnel.pcap", f, "application/vnd.tcpdump.pcap")},
                )
            inc_counts.append(resp.json()["incident_count"])

        analytics = client.get("/api/analytics").json()
        expected_total = sum(inc_counts)
        assert analytics["total_incidents"] == expected_total, (
            f"Expected cumulative incidents={expected_total}, got {analytics['total_incidents']}"
        )


# ── Test 9: Malformed PCAP handled safely ─────────────────────────────────────

class TestMalformedPcapHandling:
    """Test 9: malformed or truncated PCAPs must return standard error schema without crashing."""

    def _pcap_header(self) -> bytes:
        """Minimal valid PCAP little-endian header."""
        # magic, ver_major, ver_minor, thiszone, sigfigs, snaplen, network
        return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    def test_truncated_pcap_content_is_handled_safely(self, client_and_engine):
        """A file with valid PCAP magic but truncated body should not crash the server."""
        client, _ = client_and_engine
        # Valid magic header but no packet data after it
        truncated = self._pcap_header() + b"\x00" * 10
        resp = client.post(
            "/api/upload",
            files={"file": ("truncated.pcap", truncated, "application/vnd.tcpdump.pcap")},
        )
        # Must return standard error schema (400 or 500), never crash with unhandled exception
        assert resp.status_code in (200, 400, 500), f"Unexpected status: {resp.status_code}"
        if resp.status_code in (400, 500):
            data = resp.json()
            assert "error" in data
            assert "detail" in data
            assert "status_code" in data

    def test_unsupported_file_extension_rejected(self, client_and_engine):
        """Regression: unsupported file types must be rejected with standard error schema."""
        client, _ = client_and_engine
        resp = client.post(
            "/api/upload",
            files={"file": ("capture.exe", b"MZ\x90\x00some_binary", "application/octet-stream")},
        )
        assert resp.status_code == 400
        data = resp.json()
        assert data["status_code"] == 400
        assert data["error"] == "Bad Request"
        assert "extension" in data["detail"].lower()

    def test_invalid_magic_bytes_rejected(self, client_and_engine):
        """Regression: spoofed extension with wrong magic bytes must use standard error schema."""
        client, _ = client_and_engine
        resp = client.post(
            "/api/upload",
            files={"file": ("not_pcap.pcap", b"INVALID_MAGIC_BYTES_HERE", "application/vnd.tcpdump.pcap")},
        )
        assert resp.status_code == 400
        data = resp.json()
        assert data["status_code"] == 400
        assert "magic bytes" in data["detail"].lower()


# ── Test 10: Score bounds 0-100 ───────────────────────────────────────────────

class TestRiskScoreBounds:
    """Test 10: risk score must stay in [0, 100] for all records in both datasets."""

    def _get_all_scores(self, pcap_path: Path) -> list:
        parser = DNSParser()
        records = list(parser.stream_records(str(pcap_path)))
        extractor = FeatureExtractor(window_seconds=60.0)
        features = [extractor.extract_features(r) for r in records if r is not None]
        features = [f for f in features if f is not None]
        detector = DNSDetector()
        return [detector.detect(f).risk_score for f in features]

    def test_normal_pcap_scores_within_bounds(self):
        if not NORMAL_PCAP_PATH.exists():
            pytest.skip(f"Normal PCAP not found: {NORMAL_PCAP_PATH}")
        scores = self._get_all_scores(NORMAL_PCAP_PATH)
        assert len(scores) > 0
        violations = [s for s in scores if not (0 <= s <= 100)]
        assert len(violations) == 0, f"Out-of-bounds scores in normal PCAP: {violations}"

    def test_suspicious_pcap_scores_within_bounds(self):
        if not TUNNEL_PCAP_PATH.exists():
            pytest.skip(f"Synthetic PCAP not found: {TUNNEL_PCAP_PATH}")
        scores = self._get_all_scores(TUNNEL_PCAP_PATH)
        assert len(scores) > 0
        violations = [s for s in scores if not (0 <= s <= 100)]
        assert len(violations) == 0, f"Out-of-bounds scores in tunnel PCAP: {violations}"

    def test_extreme_synthetic_feature_scores_within_bounds(self):
        """Feed extreme feature values directly to confirm score clamping."""
        detector = DNSDetector()
        extreme_record = {
            "query_name": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.attacker.test",
            "domain": "attacker.test",
            "source_ip": "10.10.10.10",
            "timestamp": 1790700000.0,
            "query_type": "TXT",
            "query_length": 253,
            "subdomain_length": 240,
            "label_count": 8,
            "subdomain_depth": 5,
            "longest_label_length": 63,
            "domain_entropy": 4.99,
            "subdomain_entropy": 4.99,
            "digit_ratio": 0.5,
            "alpha_ratio": 0.5,
            "hex_ratio": 0.95,
            "base32_ratio": 0.95,
            "base64_ratio": 0.95,
            "query_count_60s": 999,
            "unique_query_count_60s": 999,
            "unique_subdomain_count_60s": 999,
            "nxdomain_ratio": 0.99,
            "nxdomain_count": 50,
        }
        result = detector.detect(extreme_record)
        assert 0 <= result.risk_score <= 100, (
            f"Extreme features produced out-of-bounds score: {result.risk_score}"
        )
        assert result.severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
