"""
Tests for ioc_enrichment.py
Run with: pytest tests/test_ioc_enrichment.py -v
"""

import sys
import os
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))
from ioc_enrichment import (
    detect_type,
    verdict_from_vt,
    load_iocs_from_file,
    generate_report,
    IOCResult,
    render_ip_section,
    render_hash_section,
)

class TestDetectType:
    def test_ipv4(self):
        assert detect_type("192.168.1.1")    == "ip"
        assert detect_type("8.8.8.8")        == "ip"
        assert detect_type("185.220.101.45") == "ip"

    def test_md5(self):
        assert detect_type("44d88612fea8a8f36de82e1278abb02f") == "hash"
        assert detect_type("d41d8cd98f00b204e9800998ecf8427e") == "hash"

    def test_sha256(self):
        sha = "a" * 64
        assert detect_type(sha) == "hash"

    def test_invalid(self):
        assert detect_type("not-an-ioc")          is None
        assert detect_type("http://example.com")   is None
        assert detect_type("example.com")          is None
        assert detect_type("")                     is None

    def test_strips_whitespace(self):
        assert detect_type("  8.8.8.8  ") == "ip"

class TestVerdictFromVT:
    def test_malicious_threshold(self):
        assert verdict_from_vt({"malicious": 3})  == "malicious"
        assert verdict_from_vt({"malicious": 10}) == "malicious"

    def test_suspicious_threshold(self):
        assert verdict_from_vt({"malicious": 1})                    == "suspicious"
        assert verdict_from_vt({"malicious": 0, "suspicious": 3})   == "suspicious"

    def test_clean(self):
        assert verdict_from_vt({"malicious": 0, "suspicious": 0, "harmless": 70}) == "clean"
        assert verdict_from_vt({}) == "clean"

    def test_borderline(self):
        assert verdict_from_vt({"malicious": 2}) == "suspicious"

class TestLoadIOCs:
    def test_basic_load(self, tmp_path):
        f = tmp_path / "iocs.txt"
        f.write_text("8.8.8.8\n1.1.1.1\n")
        assert load_iocs_from_file(str(f)) == ["8.8.8.8", "1.1.1.1"]

    def test_skips_comments(self, tmp_path):
        f = tmp_path / "iocs.txt"
        f.write_text("# comment\n8.8.8.8\n# another\n")
        assert load_iocs_from_file(str(f)) == ["8.8.8.8"]

    def test_skips_blank_lines(self, tmp_path):
        f = tmp_path / "iocs.txt"
        f.write_text("\n8.8.8.8\n\n1.1.1.1\n")
        assert load_iocs_from_file(str(f)) == ["8.8.8.8", "1.1.1.1"]

class TestGenerateReport:
    def _ip_result(self, verdict="malicious"):
        r = IOCResult(ioc="1.2.3.4", ioc_type="ip", verdict=verdict)
        r.vt_data = {
            "stats": {"malicious": 5, "suspicious": 1, "harmless": 60, "undetected": 10},
            "country": "RU", "asn": 12345, "as_owner": "BadISP",
            "network": "1.2.3.0/24", "reputation": -10, "tags": ["vpn"],
        }
        r.abip_data = {
            "abuseConfidenceScore": 95, "totalReports": 42,
            "isp": "BadISP LLC", "domain": "bad.example",
            "usageType": "Data Center/Web Hosting/Transit",
            "lastReportedAt": "2024-01-15T12:00:00+00:00",
        }
        return r

    def _hash_result(self, verdict="suspicious"):
        r = IOCResult(ioc="a" * 64, ioc_type="hash", verdict=verdict)
        r.vt_data = {
            "stats": {"malicious": 2, "suspicious": 4, "harmless": 0, "undetected": 60},
            "meaningful_name": "evil.exe", "type_description": "Win32 EXE",
            "magic": "PE32 executable", "size": 204800,
            "first_submission": 1700000000, "last_submission": 1705000000,
            "times_submitted": 7, "tags": ["peexe"],
            "popular_threat": {"suggested_threat_label": "trojan.genericgb/agent"},
        }
        return r

    def test_report_created(self, tmp_path):
        results = [self._ip_result(), self._hash_result()]
        path = generate_report(results, str(tmp_path))
        assert Path(path).exists()

    def test_report_contains_summary(self, tmp_path):
        results = [self._ip_result()]
        path = generate_report(results, str(tmp_path))
        content = Path(path).read_text()
        assert "Executive Summary" in content
        assert "Total IOCs analyzed" in content

    def test_report_contains_ioc(self, tmp_path):
        results = [self._ip_result()]
        path = generate_report(results, str(tmp_path))
        content = Path(path).read_text()
        assert "1.2.3.4" in content
        assert "MALICIOUS" in content

    def test_report_contains_mitre(self, tmp_path):
        results = [self._ip_result()]
        path = generate_report(results, str(tmp_path))
        content = Path(path).read_text()
        assert "MITRE ATT&CK" in content

    def test_error_result_in_report(self, tmp_path):
        r = IOCResult(ioc="9.9.9.9", ioc_type="ip", error="Connection timeout")
        path = generate_report([r], str(tmp_path))
        content = Path(path).read_text()
        assert "ERROR" in content
        assert "Connection timeout" in content

    def test_unknown_hash_in_report(self, tmp_path):
        r = IOCResult(ioc="b" * 64, ioc_type="hash", verdict="unknown", vt_data={})
        path = generate_report([r], str(tmp_path))
        content = Path(path).read_text()
        assert "Not found in VirusTotal" in content
