"""test_get_ioc_intel.py

pytest suite for get_ioc_intel.py.
Uses the `responses` library to stub HTTP calls.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Ensure the script-under-test is importable (conftest.py handles _SHARED,
# but we also need the package directory itself on sys.path so that
# `import get_ioc_intel` resolves without installing anything).
_PKG = Path(__file__).resolve().parent
if str(_PKG) not in sys.path:
    sys.path.insert(0, str(_PKG))

import get_ioc_intel as gii  # noqa: E402
import pytest  # noqa: E402
import responses as resp_lib  # noqa: E402

# ---------------------------------------------------------------------------
# 1. IOC type detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value, expected",
    [
        ("1.2.3.4", "ipv4"),
        ("255.0.0.1", "ipv4"),
        ("evil.com", "domain"),
        ("sub.evil.co.uk", "domain"),
        ("http://evil.com/payload", "url"),
        ("https://malware.biz/dl?x=1", "url"),
        ("d41d8cd98f00b204e9800998ecf8427e", "md5"),       # 32 hex
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"),  # 40 hex
        ("a" * 64, "sha256"),
    ],
)
def test_detect_ioc_type_valid(value, expected):
    assert gii.detect_ioc_type(value) == expected


def test_detect_ioc_type_invalid():
    with pytest.raises(ValueError, match="Could not detect IOC type"):
        gii.detect_ioc_type("not-an-ioc!!!")


def test_detect_ioc_type_bad_octet():
    """256.0.0.1 looks like an IP but has an invalid octet — should raise."""
    with pytest.raises(ValueError):
        gii.detect_ioc_type("256.0.0.1")


# ---------------------------------------------------------------------------
# 2. VirusTotal — IP
# ---------------------------------------------------------------------------


@resp_lib.activate
def test_query_vt_ip(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-vt-key")
    resp_lib.add(
        resp_lib.GET,
        "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4",
        json={
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 3,
                        "suspicious": 1,
                        "harmless": 70,
                        "undetected": 5,
                    }
                }
            }
        },
        status=200,
    )
    result = gii.query_virustotal("1.2.3.4", "ipv4")
    assert result is not None
    assert result["provider"] == "virustotal"
    assert result["stats"]["malicious"] == 3
    assert result["stats"]["harmless"] == 70
    assert result["raw_status"] == 200


# ---------------------------------------------------------------------------
# 3. VirusTotal — hash (files endpoint)
# ---------------------------------------------------------------------------


@resp_lib.activate
def test_query_vt_hash(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-vt-key")
    sha256 = "a" * 64
    resp_lib.add(
        resp_lib.GET,
        f"https://www.virustotal.com/api/v3/files/{sha256}",
        json={
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 50,
                        "suspicious": 2,
                        "harmless": 0,
                        "undetected": 10,
                    }
                }
            }
        },
        status=200,
    )
    result = gii.query_virustotal(sha256, "sha256")
    assert result is not None
    assert result["stats"]["malicious"] == 50
    assert result["type"] == "sha256"


# ---------------------------------------------------------------------------
# 4. AbuseIPDB — IP check
# ---------------------------------------------------------------------------


@resp_lib.activate
def test_query_abuseipdb_ip(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-abuse-key")
    resp_lib.add(
        resp_lib.GET,
        "https://api.abuseipdb.com/api/v2/check",
        json={
            "data": {
                "abuseConfidenceScore": 100,
                "totalReports": 99,
                "lastReportedAt": "2024-06-01T12:00:00+00:00",
                "countryCode": "CN",
            }
        },
        status=200,
    )
    result = gii.query_abuseipdb("1.2.3.4", "ipv4")
    assert result is not None
    assert result["provider"] == "abuseipdb"
    assert result["abuseConfidenceScore"] == 100
    assert result["countryCode"] == "CN"


# ---------------------------------------------------------------------------
# 5. AbuseIPDB — skips non-IP types (no HTTP call)
# ---------------------------------------------------------------------------


@resp_lib.activate
def test_query_abuseipdb_skips_non_ip(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-abuse-key")
    result = gii.query_abuseipdb("a" * 64, "sha256")
    assert result is None
    assert len(resp_lib.calls) == 0


# ---------------------------------------------------------------------------
# 6. AlienVault OTX — domain
# ---------------------------------------------------------------------------


@resp_lib.activate
def test_query_otx_domain(monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "test-otx-key")
    resp_lib.add(
        resp_lib.GET,
        "https://otx.alienvault.com/api/v1/indicators/domain/evil.com/general",
        json={
            "pulse_info": {"count": 7},
            "reputation": 0,
        },
        status=200,
    )
    result = gii.query_otx("evil.com", "domain")
    assert result is not None
    assert result["provider"] == "otx"
    assert result["pulse_count"] == 7


# ---------------------------------------------------------------------------
# 7. 429 retry
# ---------------------------------------------------------------------------


@resp_lib.activate
def test_429_retry(monkeypatch):
    """First call returns 429, second call succeeds — should return the 200."""
    monkeypatch.setenv("VT_API_KEY", "test-vt-key")
    monkeypatch.setattr("time.sleep", lambda *_: None)

    resp_lib.add(
        resp_lib.GET,
        "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4",
        status=429,
        headers={"Retry-After": "1"},
    )
    resp_lib.add(
        resp_lib.GET,
        "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4",
        json={
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 1,
                        "suspicious": 0,
                        "harmless": 80,
                        "undetected": 2,
                    }
                }
            }
        },
        status=200,
    )
    result = gii.query_virustotal("1.2.3.4", "ipv4")
    assert result is not None
    assert result["raw_status"] == 200
    # Two HTTP calls were made (the 429 + the successful retry)
    assert len(resp_lib.calls) == 2


# ---------------------------------------------------------------------------
# 8. Missing API key — warns, returns None, no HTTP call
# ---------------------------------------------------------------------------


@resp_lib.activate
def test_missing_api_key_warns_returns_none(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    result = gii.query_virustotal("1.2.3.4", "ipv4")
    assert result is None
    assert len(resp_lib.calls) == 0


@resp_lib.activate
def test_missing_abuseipdb_key_returns_none(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    result = gii.query_abuseipdb("1.2.3.4", "ipv4")
    assert result is None
    assert len(resp_lib.calls) == 0


@resp_lib.activate
def test_missing_otx_key_returns_none(monkeypatch):
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    result = gii.query_otx("evil.com", "domain")
    assert result is None
    assert len(resp_lib.calls) == 0


# ---------------------------------------------------------------------------
# 9. Dry-run returns canned data, no HTTP
# ---------------------------------------------------------------------------


@resp_lib.activate
def test_dry_run_returns_canned_vt():
    result = gii.query_virustotal("1.2.3.4", "ipv4", dry_run=True)
    assert result is not None
    assert result.get("dry_run") is True
    assert result["provider"] == "virustotal"
    assert "malicious" in result["stats"]
    assert len(resp_lib.calls) == 0


@resp_lib.activate
def test_dry_run_returns_canned_abuseipdb():
    result = gii.query_abuseipdb("1.2.3.4", "ipv4", dry_run=True)
    assert result is not None
    assert result.get("dry_run") is True
    assert result["provider"] == "abuseipdb"
    assert len(resp_lib.calls) == 0


@resp_lib.activate
def test_dry_run_returns_canned_otx():
    result = gii.query_otx("evil.com", "domain", dry_run=True)
    assert result is not None
    assert result.get("dry_run") is True
    assert result["provider"] == "otx"
    assert len(resp_lib.calls) == 0


# ---------------------------------------------------------------------------
# 10. Batch mode via main()
# ---------------------------------------------------------------------------


def test_batch_mode(tmp_path, monkeypatch, capsys):
    csv_file = tmp_path / "iocs.csv"
    csv_file.write_text("value,type\n1.2.3.4,ipv4\nevil.com,domain\n", encoding="utf-8")

    # No env keys set — use dry-run so no HTTP needed and no "no keys" exit
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("OTX_API_KEY", raising=False)

    exit_code = gii.main(["--batch", str(csv_file), "--dry-run"])
    assert exit_code == 0

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert isinstance(payload, list)
    assert len(payload) == 2
    assert payload[0]["ioc"] == "1.2.3.4"
    assert payload[1]["ioc"] == "evil.com"


# ---------------------------------------------------------------------------
# 11. --out writes a file
# ---------------------------------------------------------------------------


def test_main_writes_out_file(tmp_path, monkeypatch):
    out_file = tmp_path / "result.json"

    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("OTX_API_KEY", raising=False)

    exit_code = gii.main(["--ioc", "1.2.3.4", "--dry-run", "--out", str(out_file)])
    assert exit_code == 0
    assert out_file.exists()

    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["ioc"] == "1.2.3.4"
    assert data["type"] == "ipv4"


# ---------------------------------------------------------------------------
# 12. Batch mode with auto-detected types (no 'type' column)
# ---------------------------------------------------------------------------


def test_batch_mode_auto_detect(tmp_path, monkeypatch, capsys):
    csv_file = tmp_path / "iocs_notype.csv"
    csv_file.write_text("value\n8.8.8.8\ngoogle.com\n", encoding="utf-8")

    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("OTX_API_KEY", raising=False)

    exit_code = gii.main(["--batch", str(csv_file), "--dry-run"])
    assert exit_code == 0

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert len(payload) == 2
    assert payload[0]["type"] == "ipv4"
    assert payload[1]["type"] == "domain"
