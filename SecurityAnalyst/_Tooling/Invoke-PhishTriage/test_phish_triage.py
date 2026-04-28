"""Tests for phish_triage.py.

Runs against sample .eml fixtures under samples/ and exercises all helpers.
"""

from __future__ import annotations

import email
import email.encoders
import email.mime.base
import email.mime.multipart
import email.mime.text
import hashlib
import json
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Path bootstrap (conftest.py handles _SHARED; here we add the script dir)
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from phish_triage import (  # noqa: E402
    _defang,
    _extract_address_domain,
    _extract_urls,
    _parse_auth_results,
    _walk_attachments,
    analyze_eml,
    main,
)

SAMPLES = Path(__file__).parent / "samples"

# ---------------------------------------------------------------------------
# Integration tests — sample .eml files
# ---------------------------------------------------------------------------


def test_clean_email_no_flags():
    r = analyze_eml(SAMPLES / "clean.eml")
    assert r["flags"] == [], f"Expected no flags, got: {r['flags']}"
    assert r["headers"]["from_domain"] == "example.com"
    assert r["auth_results"]["spf"] == "pass"
    assert r["auth_results"]["dkim"] == "pass"
    assert r["auth_results"]["dmarc"] == "pass"
    assert r["summary"] == "0 flags — looks clean"


def test_clean_email_url_extracted():
    r = analyze_eml(SAMPLES / "clean.eml")
    hosts = [u["host"] for u in r["urls"]]
    assert "example.com" in hosts


def test_clean_email_defanged_url():
    r = analyze_eml(SAMPLES / "clean.eml")
    for u in r["urls"]:
        assert "hxxp" in u["defanged"]
        assert "[.]" in u["defanged"]


def test_spoofed_email_fires_expected_flags():
    r = analyze_eml(SAMPLES / "spoofed.eml")
    assert "from_returnpath_mismatch" in r["flags"]
    assert "dmarc_fail" in r["flags"]
    assert any(f.startswith("url_shortener:bit.ly") for f in r["flags"])
    assert any(f.startswith("executable_attachment:") for f in r["flags"])


def test_spoofed_email_auth_verdicts():
    r = analyze_eml(SAMPLES / "spoofed.eml")
    assert r["auth_results"]["spf"] == "fail"
    assert r["auth_results"]["dkim"] == "fail"
    assert r["auth_results"]["dmarc"] == "fail"


def test_spoofed_email_attachment_present():
    r = analyze_eml(SAMPLES / "spoofed.eml")
    assert len(r["attachments"]) == 1
    att = r["attachments"][0]
    assert att["filename"] == "invoice.docm"
    assert att["sha256"] != ""
    assert att["size"] > 0


def test_spoofed_email_replyto_mismatch():
    r = analyze_eml(SAMPLES / "spoofed.eml")
    assert "from_replyto_mismatch" in r["flags"]


# ---------------------------------------------------------------------------
# Unit tests — helpers
# ---------------------------------------------------------------------------


def test_defang_http():
    assert _defang("http://evil.com/x") == "hxxp://evil[.]com/x"


def test_defang_https():
    assert _defang("https://evil.com/x") == "hxxps://evil[.]com/x"


def test_extract_address_domain_basic():
    _raw, domain = _extract_address_domain("user@example.com")
    assert domain == "example.com"


def test_extract_address_domain_with_display_name():
    raw, domain = _extract_address_domain("Bob <bob@evil.com>")
    assert domain == "evil.com"
    assert "Bob" in raw


def test_extract_address_domain_empty():
    raw, domain = _extract_address_domain("")
    assert raw == ""
    assert domain == ""


def test_parse_auth_results_happy_path():
    header = (
        "mx.example.com; spf=pass smtp.mailfrom=example.com; "
        "dkim=pass header.d=example.com; dmarc=pass action=none"
    )
    result = _parse_auth_results(header)
    assert result["spf"] == "pass"
    assert result["dkim"] == "pass"
    assert result["dmarc"] == "pass"


def test_parse_auth_results_failures():
    header = "mx.example.com; spf=fail; dkim=fail; dmarc=fail"
    result = _parse_auth_results(header)
    assert result["spf"] == "fail"
    assert result["dkim"] == "fail"
    assert result["dmarc"] == "fail"


def test_parse_auth_results_missing_defaults_to_unknown():
    result = _parse_auth_results("")
    assert result["spf"] == "unknown"
    assert result["dkim"] == "unknown"
    assert result["dmarc"] == "unknown"


def test_url_extraction_dedupes():
    """URLs appearing multiple times should be deduplicated."""
    msg = email.message_from_string(
        "Content-Type: text/plain\n\nhttps://example.com/x https://example.com/x https://other.com/y"
    )
    urls = _extract_urls(msg)
    url_strs = [u["url"] for u in urls]
    assert url_strs.count("https://example.com/x") == 1
    assert "https://other.com/y" in url_strs


def test_url_extraction_strips_trailing_punctuation():
    msg = email.message_from_string(
        "Content-Type: text/plain\n\nVisit https://example.com/page. for info."
    )
    urls = _extract_urls(msg)
    assert urls[0]["url"] == "https://example.com/page"


def test_attachment_sha256_stable():
    """Constructing a multipart message with known payload yields stable sha256."""
    payload = b"hello world"
    expected_hash = hashlib.sha256(payload).hexdigest()

    msg = email.mime.multipart.MIMEMultipart()
    part = email.mime.base.MIMEBase("application", "octet-stream")
    part.set_payload(payload)
    email.encoders.encode_base64(part)
    part.add_header("Content-Disposition", "attachment", filename="test.bin")
    msg.attach(part)

    # Round-trip through string so it's a proper Message object
    raw = msg.as_bytes()
    parsed = email.parser.BytesParser(policy=email.policy.default).parsebytes(raw)

    attachments = _walk_attachments(parsed)
    assert len(attachments) == 1
    assert attachments[0]["sha256"] == expected_hash


def test_main_writes_out_file(tmp_path):
    out_file = tmp_path / "report.json"
    main([str(SAMPLES / "clean.eml"), "--out", str(out_file)])
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert "flags" in data
    assert "summary" in data


def test_main_missing_file_exit_2(tmp_path):
    nonexistent = tmp_path / "no_such_file.eml"
    with pytest.raises(SystemExit) as exc_info:
        main([str(nonexistent)])
    assert exc_info.value.code == 2


def test_main_stdout_output(capsys):
    main([str(SAMPLES / "clean.eml")])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["flags"] == []
