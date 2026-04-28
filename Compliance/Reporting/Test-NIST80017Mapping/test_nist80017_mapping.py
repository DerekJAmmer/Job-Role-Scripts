"""test_nist80017_mapping.py

pytest suite for nist80017_mapping.py.
All I/O uses tmp_path — no network, no subprocess.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Ensure the script module is importable when running pytest from the folder
sys.path.insert(0, str(Path(__file__).parent))

from nist80017_mapping import (
    _FAMILIES,
    FamilyStats,
    aggregate,
    load_findings,
    load_mapping,
    main,
    render_html,
    render_markdown,
)

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

_MINIMAL_CIS_MAP = {
    "1.1.1": ["3.5.7"],
    "17.1.1": ["3.3.1", "3.3.2"],
    "18.9.47.2": ["3.14.2"],
}

_MINIMAL_STIG_MAP = {
    "V-253256": ["3.4.6", "3.13.8"],
    "V-253428": ["3.14.2", "3.14.4"],
    "V-253466": ["3.3.1", "3.3.2"],
}


def _write_map(tmp_path: Path, name: str, data: dict) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def _write_findings(tmp_path: Path, name: str, data: list) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def _all_stats() -> dict:
    return {fid: FamilyStats(fid, title) for fid, title in _FAMILIES.items()}


# ---------------------------------------------------------------------------
# 1. Load mapping happy path
# ---------------------------------------------------------------------------


def test_load_mapping_happy_path(tmp_path):
    p = _write_map(tmp_path, "map.json", _MINIMAL_CIS_MAP)
    result = load_mapping(p)
    assert result["1.1.1"] == ["3.5.7"]
    assert result["17.1.1"] == ["3.3.1", "3.3.2"]


# ---------------------------------------------------------------------------
# 2. Malformed mapping JSON -> SystemExit with clear message
# ---------------------------------------------------------------------------


def test_load_mapping_malformed_json(tmp_path, capsys):
    p = tmp_path / "bad.json"
    p.write_text("{not valid json{{", encoding="utf-8")
    with pytest.raises(SystemExit):
        load_mapping(p)
    captured = capsys.readouterr()
    assert "error" in captured.err.lower() or "malformed" in captured.err.lower()


# ---------------------------------------------------------------------------
# 3. Missing mapping file -> SystemExit with clear message
# ---------------------------------------------------------------------------


def test_load_mapping_missing_file(tmp_path, capsys):
    p = tmp_path / "nonexistent.json"
    with pytest.raises(SystemExit):
        load_mapping(p)
    captured = capsys.readouterr()
    assert "error" in captured.err.lower()


# ---------------------------------------------------------------------------
# 4. CIS-only input rolls up correctly
# ---------------------------------------------------------------------------


def test_cis_only_rollup(tmp_path):
    cis_findings = [
        {"ControlId": "1.1.1", "Title": "Enforce pwd history", "Status": "Compliant"},
        {"ControlId": "17.1.1", "Title": "Audit Credential Validation", "Status": "NonCompliant"},
    ]
    stats, unmapped = aggregate(
        cis_findings, [], _MINIMAL_CIS_MAP, _MINIMAL_STIG_MAP
    )
    # 1.1.1 -> 3.5.7 -> family 3.5
    assert stats["3.5"].compliant == 1
    assert stats["3.5"].non_compliant == 0
    # 17.1.1 -> 3.3.1, 3.3.2 -> both go to 3.3
    assert stats["3.3"].non_compliant == 2
    assert unmapped == []


# ---------------------------------------------------------------------------
# 5. STIG-only input rolls up correctly
# ---------------------------------------------------------------------------


def test_stig_only_rollup(tmp_path):
    stig_findings = [
        {"VulnId": "V-253256", "Title": "SMBv1 client disabled", "Status": "NotAFinding"},
        {"VulnId": "V-253428", "Title": "Defender real-time", "Status": "Open"},
    ]
    stats, unmapped = aggregate(
        [], stig_findings, _MINIMAL_CIS_MAP, _MINIMAL_STIG_MAP
    )
    # V-253256 -> 3.4.6, 3.13.8 -> compliant each
    assert stats["3.4"].compliant == 1
    assert stats["3.13"].compliant == 1
    # V-253428 -> 3.14.2, 3.14.4 -> non_compliant each
    assert stats["3.14"].non_compliant == 2
    assert unmapped == []


# ---------------------------------------------------------------------------
# 6. Both inputs combine (counts add)
# ---------------------------------------------------------------------------


def test_both_inputs_combine():
    cis_findings = [
        {"ControlId": "17.1.1", "Title": "Audit Cred Val", "Status": "Compliant"},
    ]
    stig_findings = [
        {"VulnId": "V-253466", "Title": "PS Script Block Logging", "Status": "NotAFinding"},
    ]
    stats, _ = aggregate(cis_findings, stig_findings, _MINIMAL_CIS_MAP, _MINIMAL_STIG_MAP)
    # CIS 17.1.1 -> 3.3.1, 3.3.2 (2 compliant hits)
    # STIG V-253466 -> 3.3.1, 3.3.2 (2 more compliant hits)
    assert stats["3.3"].compliant == 4


# ---------------------------------------------------------------------------
# 7. Family rollup: 3 NonCompliant + 2 Compliant -> pct = 40%
# ---------------------------------------------------------------------------


def test_pct_compliant_calculation():
    fs = FamilyStats("3.3", "Audit and Accountability")
    fs.compliant = 2
    fs.non_compliant = 3
    fs.manual = 0
    assert fs.pct_compliant == 40
    assert fs.total_findings == 5


# ---------------------------------------------------------------------------
# 8. NotCovered family renders with "No findings" in Markdown
# ---------------------------------------------------------------------------


def test_not_covered_family_in_markdown():
    stats = _all_stats()
    # Leave all families at 0
    md = render_markdown(stats, [], "2026-01-01T00:00:00Z")
    # The 3.2 family should appear in the detail section with the "No findings" message
    assert "No findings map to this family yet." in md
    # Summary row should show N/A for pct
    assert "N/A" in md


# ---------------------------------------------------------------------------
# 9. SUMMARY row filtered out
# ---------------------------------------------------------------------------


def test_summary_row_filtered(tmp_path):
    findings = [
        {"ControlId": "SUMMARY", "Title": "Summary", "Status": "Compliant:3 NonCompliant:1"},
        {"ControlId": "1.1.1", "Title": "Password history", "Status": "Compliant"},
    ]
    p = _write_findings(tmp_path, "cis.json", findings)
    loaded = load_findings(p, "CIS")
    ids = [r["ControlId"] for r in loaded]
    assert "SUMMARY" not in ids
    assert "1.1.1" in ids


# ---------------------------------------------------------------------------
# 10. CIS Manual contributes to Manual count, not Compliant
# ---------------------------------------------------------------------------


def test_cis_manual_counts_as_manual():
    cis_findings = [
        {"ControlId": "18.9.47.2", "Title": "ASR rules", "Status": "Manual"},
    ]
    stats, _ = aggregate(cis_findings, [], _MINIMAL_CIS_MAP, _MINIMAL_STIG_MAP)
    # 18.9.47.2 -> 3.14.2 -> family 3.14
    assert stats["3.14"].manual == 1
    assert stats["3.14"].compliant == 0
    assert stats["3.14"].non_compliant == 0


# ---------------------------------------------------------------------------
# 11. STIG Open contributes to NonCompliant count
# ---------------------------------------------------------------------------


def test_stig_open_is_noncompliant():
    stig_findings = [
        {"VulnId": "V-253256", "Title": "SMBv1 client", "Status": "Open"},
    ]
    stats, _ = aggregate([], stig_findings, _MINIMAL_CIS_MAP, _MINIMAL_STIG_MAP)
    # V-253256 -> 3.4.6, 3.13.8
    assert stats["3.4"].non_compliant == 1
    assert stats["3.13"].non_compliant == 1


# ---------------------------------------------------------------------------
# 12. STIG NotApplicable excluded from all counts
# ---------------------------------------------------------------------------


def test_stig_not_applicable_excluded():
    stig_findings = [
        {"VulnId": "V-253256", "Title": "SMBv1 client", "Status": "NotApplicable"},
    ]
    stats, _ = aggregate([], stig_findings, _MINIMAL_CIS_MAP, _MINIMAL_STIG_MAP)
    assert stats["3.4"].total_findings == 0
    assert stats["3.13"].total_findings == 0


# ---------------------------------------------------------------------------
# 13. STIG Error excluded; count stays 0
# ---------------------------------------------------------------------------


def test_stig_error_excluded():
    stig_findings = [
        {"VulnId": "V-253256", "Title": "SMBv1 client", "Status": "Error"},
    ]
    stats, _ = aggregate([], stig_findings, _MINIMAL_CIS_MAP, _MINIMAL_STIG_MAP)
    assert stats["3.4"].total_findings == 0
    assert stats["3.13"].total_findings == 0


# ---------------------------------------------------------------------------
# 14. Markdown contains family title headers and summary table
# ---------------------------------------------------------------------------


def test_markdown_structure():
    stats = _all_stats()
    stats["3.3"].compliant = 2
    stats["3.3"].non_compliant = 1
    stats["3.3"].findings = [
        {"id": "17.1.1", "title": "Audit", "status": "Compliant", "source": "CIS"},
    ]
    md = render_markdown(stats, ["cis.json"], "2026-01-01T00:00:00Z")
    assert "# NIST 800-171 r2 Coverage Report" in md
    assert "## Summary" in md
    assert "## 3.3 Audit and Accountability" in md
    assert "| Family | Title |" in md


# ---------------------------------------------------------------------------
# 15. HTML escapes <>/& in user content
# ---------------------------------------------------------------------------


def test_html_escapes_user_content():
    stats = _all_stats()
    stats["3.3"].compliant = 1
    stats["3.3"].findings = [
        {
            "id": "X-1",
            "title": "<script>alert('xss')</script>",
            "status": "Compliant",
            "source": "CIS",
        }
    ]
    html_out = render_html(stats, ["<evil>&source"], "2026-01-01T00:00:00Z")
    assert "<script>" not in html_out
    assert "&lt;script&gt;" in html_out
    assert "&amp;" in html_out
    assert "<table>" in html_out


# ---------------------------------------------------------------------------
# 16. --dry-run writes nothing to disk
# ---------------------------------------------------------------------------


def test_dry_run_writes_nothing(tmp_path):
    cis_map = _write_map(tmp_path, "cis_map.json", _MINIMAL_CIS_MAP)
    stig_map = _write_map(tmp_path, "stig_map.json", _MINIMAL_STIG_MAP)
    cis_file = _write_findings(tmp_path, "cis.json", [
        {"ControlId": "1.1.1", "Title": "pwd hist", "Status": "Compliant"},
    ])
    out_md = tmp_path / "report.md"
    out_html = tmp_path / "report.html"

    rc = main([
        "--cis", str(cis_file),
        "--cis-map", str(cis_map),
        "--stig-map", str(stig_map),
        "--output", str(out_md),
        "--html", str(out_html),
        "--dry-run",
    ])
    assert rc == 0
    assert not out_md.exists()
    assert not out_html.exists()


# ---------------------------------------------------------------------------
# 17. Neither --cis nor --stig -> SystemExit code 2
# ---------------------------------------------------------------------------


def test_required_arg_validation():
    with pytest.raises(SystemExit) as exc_info:
        main([])
    assert exc_info.value.code == 2


# ---------------------------------------------------------------------------
# 18. Unknown CIS id -> finding excluded, warning to stderr
# ---------------------------------------------------------------------------


def test_unknown_cis_id_warns(capsys):
    cis_findings = [
        {"ControlId": "99.9.9", "Title": "Unknown control", "Status": "Compliant"},
    ]
    stats, unmapped = aggregate(cis_findings, [], _MINIMAL_CIS_MAP, _MINIMAL_STIG_MAP)
    assert "99.9.9" in unmapped
    # All family counts should be 0
    for fs in stats.values():
        assert fs.total_findings == 0


def test_unknown_cis_id_warns_stderr(tmp_path, capsys):
    cis_map = _write_map(tmp_path, "cis_map.json", _MINIMAL_CIS_MAP)
    stig_map = _write_map(tmp_path, "stig_map.json", _MINIMAL_STIG_MAP)
    cis_file = _write_findings(tmp_path, "cis.json", [
        {"ControlId": "99.9.9", "Title": "Unknown", "Status": "Compliant"},
    ])
    main([
        "--cis", str(cis_file),
        "--cis-map", str(cis_map),
        "--stig-map", str(stig_map),
        "--dry-run",
    ])
    captured = capsys.readouterr()
    assert "99.9.9" in captured.err
    assert "warning" in captured.err.lower()


# ---------------------------------------------------------------------------
# 19. Empty findings list -> all families NotCovered
# ---------------------------------------------------------------------------


def test_empty_findings_all_not_covered():
    stats, unmapped = aggregate([], [], _MINIMAL_CIS_MAP, _MINIMAL_STIG_MAP)
    for fs in stats.values():
        assert fs.not_covered
    assert unmapped == []


# ---------------------------------------------------------------------------
# 20. CLI integration: main() returns 0 on success
# ---------------------------------------------------------------------------


def test_main_returns_zero_on_success(tmp_path):
    cis_map = _write_map(tmp_path, "cis_map.json", _MINIMAL_CIS_MAP)
    stig_map = _write_map(tmp_path, "stig_map.json", _MINIMAL_STIG_MAP)
    cis_file = _write_findings(tmp_path, "cis.json", [
        {"ControlId": "1.1.1", "Title": "pwd hist", "Status": "Compliant"},
        {"ControlId": "17.1.1", "Title": "audit cred val", "Status": "NonCompliant"},
    ])
    stig_file = _write_findings(tmp_path, "stig.json", [
        {"VulnId": "V-253256", "Title": "SMBv1 client", "Status": "NotAFinding"},
    ])
    out_md = tmp_path / "report.md"
    out_html = tmp_path / "report.html"

    rc = main([
        "--cis", str(cis_file),
        "--stig", str(stig_file),
        "--cis-map", str(cis_map),
        "--stig-map", str(stig_map),
        "--output", str(out_md),
        "--html", str(out_html),
    ])
    assert rc == 0
    assert out_md.exists()
    assert out_html.exists()
    md_text = out_md.read_text(encoding="utf-8")
    assert "# NIST 800-171 r2 Coverage Report" in md_text
    html_text = out_html.read_text(encoding="utf-8")
    assert "<table>" in html_text
