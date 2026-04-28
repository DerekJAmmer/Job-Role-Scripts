"""test_get_software_inventory_cve.py

pytest suite for get_software_inventory_cve.py.
All subprocess and HTTP calls are mocked — no real winget, PowerShell, or NVD calls.
"""

from __future__ import annotations

import json
import subprocess
import time
import urllib.error
import urllib.request

import pytest
from get_software_inventory_cve import (
    build_report,
    collect_inventory_registry,
    collect_inventory_winget,
    lookup_cves,
    main,
    write_csv,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class FakeCompletedProcess:
    """Minimal stand-in for subprocess.CompletedProcess."""

    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


# Canned winget output — realistic fixed-width table (2+ spaces between columns)
_WINGET_OUTPUT = """\
Name                          Id                        Version    Source
--------------------------------------------------------------------------
7-Zip 22.01 (x64)             7zip.7zip                 22.01      winget
Mozilla Firefox (x64 en-US)   Mozilla.Firefox           115.0      winget
Microsoft Visual C++ 2019     Microsoft.VCRedist.x64    14.36.0    winget
"""

# Canned winget output with only the header (no data rows)
_WINGET_HEADER_ONLY = """\
Name    Id    Version    Source
------------------------------------
"""

# Canned registry JSON — array of objects
_REGISTRY_ARRAY_JSON = json.dumps(
    [
        {"DisplayName": "7-Zip 22.01", "DisplayVersion": "22.01", "Publisher": "Igor Pavlov"},
        {"DisplayName": "Python 3.11.5", "DisplayVersion": "3.11.5", "Publisher": "Python Software Foundation"},
    ]
)

# Canned registry JSON — single object (as PS does when 1 result)
_REGISTRY_SINGLE_JSON = json.dumps(
    {"DisplayName": "Git", "DisplayVersion": "2.43.0", "Publisher": "The Git Development Community"}
)

# Canned NVD API response with two CVEs, both having v3.1 metrics
_NVD_TWO_CVES = json.dumps(
    {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2023-1234",
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}
                        ]
                    },
                }
            },
            {
                "cve": {
                    "id": "CVE-2023-5678",
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                        ]
                    },
                }
            },
        ]
    }
)

# NVD response: only v3.0 metrics (no v3.1)
_NVD_V30_ONLY = json.dumps(
    {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2022-9999",
                    "metrics": {
                        "cvssMetricV30": [
                            {"cvssData": {"baseScore": 6.1, "baseSeverity": "MEDIUM"}}
                        ]
                    },
                }
            }
        ]
    }
)

# NVD response: no CVSS metrics at all
_NVD_NO_CVSS = json.dumps(
    {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-0001",
                    "metrics": {},
                }
            }
        ]
    }
)

# NVD response: empty vulnerabilities list
_NVD_EMPTY = json.dumps({"vulnerabilities": []})


# ---------------------------------------------------------------------------
# 1. collect_inventory_winget — parses sample output
# ---------------------------------------------------------------------------


def test_winget_parses_sample_output(monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: FakeCompletedProcess(stdout=_WINGET_OUTPUT),
    )
    result = collect_inventory_winget()
    assert len(result) == 3
    names = [r["name"] for r in result]
    assert "7-Zip 22.01 (x64)" in names
    assert "Mozilla Firefox (x64 en-US)" in names
    assert "Microsoft Visual C++ 2019" in names


# ---------------------------------------------------------------------------
# 2. winget header/dashes filtered correctly
# ---------------------------------------------------------------------------


def test_winget_filters_header_rows(monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: FakeCompletedProcess(stdout=_WINGET_HEADER_ONLY),
    )
    result = collect_inventory_winget()
    assert result == []


# ---------------------------------------------------------------------------
# 3. collect_inventory_registry — parses single-object JSON
# ---------------------------------------------------------------------------


def test_registry_parses_single_object(monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: FakeCompletedProcess(stdout=_REGISTRY_SINGLE_JSON),
    )
    result = collect_inventory_registry()
    assert len(result) == 1
    assert result[0]["name"] == "Git"
    assert result[0]["version"] == "2.43.0"
    assert result[0]["publisher"] == "The Git Development Community"


# ---------------------------------------------------------------------------
# 4. collect_inventory_registry — parses array JSON
# ---------------------------------------------------------------------------


def test_registry_parses_array(monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: FakeCompletedProcess(stdout=_REGISTRY_ARRAY_JSON),
    )
    result = collect_inventory_registry()
    assert len(result) == 2
    assert result[0]["name"] == "7-Zip 22.01"
    assert result[1]["name"] == "Python 3.11.5"


# ---------------------------------------------------------------------------
# 5. registry — empty/whitespace DisplayName is filtered
# ---------------------------------------------------------------------------


def test_registry_filters_empty_display_name(monkeypatch):
    data = json.dumps(
        [
            {"DisplayName": "", "DisplayVersion": "1.0", "Publisher": "X"},
            {"DisplayName": "   ", "DisplayVersion": "2.0", "Publisher": "Y"},
            {"DisplayName": "Real App", "DisplayVersion": "3.0", "Publisher": "Z"},
            {"DisplayName": None, "DisplayVersion": "4.0", "Publisher": "W"},
        ]
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: FakeCompletedProcess(stdout=data),
    )
    result = collect_inventory_registry()
    assert len(result) == 1
    assert result[0]["name"] == "Real App"


# ---------------------------------------------------------------------------
# 6. subprocess non-zero exit code raises RuntimeError
# ---------------------------------------------------------------------------


def test_winget_nonzero_exit_raises(monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: FakeCompletedProcess(
            stdout="", stderr="winget not found", returncode=1
        ),
    )
    with pytest.raises(RuntimeError, match="winget exited with code 1"):
        collect_inventory_winget()


def test_registry_nonzero_exit_raises(monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: FakeCompletedProcess(
            stdout="", stderr="Access denied", returncode=1
        ),
    )
    with pytest.raises(RuntimeError, match="PowerShell exited with code 1"):
        collect_inventory_registry()


# ---------------------------------------------------------------------------
# 7. lookup_cves cache hit — urlopen NOT called
# ---------------------------------------------------------------------------


def test_lookup_cves_cache_hit(monkeypatch):
    urlopen_called = []
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **kw: urlopen_called.append(1))

    cache = {
        "7-Zip::22.01": {
            "cve_ids": ["CVE-2023-1234"],
            "max_cvss": 7.5,
            "max_severity": "HIGH",
            "fetched_at": "2024-01-01T00:00:00+00:00",
        }
    }
    result = lookup_cves("7-Zip", "22.01", cache=cache, rate_limit=5.0)
    assert result["cve_ids"] == ["CVE-2023-1234"]
    assert result["max_cvss"] == 7.5
    assert result["max_severity"] == "HIGH"
    assert urlopen_called == [], "urlopen should NOT be called on cache hit"


# ---------------------------------------------------------------------------
# 8. lookup_cves cache miss — urlopen IS called once
# ---------------------------------------------------------------------------


class _FakeHTTPResponse:
    def __init__(self, body: str) -> None:
        self._body = body.encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass


def test_lookup_cves_cache_miss(monkeypatch):
    calls = []

    def fake_urlopen(req, timeout=None):
        calls.append(req.full_url)
        return _FakeHTTPResponse(_NVD_TWO_CVES)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(time, "sleep", lambda _: None)

    cache: dict = {}
    result = lookup_cves("7-Zip", "22.01", cache=cache, rate_limit=5.0)
    assert len(calls) == 1
    assert "7-Zip" in calls[0]
    assert "cve_ids" in result


# ---------------------------------------------------------------------------
# 9. NVD response with multiple CVEs — max_cvss is highest, joined correctly
# ---------------------------------------------------------------------------


def test_lookup_cves_multiple_cves(monkeypatch):
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda *a, **kw: _FakeHTTPResponse(_NVD_TWO_CVES),
    )
    monkeypatch.setattr(time, "sleep", lambda _: None)

    cache: dict = {}
    result = lookup_cves("SomePkg", "1.0", cache=cache, rate_limit=5.0)
    assert "CVE-2023-1234" in result["cve_ids"]
    assert "CVE-2023-5678" in result["cve_ids"]
    assert result["max_cvss"] == 9.8
    assert result["max_severity"] == "CRITICAL"


# ---------------------------------------------------------------------------
# 10. NVD response: no v3.1 but v3.0 present — fallback works
# ---------------------------------------------------------------------------


def test_lookup_cves_cvss_v30_fallback(monkeypatch):
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda *a, **kw: _FakeHTTPResponse(_NVD_V30_ONLY),
    )
    monkeypatch.setattr(time, "sleep", lambda _: None)

    cache: dict = {}
    result = lookup_cves("OldApp", "2.0", cache=cache, rate_limit=5.0)
    assert result["cve_ids"] == ["CVE-2022-9999"]
    assert result["max_cvss"] == 6.1
    assert result["max_severity"] == "MEDIUM"


# ---------------------------------------------------------------------------
# 11. NVD response: no CVSS at all — max_cvss=None, max_severity=None
# ---------------------------------------------------------------------------


def test_lookup_cves_no_cvss(monkeypatch):
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda *a, **kw: _FakeHTTPResponse(_NVD_NO_CVSS),
    )
    monkeypatch.setattr(time, "sleep", lambda _: None)

    cache: dict = {}
    result = lookup_cves("AnotherApp", "3.0", cache=cache, rate_limit=5.0)
    assert result["cve_ids"] == ["CVE-2021-0001"]
    assert result["max_cvss"] is None
    assert result["max_severity"] is None


# ---------------------------------------------------------------------------
# 12. NVD HTTP error — returns empty, warning emitted, no exception
# ---------------------------------------------------------------------------


def test_lookup_cves_http_error(monkeypatch, capsys):
    def fake_urlopen(*a, **kw):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(time, "sleep", lambda _: None)

    cache: dict = {}
    result = lookup_cves("BrokenApp", "1.0", cache=cache, rate_limit=5.0)
    assert result["cve_ids"] == []
    assert result["max_cvss"] is None
    # Warning should have gone to stderr
    captured = capsys.readouterr()
    assert "warning" in captured.err.lower() or "NVD lookup failed" in captured.err


# ---------------------------------------------------------------------------
# 13. Rate-limit pacing — sleep called with correct duration
# ---------------------------------------------------------------------------


def test_rate_limit_pacing(monkeypatch):
    """Two rapid calls with rate_limit=2 (500ms min gap) should sleep ~500ms on 2nd call."""
    import get_software_inventory_cve as mod

    sleep_calls: list[float] = []
    monkeypatch.setattr(time, "sleep", lambda s: sleep_calls.append(s))
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda *a, **kw: _FakeHTTPResponse(_NVD_EMPTY),
    )

    # Freeze a fake monotonic clock.
    # lookup_cves calls _now() twice per invocation: once for the gap check,
    # once to record _last_call_time after the call.
    # Call 1: gap_check=0.0, assign=0.5  → _last_call_time becomes 0.5
    # Call 2: gap_check=0.6, assign=0.6  → gap=0.6-0.5=0.1 < 0.5 → sleep(0.4)
    fake_times = [0.0, 0.5, 0.6, 0.6]
    fake_clock = iter(fake_times)

    def fake_now():
        return next(fake_clock)

    # Reset module-level last-call time so previous tests don't bleed in
    mod._last_call_time = 0.0

    cache: dict = {}
    lookup_cves("App1", "1.0", cache=cache, rate_limit=2.0, _now=fake_now)
    # Second call: gap_check=0.6, last=0.5 → gap=0.1, min_gap=0.5 → sleep(0.4)
    lookup_cves("App2", "2.0", cache=cache, rate_limit=2.0, _now=fake_now)

    assert len(sleep_calls) >= 1
    assert sleep_calls[-1] == pytest.approx(0.4, abs=0.05)


# ---------------------------------------------------------------------------
# 14. --dry-run: build_report skips lookup_cves; CVE columns empty
# ---------------------------------------------------------------------------


def test_dry_run_skips_cve_lookup(monkeypatch, tmp_path):
    urlopen_calls = []
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **kw: urlopen_calls.append(1))

    inventory = [{"name": "App", "version": "1.0", "publisher": "Pub"}]
    rows = build_report(
        inventory,
        cache_path=tmp_path / "cve.json",
        rate_limit=5.0,
        dry_run=True,
        verbose=False,
    )
    assert rows[0]["CVE_IDs"] == ""
    assert rows[0]["MaxCVSS"] == ""
    assert rows[0]["MaxSeverity"] == ""
    assert urlopen_calls == [], "urlopen must not be called in dry-run mode"


# ---------------------------------------------------------------------------
# 15. Cache file doesn't exist → starts empty; written after lookup
# ---------------------------------------------------------------------------


def test_cache_created_on_miss(monkeypatch, tmp_path):
    cache_path = tmp_path / "nonexistent" / "cve.json"
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda *a, **kw: _FakeHTTPResponse(_NVD_TWO_CVES),
    )
    monkeypatch.setattr(time, "sleep", lambda _: None)

    inventory = [{"name": "Pkg", "version": "1.0", "publisher": "Pub"}]
    build_report(
        inventory,
        cache_path=cache_path,
        rate_limit=5.0,
        dry_run=False,
        verbose=False,
    )
    assert cache_path.exists(), "Cache file should be created after first lookup"
    data = json.loads(cache_path.read_text(encoding="utf-8"))
    assert "Pkg::1.0" in data


# ---------------------------------------------------------------------------
# 16. Cache file with malformed JSON → warning emitted; starts empty
# ---------------------------------------------------------------------------


def test_cache_malformed_json_warns(monkeypatch, tmp_path, capsys):
    cache_path = tmp_path / "cve.json"
    cache_path.write_text("not valid json {{{", encoding="utf-8")

    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda *a, **kw: _FakeHTTPResponse(_NVD_EMPTY),
    )
    monkeypatch.setattr(time, "sleep", lambda _: None)

    inventory = [{"name": "App", "version": "1.0", "publisher": "Pub"}]
    # Should not raise; should warn and continue
    rows = build_report(
        inventory,
        cache_path=cache_path,
        rate_limit=5.0,
        dry_run=False,
        verbose=False,
    )
    captured = capsys.readouterr()
    assert "warning" in captured.err.lower()
    assert len(rows) == 1


# ---------------------------------------------------------------------------
# 17. write_csv produces expected columns
# ---------------------------------------------------------------------------


def test_write_csv_columns(tmp_path):
    rows = [
        {
            "Name": "App A",
            "Version": "1.2.3",
            "Publisher": "Acme",
            "CVE_IDs": "CVE-2023-1234;CVE-2023-5678",
            "MaxCVSS": "9.8",
            "MaxSeverity": "CRITICAL",
        }
    ]
    out = tmp_path / "report.csv"
    write_csv(rows, out)
    text = out.read_text(encoding="utf-8")
    assert "Name,Version,Publisher,CVE_IDs,MaxCVSS,MaxSeverity" in text
    assert "App A" in text
    assert "CVE-2023-1234;CVE-2023-5678" in text
    assert "9.8" in text
    assert "CRITICAL" in text


# ---------------------------------------------------------------------------
# 18. main() end-to-end --dry-run --source winget
# ---------------------------------------------------------------------------


def test_main_dry_run_winget(monkeypatch, tmp_path):
    output_path = tmp_path / "report.csv"
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: FakeCompletedProcess(stdout=_WINGET_OUTPUT),
    )

    exit_code = main(
        [
            "--source", "winget",
            "--output", str(output_path),
            "--dry-run",
            "--cache", str(tmp_path / "cve.json"),
        ]
    )
    assert exit_code == 0
    assert output_path.exists()
    text = output_path.read_text(encoding="utf-8")
    assert "Name" in text
    assert "7-Zip" in text


# ---------------------------------------------------------------------------
# 19. main() invalid --source → argparse error, returncode != 0
# ---------------------------------------------------------------------------


def test_main_invalid_source():
    with pytest.raises(SystemExit) as exc_info:
        main(["--source", "badvalue", "--output", "out.csv"])
    assert exc_info.value.code != 0


# ---------------------------------------------------------------------------
# 20. main() happy path non-dry-run (mock urlopen too)
# ---------------------------------------------------------------------------


def test_main_happy_path_with_cve_lookup(monkeypatch, tmp_path):
    output_path = tmp_path / "report.csv"
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: FakeCompletedProcess(stdout=_WINGET_OUTPUT),
    )
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda *a, **kw: _FakeHTTPResponse(_NVD_TWO_CVES),
    )
    monkeypatch.setattr(time, "sleep", lambda _: None)

    exit_code = main(
        [
            "--source", "winget",
            "--output", str(output_path),
            "--cache", str(tmp_path / "cve.json"),
            "--rate-limit", "100",
        ]
    )
    assert exit_code == 0
    assert output_path.exists()
    text = output_path.read_text(encoding="utf-8")
    assert "CVE-2023-5678" in text
