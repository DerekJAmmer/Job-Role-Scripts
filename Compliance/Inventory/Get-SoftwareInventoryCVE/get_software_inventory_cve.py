"""get_software_inventory_cve.py

Enumerate installed software via winget or the Windows registry, look up
known CVEs from the NVD 2.0 API, and emit a CSV report.

Usage:
    python get_software_inventory_cve.py --source winget --output report.csv
    python get_software_inventory_cve.py --source registry --output report.csv --dry-run
    python get_software_inventory_cve.py --source winget --output report.csv --cache .cache/cve.json

Use --help for all options.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_USER_AGENT = "get-software-inventory-cve/0.1"
_HTTP_TIMEOUT = 30
_DEFAULT_CACHE = ".cache/cve.json"
_DEFAULT_RATE_LIMIT = 5.0  # requests per second
_CSV_COLUMNS = ["Name", "Version", "Publisher", "CVE_IDs", "MaxCVSS", "MaxSeverity"]

# ---------------------------------------------------------------------------
# Subprocess collection helpers
# ---------------------------------------------------------------------------

_WINGET_HEADER_SENTINEL = "---"  # line of dashes that separates header from data


def collect_inventory_winget() -> list[dict]:
    """Run ``winget list`` via subprocess, parse text output.

    Returns a list of dicts with keys: name, version, publisher.
    Raises RuntimeError if winget exits non-zero.
    """
    result = subprocess.run(
        ["winget", "list"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"winget exited with code {result.returncode}: {result.stderr.strip()}"
        )

    rows: list[dict] = []
    past_header = False
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if not past_header:
            # The separator line is all dashes/hyphens (at least 3 chars wide)
            if stripped.startswith(_WINGET_HEADER_SENTINEL) or (
                stripped and all(c == "-" for c in stripped)
            ):
                past_header = True
            continue
        if not stripped:
            continue
        # winget list uses fixed-width columns; split on 2+ consecutive spaces
        parts = [p.strip() for p in re.split(r" {2,}", line) if p.strip()]
        if len(parts) >= 1:
            name = parts[0] if len(parts) > 0 else ""
            version = parts[1] if len(parts) > 1 else ""
            publisher = parts[2] if len(parts) > 2 else ""
            if name:
                rows.append({"name": name, "version": version, "publisher": publisher})
    return rows


def collect_inventory_registry() -> list[dict]:
    """Read HKLM uninstall keys via PowerShell and parse JSON output.

    Returns a list of dicts with keys: name, version, publisher.
    Raises RuntimeError if PowerShell exits non-zero.
    """
    ps_cmd = (
        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' "
        "| Select-Object DisplayName, DisplayVersion, Publisher "
        "| ConvertTo-Json -Depth 2"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps_cmd],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"PowerShell exited with code {result.returncode}: {result.stderr.strip()}"
        )

    raw = result.stdout.strip()
    if not raw:
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Could not parse PowerShell JSON output: {exc}") from exc

    # PowerShell returns a single object (not array) when only 1 entry is found
    if isinstance(data, dict):
        data = [data]

    rows: list[dict] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        name = (item.get("DisplayName") or "").strip()
        if not name:
            continue
        rows.append(
            {
                "name": name,
                "version": (item.get("DisplayVersion") or "").strip(),
                "publisher": (item.get("Publisher") or "").strip(),
            }
        )
    return rows


# ---------------------------------------------------------------------------
# NVD CVE lookup with caching and rate limiting
# ---------------------------------------------------------------------------

_last_call_time: float = 0.0  # module-level sentinel for rate limiting


def _extract_cvss(metrics: dict) -> tuple[float | None, str | None]:
    """Extract the highest CVSS base score and corresponding severity.

    Tries v3.1, then v3.0, then v2 in order.
    Returns (score, severity) or (None, None) if none present.
    """
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            entry = entries[0]
            cvss_data = entry.get("cvssData", {})
            score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity")
            if score is not None:
                return float(score), severity
    return None, None


def lookup_cves(
    name: str,
    version: str,
    *,
    cache: dict,
    rate_limit: float,
    _now: Any = time.monotonic,
) -> dict:
    """Query NVD 2.0 with a keyword search.

    Uses *cache* (mutated in-place) to avoid repeated HTTP calls.
    Respects *rate_limit* (requests per second).
    Returns a dict with keys: cve_ids (list), max_cvss (float|None), max_severity (str|None).
    """
    global _last_call_time

    cache_key = f"{name}::{version}"
    if cache_key in cache:
        return {
            "cve_ids": cache[cache_key].get("cve_ids", []),
            "max_cvss": cache[cache_key].get("max_cvss"),
            "max_severity": cache[cache_key].get("max_severity"),
        }

    # Rate limiting
    now = _now()
    gap = now - _last_call_time
    min_gap = 1.0 / rate_limit if rate_limit > 0 else 0.0
    if gap < min_gap:
        time.sleep(min_gap - gap)
    _last_call_time = _now()

    keyword = urllib.parse.quote(f"{name} {version}")
    url = f"{_NVD_URL}?keywordSearch={keyword}&resultsPerPage=20"
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})

    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
            body = resp.read().decode("utf-8")
        data = json.loads(body)
    except Exception as exc:
        sys.stderr.write(f"[warning] NVD lookup failed for {name!r}: {exc}\n")
        return {"cve_ids": [], "max_cvss": None, "max_severity": None}

    vulnerabilities = data.get("vulnerabilities", [])
    cve_ids: list[str] = []
    best_score: float | None = None
    best_severity: str | None = None

    for vuln in vulnerabilities:
        cve = vuln.get("cve", {})
        cve_id = cve.get("id")
        if cve_id:
            cve_ids.append(cve_id)
        metrics = cve.get("metrics", {})
        score, severity = _extract_cvss(metrics)
        if score is not None and (best_score is None or score > best_score):
            best_score = score
            best_severity = severity

    result = {
        "cve_ids": cve_ids,
        "max_cvss": best_score,
        "max_severity": best_severity,
    }

    cache[cache_key] = {
        **result,
        "fetched_at": datetime.now(UTC).isoformat(),
    }
    return result


# ---------------------------------------------------------------------------
# Cache I/O
# ---------------------------------------------------------------------------


def _load_cache(cache_path: Path) -> dict:
    """Load the JSON cache from *cache_path*.

    Returns an empty dict if the file doesn't exist or contains invalid JSON.
    """
    if not cache_path.exists():
        return {}
    try:
        return json.loads(cache_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        sys.stderr.write(f"[warning] Could not read cache {cache_path}: {exc} — starting empty\n")
        return {}


def _save_cache(cache: dict, cache_path: Path) -> None:
    """Persist *cache* to *cache_path*, creating parent directories as needed."""
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(cache, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------


def build_report(
    inventory: list[dict],
    *,
    cache_path: Path,
    rate_limit: float,
    dry_run: bool,
    verbose: bool,
) -> list[dict]:
    """Compose the final report rows.

    Each row: Name, Version, Publisher, CVE_IDs, MaxCVSS, MaxSeverity.
    In dry-run mode the CVE columns are empty strings.
    """
    cache = _load_cache(cache_path)
    rows: list[dict] = []

    for item in inventory:
        name = item.get("name", "")
        version = item.get("version", "")
        publisher = item.get("publisher", "")

        if dry_run:
            cve_ids_str = ""
            max_cvss = ""
            max_severity = ""
        else:
            if verbose:
                sys.stderr.write(f"[info] Looking up CVEs for {name!r} {version!r}\n")
            cve_result = lookup_cves(
                name,
                version,
                cache=cache,
                rate_limit=rate_limit,
            )
            _save_cache(cache, cache_path)
            cve_ids_str = ";".join(cve_result["cve_ids"])
            max_cvss = "" if cve_result["max_cvss"] is None else str(cve_result["max_cvss"])
            max_severity = cve_result["max_severity"] or ""

        rows.append(
            {
                "Name": name,
                "Version": version,
                "Publisher": publisher,
                "CVE_IDs": cve_ids_str,
                "MaxCVSS": max_cvss,
                "MaxSeverity": max_severity,
            }
        )

    return rows


# ---------------------------------------------------------------------------
# CSV writer
# ---------------------------------------------------------------------------


def write_csv(rows: list[dict], output_path: Path) -> None:
    """Write *rows* to *output_path* as a UTF-8 CSV with the standard columns."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="get_software_inventory_cve",
        description=(
            "Enumerate installed software and look up known CVEs from NVD 2.0. "
            "Outputs a CSV with CVE IDs, max CVSS score, and severity per package."
        ),
    )
    p.add_argument(
        "--source",
        choices=["winget", "registry"],
        required=True,
        help="Collection method: 'winget' (winget list) or 'registry' (PowerShell/HKLM).",
    )
    p.add_argument(
        "--output",
        metavar="PATH",
        required=True,
        help="CSV output file path.",
    )
    p.add_argument(
        "--cache",
        metavar="PATH",
        default=_DEFAULT_CACHE,
        help=f"JSON cache file for CVE lookups (default: {_DEFAULT_CACHE}).",
    )
    p.add_argument(
        "--rate-limit",
        metavar="FLOAT",
        type=float,
        default=_DEFAULT_RATE_LIMIT,
        help=f"Max NVD API requests per second (default: {_DEFAULT_RATE_LIMIT}).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Collect inventory but skip CVE lookups; CVE columns will be empty.",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Print progress messages to stderr.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    """Argparse entrypoint. Returns exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Collect inventory
    try:
        if args.source == "winget":
            if args.verbose:
                sys.stderr.write("[info] Collecting inventory via winget...\n")
            inventory = collect_inventory_winget()
        else:
            if args.verbose:
                sys.stderr.write("[info] Collecting inventory via registry...\n")
            inventory = collect_inventory_registry()
    except RuntimeError as exc:
        sys.stderr.write(f"[error] {exc}\n")
        return 1

    if args.verbose:
        sys.stderr.write(f"[info] Found {len(inventory)} installed packages.\n")

    # Build report
    rows = build_report(
        inventory,
        cache_path=Path(args.cache),
        rate_limit=args.rate_limit,
        dry_run=args.dry_run,
        verbose=args.verbose,
    )

    # Write output
    write_csv(rows, Path(args.output))
    if args.verbose:
        sys.stderr.write(f"[info] Wrote {len(rows)} rows to {args.output}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
