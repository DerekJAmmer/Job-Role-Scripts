"""get_ioc_intel.py

Enrich IOCs (IP, domain, URL, hash) against VirusTotal, AbuseIPDB, and
AlienVault OTX.  API keys come from environment variables; missing keys
cause that provider to be skipped with a warning.

Usage:
    python get_ioc_intel.py --ioc 1.2.3.4
    python get_ioc_intel.py --batch iocs.csv --out results.json
    python get_ioc_intel.py --ioc evil.com --dry-run
    python get_ioc_intel.py --ioc deadbeef... --providers vt,otx

Use --help for all options.
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# sa_common bootstrap — must come before any sa_common import
# ---------------------------------------------------------------------------
_SHARED = Path(__file__).resolve().parents[2] / "_SHARED" / "Python"
if str(_SHARED) not in sys.path:
    sys.path.insert(0, str(_SHARED))

import requests  # noqa: E402
from sa_common.io import write_json  # noqa: E402
from sa_common.log import get_logger  # noqa: E402

log = get_logger("ioc_intel")

# ---------------------------------------------------------------------------
# IOC type detection
# ---------------------------------------------------------------------------

_HEX64 = re.compile(r"^[a-fA-F0-9]{64}$")
_HEX40 = re.compile(r"^[a-fA-F0-9]{40}$")
_HEX32 = re.compile(r"^[a-fA-F0-9]{32}$")
_IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_URL = re.compile(r"^https?://", re.IGNORECASE)
_DOMAIN = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def detect_ioc_type(value: str) -> str:
    """Detect whether *value* is sha256/sha1/md5/ipv4/url/domain.

    Raises ValueError if none match.
    """
    v = value.strip()
    if _HEX64.match(v):
        return "sha256"
    if _HEX40.match(v):
        return "sha1"
    if _HEX32.match(v):
        return "md5"
    if _IPV4.match(v) and all(0 <= int(o) <= 255 for o in v.split(".")):
        return "ipv4"
    if _URL.match(v):
        return "url"
    if _DOMAIN.match(v):
        return "domain"
    raise ValueError(f"Could not detect IOC type for: {value!r}")


# ---------------------------------------------------------------------------
# Low-level HTTP helper with 429 retry
# ---------------------------------------------------------------------------


def _do_get(
    session: requests.Session,
    url: str,
    headers: dict | None = None,
    params: dict | None = None,
    max_retries: int = 3,
) -> requests.Response:
    """GET *url*, retrying up to *max_retries* times on HTTP 429."""
    resp: requests.Response | None = None
    for _attempt in range(max_retries):
        resp = session.get(url, headers=headers, params=params, timeout=15)
        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", "2"))
            time.sleep(min(retry_after, 30))
            continue
        return resp
    return resp  # type: ignore[return-value]  # last response after retries


# ---------------------------------------------------------------------------
# Provider: VirusTotal v3
# ---------------------------------------------------------------------------

_VT_BASE = "https://www.virustotal.com/api/v3"

# IOC type → VT collection path segment
_VT_COLLECTION: dict[str, str] = {
    "ipv4": "ip_addresses",
    "domain": "domains",
    "sha256": "files",
    "sha1": "files",
    "md5": "files",
    "url": "urls",
}


def _vt_url(ioc: str, ioc_type: str) -> str:
    collection = _VT_COLLECTION[ioc_type]
    if ioc_type == "url":
        encoded = base64.urlsafe_b64encode(ioc.encode()).rstrip(b"=").decode()
        return f"{_VT_BASE}/{collection}/{encoded}"
    return f"{_VT_BASE}/{collection}/{ioc}"


def query_virustotal(
    ioc: str,
    ioc_type: str,
    *,
    session: requests.Session | None = None,
    dry_run: bool = False,
) -> dict[str, Any] | None:
    """Query VirusTotal v3.  Returns a result dict or None on skip/error."""
    if dry_run:
        return {
            "provider": "virustotal",
            "ioc": ioc,
            "type": ioc_type,
            "stats": {"malicious": 5, "suspicious": 1, "harmless": 60, "undetected": 4},
            "raw_status": 200,
            "dry_run": True,
        }

    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        log.warning("VT_API_KEY not set — skipping virustotal")
        return None

    if ioc_type not in _VT_COLLECTION:
        return None

    sess = session or requests.Session()
    url = _vt_url(ioc, ioc_type)
    headers = {"x-apikey": api_key}

    try:
        resp = _do_get(sess, url, headers=headers)
    except requests.RequestException as exc:
        log.error("virustotal request failed: %s", exc)
        return None

    if resp.status_code == 404:
        return {"provider": "virustotal", "ioc": ioc, "type": ioc_type, "stats": {}, "raw_status": 404}
    if resp.status_code != 200:
        log.warning("virustotal returned %d for %r", resp.status_code, ioc)
        return {"provider": "virustotal", "ioc": ioc, "type": ioc_type, "stats": {}, "raw_status": resp.status_code}

    data = resp.json()
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return {
        "provider": "virustotal",
        "ioc": ioc,
        "type": ioc_type,
        "stats": {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        },
        "raw_status": resp.status_code,
    }


# ---------------------------------------------------------------------------
# Provider: AbuseIPDB v2
# ---------------------------------------------------------------------------

_ABUSEIPDB_CHECK = "https://api.abuseipdb.com/api/v2/check"


def query_abuseipdb(
    ioc: str,
    ioc_type: str,
    *,
    session: requests.Session | None = None,
    dry_run: bool = False,
) -> dict[str, Any] | None:
    """Query AbuseIPDB.  IPv4 only; returns None silently for other types."""
    if ioc_type != "ipv4":
        return None

    if dry_run:
        return {
            "provider": "abuseipdb",
            "ioc": ioc,
            "type": ioc_type,
            "abuseConfidenceScore": 85,
            "totalReports": 42,
            "lastReportedAt": "2024-01-01T00:00:00+00:00",
            "countryCode": "RU",
            "raw_status": 200,
            "dry_run": True,
        }

    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        log.warning("ABUSEIPDB_API_KEY not set — skipping abuseipdb")
        return None

    sess = session or requests.Session()
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ioc, "maxAgeInDays": "90"}

    try:
        resp = _do_get(sess, _ABUSEIPDB_CHECK, headers=headers, params=params)
    except requests.RequestException as exc:
        log.error("abuseipdb request failed: %s", exc)
        return None

    if resp.status_code != 200:
        log.warning("abuseipdb returned %d for %r", resp.status_code, ioc)
        return {"provider": "abuseipdb", "ioc": ioc, "type": ioc_type, "raw_status": resp.status_code}

    data = resp.json().get("data", {})
    return {
        "provider": "abuseipdb",
        "ioc": ioc,
        "type": ioc_type,
        "abuseConfidenceScore": data.get("abuseConfidenceScore"),
        "totalReports": data.get("totalReports"),
        "lastReportedAt": data.get("lastReportedAt"),
        "countryCode": data.get("countryCode"),
        "raw_status": resp.status_code,
    }


# ---------------------------------------------------------------------------
# Provider: AlienVault OTX
# ---------------------------------------------------------------------------

_OTX_BASE = "https://otx.alienvault.com/api/v1/indicators"

_OTX_SECTION: dict[str, str] = {
    "ipv4": "IPv4",
    "domain": "domain",
    "url": "url",
    "sha256": "file",
    "sha1": "file",
    "md5": "file",
}


def query_otx(
    ioc: str,
    ioc_type: str,
    *,
    session: requests.Session | None = None,
    dry_run: bool = False,
) -> dict[str, Any] | None:
    """Query AlienVault OTX general endpoint."""
    if dry_run:
        return {
            "provider": "otx",
            "ioc": ioc,
            "type": ioc_type,
            "pulse_count": 3,
            "reputation": 0,
            "raw_status": 200,
            "dry_run": True,
        }

    api_key = os.environ.get("OTX_API_KEY")
    if not api_key:
        log.warning("OTX_API_KEY not set — skipping otx")
        return None

    if ioc_type not in _OTX_SECTION:
        return None

    section = _OTX_SECTION[ioc_type]
    url = f"{_OTX_BASE}/{section}/{ioc}/general"
    headers = {"X-OTX-API-KEY": api_key}
    sess = session or requests.Session()

    try:
        resp = _do_get(sess, url, headers=headers)
    except requests.RequestException as exc:
        log.error("otx request failed: %s", exc)
        return None

    if resp.status_code != 200:
        log.warning("otx returned %d for %r", resp.status_code, ioc)
        return {"provider": "otx", "ioc": ioc, "type": ioc_type, "raw_status": resp.status_code}

    data = resp.json()
    pulse_count = data.get("pulse_info", {}).get("count", 0)
    return {
        "provider": "otx",
        "ioc": ioc,
        "type": ioc_type,
        "pulse_count": pulse_count,
        "reputation": data.get("reputation", 0),
        "raw_status": resp.status_code,
    }


# ---------------------------------------------------------------------------
# Enrichment orchestration
# ---------------------------------------------------------------------------

_PROVIDERS: dict[str, Any] = {
    "vt": query_virustotal,
    "abuseipdb": query_abuseipdb,
    "otx": query_otx,
}


def enrich(
    ioc: str,
    ioc_type: str,
    *,
    providers: list[str],
    dry_run: bool = False,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    """Run all requested providers against a single IOC and return a merged result."""
    results: list[dict] = []
    sess = session or requests.Session()
    for name in providers:
        fn = _PROVIDERS.get(name)
        if fn is None:
            log.warning("Unknown provider %r — skipping", name)
            continue
        result = fn(ioc, ioc_type, session=sess, dry_run=dry_run)
        if result is not None:
            results.append(result)

    return {
        "ioc": ioc,
        "type": ioc_type,
        "providers": results,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="get_ioc_intel",
        description="Enrich IOCs against VirusTotal, AbuseIPDB, and AlienVault OTX.",
    )
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--ioc", metavar="VALUE", help="Single IOC to enrich (type auto-detected).")
    mode.add_argument("--batch", metavar="FILE", help="CSV file with a 'value' column (optional 'type').")
    p.add_argument(
        "--providers",
        metavar="LIST",
        default="vt,abuseipdb,otx",
        help="Comma-separated list of providers (default: vt,abuseipdb,otx).",
    )
    p.add_argument("--out", metavar="FILE", help="Write JSON to file instead of stdout.")
    p.add_argument("--dry-run", action="store_true", help="Return canned responses without making HTTP calls.")
    return p


def _parse_providers(raw: str) -> list[str]:
    return [p.strip() for p in raw.split(",") if p.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    providers = _parse_providers(args.providers)
    dry_run: bool = args.dry_run
    session = requests.Session()

    # ---- single IOC mode ----
    if args.ioc:
        try:
            ioc_type = detect_ioc_type(args.ioc)
        except ValueError as exc:
            sys.stderr.write(f"[error] {exc}\n")
            return 1

        if not dry_run and not any(os.environ.get(k) for k in ("VT_API_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY")):
            sys.stderr.write("[error] No API keys are set and --dry-run was not specified. Nothing to do.\n")
            return 2

        payload = enrich(args.ioc, ioc_type, providers=providers, dry_run=dry_run, session=session)

        if args.out:
            write_json(args.out, payload)
            log.info("Wrote 1 entry to %s", args.out)
        else:
            print(json.dumps(payload, indent=2))
        return 0

    # ---- batch mode ----
    batch_path = Path(args.batch)
    if not batch_path.exists():
        sys.stderr.write(f"[error] Batch file not found: {batch_path}\n")
        return 1

    records: list[dict] = []
    with batch_path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            raw_ioc = row.get("value", "").strip()
            if not raw_ioc:
                continue
            raw_type = row.get("type", "").strip()
            try:
                ioc_type = raw_type if raw_type else detect_ioc_type(raw_ioc)
            except ValueError as exc:
                log.warning("Skipping %r: %s", raw_ioc, exc)
                continue
            records.append({"ioc": raw_ioc, "type": ioc_type})

    if not records:
        sys.stderr.write("[error] No valid IOCs found in batch file.\n")
        return 1

    if not dry_run and not any(os.environ.get(k) for k in ("VT_API_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY")):
        sys.stderr.write("[error] No API keys are set and --dry-run was not specified. Nothing to do.\n")
        return 2

    results = [
        enrich(r["ioc"], r["type"], providers=providers, dry_run=dry_run, session=session)
        for r in records
    ]

    if args.out:
        write_json(args.out, results)
        log.info("Wrote %d entries to %s", len(results), args.out)
    else:
        print(json.dumps(results, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
