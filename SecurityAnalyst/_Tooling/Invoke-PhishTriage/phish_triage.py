"""phish_triage.py

Triage a suspicious .eml file: parse headers, extract and defang URLs,
hash attachments, flag red flags, and produce a JSON report.

Usage:
    python phish_triage.py <path-to-eml>
    python phish_triage.py <path-to-eml> --out report.json

Exit codes:
    0 — success
    2 — file not found / not a file
    3 — parse error
"""

from __future__ import annotations

import argparse
import email
import email.parser
import email.policy
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# sa_common bootstrap — must come before any sa_common import
# ---------------------------------------------------------------------------
_SHARED = Path(__file__).resolve().parents[2] / "_SHARED" / "Python"
if str(_SHARED) not in sys.path:
    sys.path.insert(0, str(_SHARED))

from sa_common.io import write_json  # noqa: E402
from sa_common.log import get_logger  # noqa: E402

log = get_logger("phish_triage")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_KNOWN_SHORTENERS: frozenset[str] = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "t.co",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "rebrand.ly",
        "cutt.ly",
        "shorturl.at",
    }
)

_EXECUTABLE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".exe",
        ".scr",
        ".js",
        ".vbs",
        ".lnk",
        ".iso",
        ".docm",
        ".xlsm",
        ".pptm",
        ".zip",
        ".rar",
        ".7z",
        ".bat",
        ".cmd",
        ".ps1",
        ".jar",
        ".hta",
    }
)

_URL_RE = re.compile(r"https?://[^\s<>\"\')\]]+", re.IGNORECASE)
_AUTH_VERDICT_RE = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)", re.IGNORECASE
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_email(path: str | Path) -> email.message.Message:
    """Parse a .eml file using BytesParser with RFC-compliant policy."""
    with open(path, "rb") as fh:
        return email.parser.BytesParser(policy=email.policy.default).parse(fh)


def _extract_address_domain(addr_str: str) -> tuple[str, str]:
    """Return (raw_address, domain) from an address string.

    Returns ("", "") when the input is empty or unparseable.
    """
    if not addr_str:
        return ("", "")
    addr_str = addr_str.strip()
    if not addr_str:
        return ("", "")

    # Use email.headerregistry to extract the addr-spec
    try:
        # Try angle-bracket form: "Display <user@domain>"
        match = re.search(r"<([^>]+)>", addr_str)
        addr_spec = match.group(1).strip() if match else addr_str.strip()

        if "@" not in addr_spec:
            return (addr_str, "")

        domain = addr_spec.rsplit("@", 1)[1].strip().lower()
        return (addr_str, domain)
    except Exception:
        return ("", "")


def _parse_auth_results(value: str) -> dict[str, str]:
    """Extract SPF/DKIM/DMARC verdicts from an Authentication-Results header value.

    Returns dict with keys spf, dkim, dmarc, each defaulting to "unknown".
    """
    result: dict[str, str] = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}
    if not value:
        return result

    for match in _AUTH_VERDICT_RE.finditer(value):
        key = match.group(1).lower()
        verdict = match.group(2).lower()
        if key in result:
            result[key] = verdict

    return result


def _defang(url: str) -> str:
    """Defang a URL: hxxp(s)://host[.]domain/..."""
    # Replace protocol
    defanged = re.sub(r"^http", "hxxp", url, flags=re.IGNORECASE)
    # Replace dots in host portion only: split on // then replace dots in the host
    # Simpler: replace all dots with [.]
    defanged = defanged.replace(".", "[.]")
    return defanged


def _strip_trailing_punctuation(url: str) -> str:
    """Strip trailing punctuation characters that are unlikely part of the URL."""
    return url.rstrip(".,;:!?")


def _extract_urls(message: email.message.Message) -> list[dict[str, Any]]:
    """Walk message parts, collect URLs from text/plain and text/html bodies.

    Returns list of dicts with url, defanged, is_shortener, host.
    Deduplicates preserving first-seen order. Caps at 100.
    """
    seen: dict[str, None] = {}  # ordered set via dict
    raw_urls: list[str] = []

    for part in message.walk():
        ct = part.get_content_type()
        if ct not in ("text/plain", "text/html"):
            continue
        try:
            # get_content() is only available on EmailMessage (policy=default).
            # Fall back to get_payload() for legacy Message objects (e.g. in tests).
            if hasattr(part, "get_content"):
                body = part.get_content()
                if not isinstance(body, str):
                    body = body.decode("utf-8", errors="replace")
            else:
                raw_payload = part.get_payload(decode=True)
                if raw_payload is None:
                    raw_payload = part.get_payload()
                if isinstance(raw_payload, bytes):
                    body = raw_payload.decode("utf-8", errors="replace")
                elif isinstance(raw_payload, str):
                    body = raw_payload
                else:
                    continue
        except Exception:
            continue

        for raw in _URL_RE.findall(body):
            url = _strip_trailing_punctuation(raw)
            if url and url not in seen:
                seen[url] = None
                raw_urls.append(url)
                if len(raw_urls) >= 100:
                    break
        if len(raw_urls) >= 100:
            break

    result: list[dict[str, Any]] = []
    for url in raw_urls:
        parsed = urlparse(url)
        # strip fragment
        clean_url = parsed._replace(fragment="").geturl()
        host = parsed.hostname or ""
        result.append(
            {
                "url": clean_url,
                "defanged": _defang(clean_url),
                "is_shortener": host.lower() in _KNOWN_SHORTENERS,
                "host": host.lower(),
            }
        )

    return result


def _walk_attachments(
    message: email.message.Message,
) -> list[dict[str, Any]]:
    """Return attachment info: filename, content_type, size, sha256."""
    attachments: list[dict[str, Any]] = []

    for part in message.walk():
        filename = part.get_filename()
        if not filename:
            continue

        payload_bytes = part.get_payload(decode=True)
        if payload_bytes is None:
            payload_bytes = b""

        sha256 = hashlib.sha256(payload_bytes).hexdigest()
        content_type = part.get_content_type()
        size = len(payload_bytes)

        attachments.append(
            {
                "filename": filename,
                "content_type": content_type,
                "size": size,
                "sha256": sha256,
            }
        )

    return attachments


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------


def analyze_eml(path: str | Path) -> dict[str, Any]:
    """Parse a .eml file and return a triage report dict."""
    path = Path(path)
    msg = _parse_email(path)

    # --- Headers ---
    from_raw = str(msg.get("From") or "")
    return_path_raw = str(msg.get("Return-Path") or "")
    reply_to_raw = str(msg.get("Reply-To") or "")
    subject = str(msg.get("Subject") or "")

    from_full, from_domain = _extract_address_domain(from_raw)
    rp_full, rp_domain = _extract_address_domain(return_path_raw)
    rt_full, rt_domain = _extract_address_domain(reply_to_raw)

    # Received chain
    received_headers = msg.get_all("Received") or []
    received_hops = len(received_headers)
    first_received_at = str(received_headers[-1]) if received_headers else ""

    headers_info: dict[str, Any] = {
        "from": from_full,
        "from_domain": from_domain,
        "return_path": rp_full,
        "return_path_domain": rp_domain,
        "reply_to": rt_full,
        "reply_to_domain": rt_domain,
        "subject": subject,
        "received_chain_hops": received_hops,
        "first_received_at": first_received_at,
    }

    # --- Auth Results ---
    auth_raw = str(msg.get("Authentication-Results") or "")
    auth_verdicts = _parse_auth_results(auth_raw)
    auth_results: dict[str, Any] = {
        "spf": auth_verdicts["spf"],
        "dkim": auth_verdicts["dkim"],
        "dmarc": auth_verdicts["dmarc"],
        "raw": auth_raw,
    }

    # --- URLs ---
    urls = _extract_urls(msg)

    # --- Attachments ---
    attachments = _walk_attachments(msg)

    # --- Red-flag rules ---
    flags: list[str] = []

    if from_domain and rp_domain and from_domain.lower() != rp_domain.lower():
        flags.append("from_returnpath_mismatch")

    if from_domain and rt_domain and from_domain.lower() != rt_domain.lower():
        flags.append("from_replyto_mismatch")

    if auth_verdicts["spf"] in {"fail", "softfail"}:
        flags.append("spf_fail")

    if auth_verdicts["dkim"] == "fail":
        flags.append("dkim_fail")

    if auth_verdicts["dmarc"] in {"fail", "reject", "quarantine"}:
        flags.append("dmarc_fail")

    for u in urls:
        if u["is_shortener"]:
            flags.append(f"url_shortener:{u['host']}")

    for att in attachments:
        ext = Path(att["filename"]).suffix.lower()
        if ext in _EXECUTABLE_EXTENSIONS:
            flags.append(f"executable_attachment:{att['filename']}")

    # --- Summary ---
    if flags:
        joined = ", ".join(flags[:5])
        ellipsis = "..." if len(flags) > 5 else ""
        summary = f"{len(flags)} flag(s): {joined}{ellipsis}"
    else:
        summary = "0 flags — looks clean"

    return {
        "source": str(path),
        "headers": headers_info,
        "auth_results": auth_results,
        "urls": urls,
        "attachments": attachments,
        "flags": flags,
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phish_triage.py",
        description="Triage a suspicious .eml file and produce a JSON report.",
    )
    parser.add_argument("eml", metavar="PATH", help="Path to the .eml file.")
    parser.add_argument(
        "--out",
        metavar="FILE",
        help="Write JSON report to FILE (default: stdout).",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)

    eml_path = Path(args.eml)
    if not eml_path.exists() or not eml_path.is_file():
        log.error("File not found: %s", eml_path)
        sys.exit(2)

    try:
        report = analyze_eml(eml_path)
    except Exception as exc:
        log.error("Failed to parse %s: %s", eml_path, exc)
        sys.exit(3)

    if args.out:
        out_path = Path(args.out)
        write_json(out_path, report)
        log.info("wrote report to %s", out_path)
        print(report["summary"])
    else:
        print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
