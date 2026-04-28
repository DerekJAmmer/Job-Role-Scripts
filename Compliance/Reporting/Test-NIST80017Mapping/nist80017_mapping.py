"""nist80017_mapping.py

Map CIS Benchmark and DISA STIG findings to NIST SP 800-171 r2 controls and
emit a per-family coverage report in Markdown and/or HTML.

Usage:
    python nist80017_mapping.py --cis cis-findings.json --output report.md
    python nist80017_mapping.py --stig stig-findings.json --html report.html
    python nist80017_mapping.py --cis cis.json --stig stig.json --output report.md --html report.html
    python nist80017_mapping.py --cis cis.json --dry-run

Use --help for all options.
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_FAMILIES: dict[str, str] = {
    "3.1": "Access Control",
    "3.2": "Awareness and Training",
    "3.3": "Audit and Accountability",
    "3.4": "Configuration Management",
    "3.5": "Identification and Authentication",
    "3.6": "Incident Response",
    "3.7": "Maintenance",
    "3.8": "Media Protection",
    "3.9": "Personnel Security",
    "3.10": "Physical Protection",
    "3.11": "Risk Assessment",
    "3.12": "Security Assessment",
    "3.13": "System and Communications Protection",
    "3.14": "System and Information Integrity",
}

# CIS statuses that map to Compliant / NonCompliant / Manual
_CIS_COMPLIANT = {"Compliant"}
_CIS_NONCOMPLIANT = {"NonCompliant"}
_CIS_MANUAL = {"Manual"}

# STIG statuses
_STIG_COMPLIANT = {"NotAFinding"}
_STIG_NONCOMPLIANT = {"Open"}
_STIG_MANUAL = {"Manual"}
# NotApplicable and Error are excluded from all counts (noted in README)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


class FamilyStats:
    """Aggregated statistics for one NIST 800-171 family."""

    __slots__ = ("compliant", "family_id", "findings", "manual", "non_compliant", "title")

    def __init__(self, family_id: str, title: str) -> None:
        self.family_id = family_id
        self.title = title
        self.compliant: int = 0
        self.non_compliant: int = 0
        self.manual: int = 0
        self.findings: list[dict] = []  # {id, title, status, source}

    @property
    def total_findings(self) -> int:
        return self.compliant + self.non_compliant + self.manual

    @property
    def pct_compliant(self) -> int:
        denom = self.compliant + self.non_compliant
        if denom == 0:
            return 0
        return round(self.compliant / denom * 100)

    @property
    def not_covered(self) -> bool:
        return self.total_findings == 0


# ---------------------------------------------------------------------------
# Mapping loader
# ---------------------------------------------------------------------------


def load_mapping(path: Path) -> dict[str, list[str]]:
    """Load a JSON mapping file.

    Raises SystemExit on missing file or malformed JSON.
    Returns dict mapping source id -> list of 800-171 control ids.
    """
    if not path.exists():
        sys.stderr.write(f"[error] Mapping file not found: {path}\n")
        sys.exit(1)
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"[error] Malformed JSON in mapping file {path}: {exc}\n")
        sys.exit(1)
    if not isinstance(data, dict):
        sys.stderr.write(f"[error] Mapping file {path} must be a JSON object.\n")
        sys.exit(1)
    return data


# ---------------------------------------------------------------------------
# Findings loader
# ---------------------------------------------------------------------------


def _unwrap_findings(raw: Any, source_label: str) -> list[dict]:
    """Accept a top-level list or a wrapped object with value/results/controls key."""
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        for key in ("value", "results", "controls"):
            if key in raw and isinstance(raw[key], list):
                return raw[key]
    sys.stderr.write(
        f"[error] {source_label} findings must be a JSON array or a wrapped object "
        "with a 'value', 'results', or 'controls' key.\n"
    )
    sys.exit(1)


def load_findings(path: Path, source_label: str) -> list[dict]:
    """Load findings JSON from *path*.

    Accepts a top-level array or single wrapped object.
    Filters out the SUMMARY row.
    Raises SystemExit on missing file or malformed JSON.
    """
    if not path.exists():
        sys.stderr.write(f"[error] Findings file not found: {path}\n")
        sys.exit(1)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"[error] Malformed JSON in {source_label} file {path}: {exc}\n")
        sys.exit(1)

    findings = _unwrap_findings(raw, source_label)

    # Filter SUMMARY rows
    filtered: list[dict] = []
    for row in findings:
        if not isinstance(row, dict):
            continue
        cid = str(row.get("ControlId", "") or row.get("VulnId", "")).strip().upper()
        if cid == "SUMMARY":
            continue
        filtered.append(row)
    return filtered


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def _family_for_control(control_id: str) -> str | None:
    """Return the top-level family prefix (e.g. '3.1') for a control id like '3.1.1'."""
    parts = control_id.split(".")
    if len(parts) >= 2:
        candidate = f"{parts[0]}.{parts[1]}"
        if candidate in _FAMILIES:
            return candidate
    return None


def aggregate(
    cis_findings: list[dict],
    stig_findings: list[dict],
    cis_mapping: dict[str, list[str]],
    stig_mapping: dict[str, list[str]],
) -> tuple[dict[str, FamilyStats], list[str]]:
    """Aggregate findings into per-family statistics.

    Returns:
        (family_stats, unmapped_ids) where unmapped_ids is a list of source IDs
        not found in the mapping files.
    """
    stats: dict[str, FamilyStats] = {
        fid: FamilyStats(fid, title) for fid, title in _FAMILIES.items()
    }
    unmapped: list[str] = []

    def _apply(source_id: str, title: str, status: str, source_label: str,
               mapping: dict[str, list[str]]) -> None:
        if source_id not in mapping:
            unmapped.append(source_id)
            return
        for ctrl_id in mapping[source_id]:
            family = _family_for_control(ctrl_id)
            if family is None or family not in stats:
                continue
            fs = stats[family]
            if status in _CIS_COMPLIANT or status in _STIG_COMPLIANT:
                fs.compliant += 1
            elif status in _CIS_NONCOMPLIANT or status in _STIG_NONCOMPLIANT:
                fs.non_compliant += 1
            elif status in _CIS_MANUAL or status in _STIG_MANUAL:
                fs.manual += 1
            else:
                # NotApplicable, Error, unknown → excluded
                return
            fs.findings.append({
                "id": source_id,
                "title": title,
                "status": status,
                "source": source_label,
            })

    for row in cis_findings:
        cid = str(row.get("ControlId", "")).strip()
        title = str(row.get("Title", "")).strip()
        status = str(row.get("Status", "")).strip()
        _apply(cid, title, status, "CIS", cis_mapping)

    for row in stig_findings:
        vid = str(row.get("VulnId", "")).strip()
        title = str(row.get("Title", "")).strip()
        status = str(row.get("Status", "")).strip()
        _apply(vid, title, status, "STIG", stig_mapping)

    return stats, unmapped


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------

_MD_HEADER = "# NIST 800-171 r2 Coverage Report\n"
_MD_SUMMARY_HEADER = (
    "| Family | Title | Compliant | NonCompliant | Manual | Total | % Compliant |\n"
    "|---|---|---:|---:|---:|---:|---:|\n"
)


def render_markdown(
    stats: dict[str, FamilyStats],
    sources: list[str],
    generated: str,
) -> str:
    """Render the full Markdown report as a string."""
    lines: list[str] = [
        _MD_HEADER,
        f"Generated: {generated}  \n",
        f"Sources: {', '.join(sources) if sources else '(none)'}  \n",
        "\n## Summary\n\n",
        _MD_SUMMARY_HEADER,
    ]

    for fid, fs in stats.items():
        pct = f"{fs.pct_compliant}%" if not fs.not_covered else "N/A"
        lines.append(
            f"| {fid} | {fs.title} | {fs.compliant} | {fs.non_compliant} | "
            f"{fs.manual} | {fs.total_findings} | {pct} |\n"
        )

    for fid, fs in stats.items():
        lines.append(f"\n## {fid} {fs.title}\n\n")
        if fs.not_covered:
            lines.append("No findings map to this family yet.\n")
        else:
            lines.append("| ID | Title | Status | Source |\n")
            lines.append("|---|---|---|---|\n")
            for f in fs.findings:
                lines.append(
                    f"| {f['id']} | {f['title']} | {f['status']} | {f['source']} |\n"
                )

    return "".join(lines)


# ---------------------------------------------------------------------------
# HTML renderer
# ---------------------------------------------------------------------------

_HTML_STYLE = """
body { font-family: sans-serif; margin: 2em; color: #222; }
h1 { color: #2c3e50; }
h2 { color: #34495e; border-bottom: 1px solid #ccc; padding-bottom: 4px; }
table { border-collapse: collapse; width: 100%; margin-bottom: 1.5em; }
th { background: #2c3e50; color: #fff; padding: 6px 10px; text-align: left; }
td { padding: 5px 10px; border-bottom: 1px solid #e0e0e0; }
tr:nth-child(even) td { background: #f8f8f8; }
.compliant { color: #27ae60; font-weight: bold; }
.noncompliant { color: #e74c3c; font-weight: bold; }
.manual { color: #e67e22; }
p.meta { color: #666; font-size: 0.9em; }
"""


def _status_class(status: str) -> str:
    if status in ("Compliant", "NotAFinding"):
        return "compliant"
    if status in ("NonCompliant", "Open"):
        return "noncompliant"
    return "manual"


def render_html(
    stats: dict[str, FamilyStats],
    sources: list[str],
    generated: str,
) -> str:
    """Render a minimal styled HTML report."""
    esc = html.escape

    parts: list[str] = [
        "<!DOCTYPE html>\n<html lang='en'>\n<head>\n",
        "<meta charset='UTF-8'>\n",
        "<title>NIST 800-171 r2 Coverage Report</title>\n",
        f"<style>{_HTML_STYLE}</style>\n",
        "</head>\n<body>\n",
        "<h1>NIST 800-171 r2 Coverage Report</h1>\n",
        f"<p class='meta'>Generated: {esc(generated)}</p>\n",
        f"<p class='meta'>Sources: {esc(', '.join(sources) if sources else '(none)')}</p>\n",
        "<h2>Summary</h2>\n",
        "<table>\n<tr>",
        "<th>Family</th><th>Title</th>",
        "<th>Compliant</th><th>NonCompliant</th><th>Manual</th>",
        "<th>Total</th><th>% Compliant</th></tr>\n",
    ]

    for fid, fs in stats.items():
        pct = f"{fs.pct_compliant}%" if not fs.not_covered else "N/A"
        parts.append(
            f"<tr><td>{esc(fid)}</td><td>{esc(fs.title)}</td>"
            f"<td class='compliant'>{fs.compliant}</td>"
            f"<td class='noncompliant'>{fs.non_compliant}</td>"
            f"<td class='manual'>{fs.manual}</td>"
            f"<td>{fs.total_findings}</td><td>{esc(pct)}</td></tr>\n"
        )
    parts.append("</table>\n")

    for fid, fs in stats.items():
        parts.append(f"<h2>{esc(fid)} {esc(fs.title)}</h2>\n")
        if fs.not_covered:
            parts.append("<p>No findings map to this family yet.</p>\n")
        else:
            parts.append(
                "<table>\n<tr>"
                "<th>ID</th><th>Title</th><th>Status</th><th>Source</th>"
                "</tr>\n"
            )
            for f in fs.findings:
                cls = _status_class(f["status"])
                parts.append(
                    f"<tr>"
                    f"<td>{esc(f['id'])}</td>"
                    f"<td>{esc(f['title'])}</td>"
                    f"<td class='{cls}'>{esc(f['status'])}</td>"
                    f"<td>{esc(f['source'])}</td>"
                    f"</tr>\n"
                )
            parts.append("</table>\n")

    parts.append("</body>\n</html>\n")
    return "".join(parts)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nist80017_mapping",
        description=(
            "Map CIS Benchmark and DISA STIG findings to NIST SP 800-171 r2 controls "
            "and emit a per-family coverage report."
        ),
    )
    p.add_argument(
        "--cis",
        metavar="FILE",
        help="Path to a CIS findings JSON file (output of Test-CISBenchmark).",
    )
    p.add_argument(
        "--stig",
        metavar="FILE",
        help="Path to a STIG findings JSON file (output of Test-STIGCompliance).",
    )
    p.add_argument(
        "--output",
        metavar="FILE",
        default=None,
        help="Markdown output path (default: stdout).",
    )
    p.add_argument(
        "--html",
        metavar="FILE",
        default=None,
        help="Optional HTML output path.",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print summary to stdout; write nothing to disk.",
    )
    p.add_argument(
        "--cis-map",
        metavar="FILE",
        default=None,
        help="Override path to cis_to_800171.json (default: mapping/ sibling folder).",
    )
    p.add_argument(
        "--stig-map",
        metavar="FILE",
        default=None,
        help="Override path to stig_to_800171.json (default: mapping/ sibling folder).",
    )
    return p


def _default_map_dir() -> Path:
    return Path(__file__).parent / "mapping"


def main(argv: list[str] | None = None) -> int:
    """Argparse entrypoint. Returns exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.cis and not args.stig:
        parser.error("At least one of --cis or --stig is required.")

    # Resolve mapping paths
    map_dir = _default_map_dir()
    cis_map_path = Path(args.cis_map) if args.cis_map else map_dir / "cis_to_800171.json"
    stig_map_path = Path(args.stig_map) if args.stig_map else map_dir / "stig_to_800171.json"

    cis_mapping = load_mapping(cis_map_path)
    stig_mapping = load_mapping(stig_map_path)

    # Load findings
    cis_findings: list[dict] = []
    stig_findings: list[dict] = []
    sources: list[str] = []

    if args.cis:
        cis_findings = load_findings(Path(args.cis), "CIS")
        sources.append(args.cis)

    if args.stig:
        stig_findings = load_findings(Path(args.stig), "STIG")
        sources.append(args.stig)

    # Aggregate
    stats, unmapped = aggregate(cis_findings, stig_findings, cis_mapping, stig_mapping)

    if unmapped:
        unique = sorted(set(unmapped))
        sys.stderr.write(
            f"[warning] {len(unique)} source ID(s) not found in mapping files "
            f"and excluded from family counts: {', '.join(unique)}\n"
        )

    # Render
    generated = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    md_content = render_markdown(stats, sources, generated)
    html_content = render_html(stats, sources, generated) if args.html else None

    total_findings = sum(fs.total_findings for fs in stats.values())
    covered_families = sum(1 for fs in stats.values() if not fs.not_covered)

    # --dry-run: print summary only, write nothing
    if args.dry_run:
        md_dest = args.output if args.output else "stdout"
        sys.stdout.write(f"Would write Markdown to {md_dest}\n")
        if args.html:
            sys.stdout.write(f"Would write HTML to {args.html}\n")
        sys.stdout.write(
            f"{total_findings} findings across {covered_families} families\n"
        )
        return 0

    # Write Markdown
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(md_content, encoding="utf-8")
    else:
        sys.stdout.write(md_content)

    # Write HTML if requested
    if args.html and html_content is not None:
        html_path = Path(args.html)
        html_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.write_text(html_content, encoding="utf-8")

    return 0


if __name__ == "__main__":
    sys.exit(main())
