"""scriptblock_parse.py

Parse Windows PowerShell ScriptBlock log events (Event ID 4104) from EVTX
files or NDJSON (Winlogbeat-style) input.

For each event, this tool:
  - Decodes base64-encoded payloads (common in obfuscated scripts)
  - Flags obfuscation patterns (char-cast arrays, string-join tricks, etc.)
  - Extracts IOCs: IPv4 addresses, URLs, file paths, registry paths

Usage:
    python scriptblock_parse.py --input events.ndjson --output results.json
    python scriptblock_parse.py --input Security.evtx --format evtx --output results.csv
    python scriptblock_parse.py --input events.ndjson --stdout

Use --help for all options.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterator


# ---------------------------------------------------------------------------
# IOC patterns
# ---------------------------------------------------------------------------

_RE_IPV4 = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

_RE_URL = re.compile(
    r'(?i)https?://[^\s\'"<>]{4,}',
)

_RE_FILEPATH = re.compile(
    r'(?i)[A-Za-z]:\\(?:[^\\\s\'"<>|]+\\)*[^\\\s\'"<>|]+',
)

_RE_REGPATH = re.compile(
    r'(?i)HK(?:LM|CU|CR|U|CC)\\[^\s\'"<>]+',
)

# ---------------------------------------------------------------------------
# Obfuscation patterns
# ---------------------------------------------------------------------------

# [char] cast arrays like: [char]104+[char]101+[char]108...
_RE_CHAR_CAST = re.compile(r'\[char\]\d+', re.IGNORECASE)

# String splitting like: ('inv'+'oke')
_RE_STR_CONCAT = re.compile(r"'[^']*'\s*\+\s*'[^']*'")

# IEX / Invoke-Expression hiding: iex, &(gi ...), . (...)
_RE_IEX = re.compile(r'\biex\b|\binvoke-expression\b', re.IGNORECASE)

# Byte/char array construction: [byte[]](...) or [char[]]...
_RE_BYTE_ARRAY = re.compile(r'\[(?:byte|char)\[\]\]', re.IGNORECASE)

# Hex encoding: 0x41, \x41
_RE_HEX_CHARS = re.compile(r'(?:0x[0-9a-fA-F]{2}|\\x[0-9a-fA-F]{2})')

# Base64 literal strings (long b64 payloads embedded in script text)
_RE_B64_LITERAL = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')

# Net.WebClient / DownloadString / DownloadFile patterns
_RE_DOWNLOAD = re.compile(
    r'(?i)(?:net\.webclient|downloadstring|downloadfile|bitstransfer|invoke-webrequest|curl\b|wget\b)',
)

# AMSI bypass keywords
_RE_AMSI = re.compile(r'(?i)amsiutils|amsicontext|amsiinitfailed|amsi\.dll')

# Reflective loading
_RE_REFLECTIVE = re.compile(r'(?i)\[reflection\.assembly\]|\[system\.reflection\]|load\(|loadfile\(')


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ObfuscationFlags:
    char_cast: bool = False
    string_concat: bool = False
    iex: bool = False
    byte_array: bool = False
    hex_chars: bool = False
    base64_literal: bool = False
    download: bool = False
    amsi_bypass: bool = False
    reflective_load: bool = False

    @property
    def any(self) -> bool:
        return any(vars(self).values())

    @property
    def score(self) -> int:
        """Rough suspicion score — more flags = more interesting."""
        return sum(1 for v in vars(self).values() if v)


@dataclass
class ScriptBlockResult:
    event_record_id: str
    time_created: str
    computer: str
    user_id: str
    path: str                        # script path if available
    script_preview: str              # first 200 chars of decoded text
    decoded: bool                    # was any base64 decoded?
    obfuscation: ObfuscationFlags = field(default_factory=ObfuscationFlags)
    iocs_ipv4: list[str] = field(default_factory=list)
    iocs_urls: list[str] = field(default_factory=list)
    iocs_filepaths: list[str] = field(default_factory=list)
    iocs_regpaths: list[str] = field(default_factory=list)
    flagged: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        d['obfuscation'] = asdict(self.obfuscation)
        d['obfuscation_score'] = self.obfuscation.score
        return d


# ---------------------------------------------------------------------------
# Base64 decode helpers
# ---------------------------------------------------------------------------

def _try_decode_b64(text: str) -> str | None:
    """Try to decode a string as base64.  Returns the decoded text or None.

    Tries UTF-8 first (strict — fails fast on non-UTF-8 bytes), then
    UTF-16LE which is what PowerShell's -EncodedCommand uses.
    Latin-1 is intentionally skipped because it accepts any byte sequence
    and produces too many false positives.
    """
    try:
        padded = text + '=' * ((-len(text)) % 4)
        raw = base64.b64decode(padded)
    except binascii.Error:
        return None

    for encoding in ('utf-8', 'utf-16-le'):
        try:
            decoded = raw.decode(encoding)
            # Require a high ratio of printable chars to avoid treating binary
            # blobs as valid text.  Control chars other than \t \n \r don't count.
            printable = sum(1 for c in decoded if c.isprintable() or c in '\r\n\t')
            if printable / max(len(decoded), 1) >= 0.85:
                return decoded
        except UnicodeDecodeError:
            continue
    return None


def _decode_b64_payloads(text: str) -> tuple[str, bool]:
    """Find and replace base64 blobs in the text.  Returns (expanded_text, was_decoded)."""
    decoded_any = False

    def replace_match(m: re.Match) -> str:
        nonlocal decoded_any
        blob = m.group(0)
        result = _try_decode_b64(blob)
        if result:
            decoded_any = True
            return f'[DECODED:{result}]'
        return blob

    expanded = _RE_B64_LITERAL.sub(replace_match, text)
    return expanded, decoded_any


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def _extract_iocs(text: str) -> tuple[list[str], list[str], list[str], list[str]]:
    """Return (ips, urls, filepaths, regpaths) extracted from text."""
    ips       = list({m for m in _RE_IPV4.findall(text) if not m.startswith('127.')})
    urls      = list({m for m in _RE_URL.findall(text)})
    filepaths = list({m for m in _RE_FILEPATH.findall(text)})
    regpaths  = list({m for m in _RE_REGPATH.findall(text)})
    return ips, urls, filepaths, regpaths


def _detect_obfuscation(text: str) -> ObfuscationFlags:
    flags = ObfuscationFlags()
    flags.char_cast       = bool(_RE_CHAR_CAST.search(text))
    flags.string_concat   = bool(_RE_STR_CONCAT.search(text))
    flags.iex             = bool(_RE_IEX.search(text))
    flags.byte_array      = bool(_RE_BYTE_ARRAY.search(text))
    flags.hex_chars       = bool(_RE_HEX_CHARS.search(text))
    flags.base64_literal  = bool(_RE_B64_LITERAL.search(text))
    flags.download        = bool(_RE_DOWNLOAD.search(text))
    flags.amsi_bypass     = bool(_RE_AMSI.search(text))
    flags.reflective_load = bool(_RE_REFLECTIVE.search(text))
    return flags


def analyse_script_text(
    script_text: str,
    event_record_id: str = '',
    time_created: str = '',
    computer: str = '',
    user_id: str = '',
    path: str = '',
) -> ScriptBlockResult:
    """Analyse a single ScriptBlock text and return a ScriptBlockResult."""
    expanded, decoded = _decode_b64_payloads(script_text)
    obf = _detect_obfuscation(expanded)
    ips, urls, files, regs = _extract_iocs(expanded)

    flagged = obf.score >= 2 or bool(ips) or bool(urls) or obf.amsi_bypass or obf.reflective_load

    preview = (expanded[:200] + '…') if len(expanded) > 200 else expanded
    preview = preview.replace('\n', ' ').replace('\r', '')

    return ScriptBlockResult(
        event_record_id=event_record_id,
        time_created=time_created,
        computer=computer,
        user_id=user_id,
        path=path,
        script_preview=preview,
        decoded=decoded,
        obfuscation=obf,
        iocs_ipv4=ips,
        iocs_urls=urls,
        iocs_filepaths=files,
        iocs_regpaths=regs,
        flagged=flagged,
    )


# ---------------------------------------------------------------------------
# Input readers
# ---------------------------------------------------------------------------

def _iter_ndjson(path: Path) -> Iterator[ScriptBlockResult]:
    """Yield results from a Winlogbeat-style NDJSON file."""
    with path.open('r', encoding='utf-8') as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError as exc:
                sys.stderr.write(f'[warn] line {lineno}: JSON parse error: {exc}\n')
                continue

            # Support both raw WinEvent shape and Winlogbeat/ECS shape
            event_id = (
                doc.get('event', {}).get('code') or
                doc.get('winlog', {}).get('event_id') or
                doc.get('EventID') or
                doc.get('event_id')
            )
            if str(event_id) != '4104':
                continue

            # Extract common fields
            record_id = str(
                doc.get('winlog', {}).get('record_id') or
                doc.get('EventRecordID') or
                ''
            )
            time = (
                doc.get('@timestamp') or
                doc.get('TimeCreated') or
                doc.get('timestamp') or
                ''
            )
            computer = (
                doc.get('winlog', {}).get('computer_name') or
                doc.get('computer') or
                doc.get('Computer') or
                ''
            )
            user_id = (
                doc.get('winlog', {}).get('user', {}).get('identifier') or
                doc.get('user_id') or
                doc.get('UserID') or
                ''
            )

            # Script text — nested under event_data in Winlogbeat, or EventData.Data in raw
            event_data = (
                doc.get('winlog', {}).get('event_data') or
                doc.get('EventData', {}) or
                {}
            )
            script_text = (
                event_data.get('ScriptBlockText') or
                event_data.get('scriptblocktext') or
                ''
            )
            script_path = (
                event_data.get('Path') or
                event_data.get('path') or
                ''
            )

            if not script_text:
                continue

            yield analyse_script_text(
                script_text=script_text,
                event_record_id=record_id,
                time_created=time,
                computer=computer,
                user_id=user_id,
                path=script_path,
            )


def _iter_evtx(path: Path) -> Iterator[ScriptBlockResult]:
    """Yield results from an EVTX file using the python-evtx library."""
    try:
        import Evtx.Evtx as evtx      # type: ignore[import]
        import Evtx.Views as evtxview  # type: ignore[import]
    except ImportError:
        sys.stderr.write(
            '[error] python-evtx is not installed.  Install it with: pip install python-evtx\n'
        )
        sys.exit(1)

    import xml.etree.ElementTree as ET

    NS = 'http://schemas.microsoft.com/win/2004/08/events/event'

    def find(root: ET.Element, tag: str) -> str:
        el = root.find(f'.//{{{NS}}}{tag}')
        return el.text or '' if el is not None else ''

    def find_data(root: ET.Element, name: str) -> str:
        for el in root.findall(f'.//{{{NS}}}Data'):
            if el.get('Name') == name:
                return el.text or ''
        return ''

    with evtx.Evtx(str(path)) as log:
        for record in log.records():
            try:
                xml_str = record.xml()
                root = ET.fromstring(xml_str)
            except Exception:
                continue

            event_id_el = root.find(f'.//{{{NS}}}EventID')
            if event_id_el is None or event_id_el.text != '4104':
                continue

            script_text = find_data(root, 'ScriptBlockText')
            if not script_text:
                continue

            yield analyse_script_text(
                script_text=script_text,
                event_record_id=find(root, 'EventRecordID'),
                time_created=find(root, 'TimeCreated'),
                computer=find(root, 'Computer'),
                user_id=find(root, 'UserID'),
                path=find_data(root, 'Path'),
            )


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

def _write_json(results: list[ScriptBlockResult], path: Path) -> None:
    with path.open('w', encoding='utf-8') as fh:
        json.dump([r.to_dict() for r in results], fh, indent=2, default=str)


def _write_csv(results: list[ScriptBlockResult], path: Path) -> None:
    import csv
    if not results:
        path.write_text('', encoding='utf-8')
        return
    flat = [r.to_dict() for r in results]
    # Flatten nested obfuscation dict and list fields for CSV
    rows = []
    for d in flat:
        row = {k: v for k, v in d.items() if not isinstance(v, (dict, list))}
        obf = d.get('obfuscation', {})
        for k, v in obf.items():
            row[f'obf_{k}'] = v
        row['iocs_ipv4']      = '; '.join(d.get('iocs_ipv4', []))
        row['iocs_urls']      = '; '.join(d.get('iocs_urls', []))
        row['iocs_filepaths'] = '; '.join(d.get('iocs_filepaths', []))
        row['iocs_regpaths']  = '; '.join(d.get('iocs_regpaths', []))
        rows.append(row)

    fieldnames = list(rows[0].keys())
    with path.open('w', encoding='utf-8', newline='') as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _write_ndjson(results: list[ScriptBlockResult], path: Path) -> None:
    with path.open('w', encoding='utf-8') as fh:
        for r in results:
            fh.write(json.dumps(r.to_dict(), default=str) + '\n')


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='scriptblock_parse',
        description='Parse PowerShell ScriptBlock (4104) events, decode base64, flag obfuscation, extract IOCs.',
    )
    p.add_argument('--input', '-i', required=True, help='Input file (NDJSON or EVTX)')
    p.add_argument(
        '--format', '-f', choices=['ndjson', 'evtx'], default='ndjson',
        help='Input format (default: ndjson)',
    )
    p.add_argument('--output', '-o', help='Output file (.json, .csv, or .ndjson)')
    p.add_argument(
        '--flagged-only', action='store_true',
        help='Only include events that triggered at least one flag',
    )
    p.add_argument(
        '--min-score', type=int, default=0,
        help='Only include events with an obfuscation score >= this value',
    )
    p.add_argument(
        '--stdout', action='store_true',
        help='Print a summary table to stdout regardless of --output',
    )
    p.add_argument(
        '--no-iocs', action='store_true',
        help='Skip IOC extraction (faster on large files)',
    )
    return p


def _print_summary(results: list[ScriptBlockResult]) -> None:
    flagged = [r for r in results if r.flagged]
    print(f'\n{"─"*60}')
    print(f'  Total events parsed : {len(results)}')
    print(f'  Flagged             : {len(flagged)}')
    print(f'{"─"*60}')
    if not flagged:
        print('  No flagged events.')
        return
    print(f'  {"Time":<24} {"Score":>5}  {"Computer":<16}  Preview')
    print(f'  {"─"*22:<24} {"─"*5:>5}  {"─"*14:<16}  {"─"*30}')
    for r in flagged[:25]:
        preview = r.script_preview[:50].replace('\n', ' ')
        score   = r.obfuscation.score
        print(f'  {r.time_created[:24]:<24} {score:>5}  {r.computer[:16]:<16}  {preview}')
    if len(flagged) > 25:
        print(f'  … and {len(flagged) - 25} more.')
    print()


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    if not input_path.exists():
        sys.stderr.write(f'[error] Input file not found: {input_path}\n')
        return 1

    reader = _iter_ndjson if args.format == 'ndjson' else _iter_evtx

    results: list[ScriptBlockResult] = []
    for result in reader(input_path):
        if args.flagged_only and not result.flagged:
            continue
        if result.obfuscation.score < args.min_score:
            continue
        results.append(result)

    if args.stdout or not args.output:
        _print_summary(results)

    if args.output:
        out = Path(args.output)
        ext = out.suffix.lower()
        if ext == '.json':
            _write_json(results, out)
        elif ext == '.csv':
            _write_csv(results, out)
        elif ext == '.ndjson':
            _write_ndjson(results, out)
        else:
            sys.stderr.write(f'[error] Unknown output extension "{ext}". Use .json, .csv, or .ndjson.\n')
            return 1
        sys.stderr.write(f'[info] Wrote {len(results)} records to {out}\n')

    return 0


if __name__ == '__main__':
    sys.exit(main())
