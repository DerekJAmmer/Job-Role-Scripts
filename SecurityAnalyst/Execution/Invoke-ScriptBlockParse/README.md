---
name: Invoke-ScriptBlockParse
role: SecurityAnalyst
tactic_folder: Execution
language: Python
difficulty: intermediate
status: in-progress
entry_point: scriptblock_parse.py
requires:
  Python: 3.10+
  Packages: []
  Packages_optional: [python-evtx (for EVTX input)]
frameworks:
  mitre_attack:
    tactic: TA0002
    techniques: [T1059.001, T1027, T1027.010, T1059.003]
  nist_800_53: [AU-6, SI-4, SI-3]
inputs:
  - --input: path to NDJSON or EVTX file
  - --format: ndjson (default) or evtx
  - --output: output file (.json, .csv, or .ndjson)
  - --flagged-only: only include events that triggered a flag
  - --min-score: only include events with obfuscation score >= N
  - --stdout: print summary table to terminal
outputs:
  - JSON / CSV / NDJSON report at --output
  - Summary table to stdout (with --stdout or when --output is omitted)
---

# Invoke-ScriptBlockParse

Parse Windows PowerShell ScriptBlock log events (Event ID 4104), decode any embedded base64, flag obfuscation patterns, and pull out IOCs.

Works with Winlogbeat-style NDJSON exports or raw EVTX files. EVTX support requires `pip install python-evtx`.

## What it flags

| Detection | What it looks for |
|---|---|
| char_cast | `[char]104+[char]101...` — character-code arrays used to hide strings |
| iex / invoke_expression | `iex` or `Invoke-Expression` — common way to execute decoded payloads |
| base64_literal | Long base64 strings embedded in the script text |
| byte_array | `[byte[]]` or `[char[]]` casts often used in shellcode loading |
| hex_chars | `0x41` or `\x41` hex escapes for string hiding |
| string_concat | `'inv'+'oke'` style string splitting |
| download | `Net.WebClient`, `DownloadString`, `Invoke-WebRequest`, etc. |
| amsi_bypass | References to AmsiUtils, amsiInitFailed, amsi.dll |
| reflective_load | `[Reflection.Assembly]`, `.Load(`, reflective injection patterns |

Each flag adds 1 to the obfuscation score. Events with a score ≥ 2, any extracted IP/URL, or AMSI/reflective patterns are marked as flagged.

## Usage

```bash
# Basic run — prints summary to stdout
python scriptblock_parse.py --input events.ndjson

# Flagged events only, JSON output
python scriptblock_parse.py --input events.ndjson --flagged-only --output results.json

# CSV output for import into a spreadsheet or SIEM
python scriptblock_parse.py --input events.ndjson --output results.csv

# EVTX input (needs python-evtx)
python scriptblock_parse.py --input Security.evtx --format evtx --output results.ndjson

# Only show high-confidence hits
python scriptblock_parse.py --input events.ndjson --min-score 3 --stdout
```

## Input format

**NDJSON** — one JSON object per line. Works with Winlogbeat's default output or Elastic's winlogbeat index exports. The parser accepts both Winlogbeat ECS shape (`winlog.event_data.ScriptBlockText`) and raw Windows event shape (`EventData.ScriptBlockText`).

**EVTX** — raw Windows event log file. Install `python-evtx` first:
```bash
pip install python-evtx
```

## Output example

Terminal summary:

```
────────────────────────────────────────────────────────────
  Total events parsed : 1423
  Flagged             : 7
────────────────────────────────────────────────────────────
  Time                     Score  Computer          Preview
  ─────────────────────── ─────  ──────────────  ──────────────────────────────
  2026-04-15T02:11:34Z         5  WIN11-VM        iex ([char]105+[char]101...
  2026-04-15T02:11:38Z         4  WIN11-VM        [DECODED:Invoke-Expression...
```

JSON entry shape:

```json
{
  "event_record_id": "42",
  "time_created": "2026-04-15T02:11:34Z",
  "computer": "WIN11-VM",
  "flagged": true,
  "obfuscation_score": 5,
  "obfuscation": { "iex": true, "char_cast": true, "download": true, ... },
  "iocs_ipv4": ["10.0.0.99"],
  "iocs_urls": ["http://evil.example.com/payload.ps1"],
  "script_preview": "iex ([char]105+[char]101+..."
}
```

## Running the tests

```bash
pytest test_scriptblock_parse.py -v
```

No external dependencies needed for the tests — the EVTX path is not tested by default.

## Known gaps

- **No multi-part ScriptBlock reassembly.** Large scripts get split across multiple 4104 events. The parser handles each independently right now; reassembly is on the roadmap.
- **Base64 detection has false positives.** Long certificate strings, embedded binaries, and some module help text can trigger the base64 pattern. Use `--min-score 2` to cut noise.
- **EVTX support is read-only.** The `python-evtx` library is read-only; writing modified EVTX back isn't supported or needed, but worth noting.
