---
name: Invoke-IOCSweep
role: SecurityAnalyst
tactic_folder: Triage
language: PowerShell
difficulty: intermediate
status: in-progress
entry_point: Invoke-IOCSweep.ps1
requires:
  PowerShell: 7.2+
  Modules: []
  Privileges: non-elevated runs all four checks; admin not required
frameworks:
  mitre_attack:
    tactic: TA0007
    techniques: [T1046, T1018, T1049, T1071, T1059]
  nist_800_53: [IR-4, SI-4, AU-6]
inputs:
  - IocFile: string (CSV or JSON; type+value columns)
  - ComputerName: string (default localhost; remote not implemented)
  - OutputPath: string (default ./IOCSweep-<host>-<yyyyMMdd-HHmm>.json)
  - MaxFiles: int (default 5000)
  - Skip: string[] (Hash | Connection | Process | Dns)
outputs:
  - JSON file at -OutputPath
  - PSCustomObject: { HostName, RunTime, IocCount, FindingCount, OutputPath }
---

# Invoke-IOCSweep

You have a list of IOCs — hashes, IPs, process names, domains — and you want
to know if any of them are on a box right now. This script does that sweep
across four surfaces and writes a JSON report you can triage or feed into a
SIEM.

Run it during incident triage, after a threat intel drop, or any time you
need a quick "is this thing here?" answer.

## Detection surfaces

| Surface | What it checks | What it needs |
|---|---|---|
| Hash | SHA256s of files under common exec paths (`%ProgramData%`, `%TEMP%`, `%APPDATA%`, `%LOCALAPPDATA%`, `Users\Public`) | Read access to those paths |
| Connection | Active TCP connections whose `RemoteAddress` matches an IOC IP | `Get-NetTCPConnection` (no elevation needed) |
| Process | Running process names matched against IOC process names (`.exe` suffix ignored, case-insensitive) | `Get-Process` (no elevation needed) |
| DNS | DNS client cache entries that exactly match or are a subdomain of an IOC domain | `Get-DnsClientCache` (no elevation needed) |

## IOC file format

The file can be JSON or CSV. Each entry needs a `type` and a `value`.
Recognised types: `sha256`, `ip`, `process`, `domain`. Anything else gets
skipped with a warning.

**JSON:**
```json
[
  { "type": "sha256",  "value": "e3b0c44298fc1c149afb..." },
  { "type": "ip",      "value": "185.220.101.47" },
  { "type": "process", "value": "mimi.exe" },
  { "type": "domain",  "value": "evil-c2.example.com" }
]
```

**CSV:**
```
type,value
sha256,e3b0c44298fc1c149afb...
ip,185.220.101.47
process,mimi.exe
domain,evil-c2.example.com
```

## Usage

```powershell
# Sweep with all defaults — report lands in the current directory
Invoke-IOCSweep -IocFile .\iocs.json

# Specify the output path
Invoke-IOCSweep -IocFile .\iocs.csv -OutputPath C:\IR\sweep-results.json

# Skip the hash scan (slow on big AppData trees) and DNS
Invoke-IOCSweep -IocFile .\iocs.json -Skip Hash,Dns

# Cap the file scan at 1000 files to keep it fast
Invoke-IOCSweep -IocFile .\iocs.json -MaxFiles 1000
```

## Output

The JSON report written to `-OutputPath` looks like this:

```json
{
  "HostName":    "WIN11-BOX",
  "GeneratedAt": "2026-04-23T10:15:30.0000000+00:00",
  "IocFile":     "C:\\IR\\iocs.json",
  "IocCounts": {
    "sha256":  2,
    "ip":      5,
    "process": 1,
    "domain":  3
  },
  "Findings": [
    {
      "Category": "NetConnection",
      "Ioc":      "185.220.101.47",
      "Subject":  "185.220.101.47:443",
      "Detail":   "State=Established Local=10.0.0.5:54321 PID=1234"
    }
  ]
}
```

The script also returns a summary object:

```
HostName     : WIN11-BOX
RunTime      : 00:00:02.4187230
IocCount     : 11
FindingCount : 1
OutputPath   : C:\IR\sweep-results.json
```

## Running the tests

```powershell
Invoke-Pester .\Invoke-IOCSweep.Tests.ps1 -Output Detailed
```

The integration test (`-Tag Integration`) runs against localhost but skips all
four detection surfaces, so it's deterministic and doesn't need network access
or specific files on disk.

## Known gaps

- **Localhost only.** `-ComputerName` accepts input but warns and falls back
  to local execution. Remote sweeps via `Invoke-Command` are not wired up yet.
- **Hash scan is bounded.** `MaxFiles` (default 5000) caps how many files get
  hashed. On a noisy `%APPDATA%` it's easy to hit that ceiling — tune it or
  add targeted `-Roots` if you need full coverage.
- **DNS cache only shows what's currently cached.** Entries expire. If the
  connection happened hours ago and the TTL has expired, you won't see it here.
  Pair with network logs if you need historical coverage.
- **Hash roots are fixed.** The script scans a hard-coded set of exec-likely
  paths. Mapped drives, alternate user profiles, and custom install paths are
  not included.
