---
name: Invoke-QuickTriage
role: SecurityAnalyst
tactic_folder: Triage
language: PowerShell
difficulty: beginner
status: in-progress
entry_point: Invoke-QuickTriage.ps1
requires:
  PowerShell: 7.2+
  Modules: []
  Privileges: non-elevated is fine; a few sections need admin to fully populate
frameworks:
  mitre_attack:
    tactic: TA0007
    techniques: []
  nist_800_53: [IR-4, SI-4, AU-6]
inputs:
  - ComputerName: string[] (default localhost; remote not implemented yet)
  - OutFile: string (default ./QuickTriage-<host>-<yyyyMMdd-HHmm>.md)
  - Skip: string[] (section names to skip)
  - MaxItems: int (default 20)
outputs:
  - Markdown file at -OutFile
  - PSCustomObject: { HostName, RunTime, SectionCount, FlagCount, OutFile }
---

# Invoke-QuickTriage

Run this on a box you're suspicious about. It pulls together the usual
first-response checks and dumps them into a single Markdown file you can
scroll through or hand off.

## Sections

| Section | What it shows | Needs admin? |
|---|---|---|
| Host | OS, build, uptime, last boot | no |
| Sessions | Who's logged on right now (`quser`) | no |
| Processes | Every process with its path and signer; unsigned stuff from writable locations gets flagged | partial |
| Listeners | Open TCP ports and what's owning them; flags high ports from sketchy paths | partial |
| RecentPersistence | Services and scheduled tasks created in the last 30 days | admin helps |
| DropsiteFiles | Executables/scripts that showed up in `%TEMP%`, `%APPDATA%`, `%PROGRAMDATA%` in the last week | no |
| Defender | Real-time protection status + recent threat detections | admin |
| PSHistory | Last ~20 ScriptBlock (4104) events | admin + ScriptBlock logging on |
| AdminMembership | Who's in the local Administrators group | no |

Sections that can't run (no elevation, feature disabled, etc.) record a note in the report and move on — they don't throw.

## Flag heuristics

Items marked ⚠ in the report are things worth following up on, not necessarily bad:

- **Process**: unsigned or not Microsoft-signed, *and* running from somewhere like `%TEMP%` or `%APPDATA%`.
- **Listener**: high port (≥1024) owned by a process that isn't living under `Program Files` or `System32`.
- **Recent service**: created in the last 30 days with a non-Microsoft signer.

The flag count shows up in the report header and in the summary object the script returns.

## Usage

```powershell
# Just run it — report lands in the current directory
Invoke-QuickTriage

# Skip the sections that need admin, keep it quick
Invoke-QuickTriage -OutFile .\triage.md -Skip PSHistory,Defender -MaxItems 10

# Grab the flag count without opening the file
$r = Invoke-QuickTriage -OutFile .\triage.md
$r.FlagCount
```

## Output

Markdown file, one `## SectionName` per section. Flagged sections get ⚠ in
the heading and a bold count of how many rows were flagged.

The script also returns a summary object:

```
HostName     : WIN11-VM
RunTime      : 00:00:04.1298734
SectionCount : 9
FlagCount    : 2
OutFile      : C:\...\QuickTriage-WIN11-VM-20260415-1207.md
```

## Running the tests

```powershell
Invoke-Pester .\Invoke-QuickTriage.Tests.ps1 -Output Detailed
```

The integration test (`-Tag Integration`) actually runs against localhost, skipping the slow/admin-only sections.

## Known gaps

- **Localhost only for now.** `-ComputerName` accepts input but falls back to localhost with a warning. Remote execution is on the roadmap.
- **Markdown output only.** An HTML version with color-coded flags would be nice — not there yet.
- **`quser` parsing is fragile.** If you're on a non-English locale, the column parsing might mis-split. It fails gracefully but the data won't be there.
- **`Get-ArtifactCollect`** (the full artifact grab script) is separate — see the Triage folder.
