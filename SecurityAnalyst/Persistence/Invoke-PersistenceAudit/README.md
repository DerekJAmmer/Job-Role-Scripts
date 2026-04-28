---
name: Invoke-PersistenceAudit
role: SecurityAnalyst
tactic_folder: Persistence
language: PowerShell
difficulty: intermediate
status: in-progress
entry_point: Invoke-PersistenceAudit.ps1
requires:
  PowerShell: 7.2+
  Modules: []
  Privileges: non-elevated runs most checks; WMI subscriptions need admin
frameworks:
  mitre_attack:
    tactic: TA0003
    techniques: [T1547.001, T1053.005, T1543.003, T1546.003, T1547.002]
  nist_800_53: [SI-4, CM-7, AU-6]
inputs:
  - BaselinePath: string (path to baseline JSON from a previous run)
  - SaveBaseline: switch (write a baseline snapshot after collecting)
  - OutFile: string (default ./PersistenceAudit-<host>-<yyyyMMdd-HHmm>.md)
  - Skip: string[] (sections to skip)
outputs:
  - Markdown file at -OutFile
  - PSCustomObject: { HostName, RunTime, SectionCount, FlagCount, NewCount, OutFile }
---

# Invoke-PersistenceAudit

> ⚠️ **Status: Work in Progress.** Currently blocked by Windows Defender ML heuristics flagging the registry-walk patterns. Code, tests, and ATT&CK mapping are complete; AMSI/Defender suppression options are still under evaluation before this is considered shipped.


Checks all the usual places attackers hide to survive a reboot: Run keys, scheduled tasks, services, WMI event subscriptions, startup folders, and LSA notification packages.

Run it once to get a baseline, then run it again later and any new entries get flagged.

## Sections

| Section | What it checks | Needs admin? |
|---|---|---|
| RunKeys | HKLM/HKCU Run and RunOnce keys (including WOW6432Node) | no |
| ScheduledTasks | All scheduled tasks — flags unsigned executables | no |
| Services | All Win32 services — flags unsigned or missing binaries | no |
| WMISubscriptions | WMI event filter/consumer/binding subscriptions | admin |
| StartupFolders | Files in common and user startup folders | no |
| LSAPackages | Authentication and notification packages registered in LSA | no |

Anything that isn't Microsoft-signed is flagged (⚠). Anything not in the baseline is marked new (🆕).

## Flag heuristics

- **Unsigned binary** — the signer field comes back as "Unsigned" from `Get-AuthenticodeSignature`. A third-party tool being unsigned isn't automatically malicious, but it's worth a look.
- **Unknown path** — the binary referenced in the registry or task doesn't exist on disk. Could be a stale entry or a deleted tool.
- **WMI subscription** — any subscription is flagged. Legitimate software rarely uses WMI event subs; attackers love them because they persist even after task deletion.
- **Non-default LSA package** — anything not in the known-good set (msv1_0, kerberos, wdigest, etc.).

## Usage

```powershell
# Quick look — no baseline
Invoke-PersistenceAudit

# First time on a clean box — save a baseline
Invoke-PersistenceAudit -SaveBaseline -BaselinePath .\baseline.json

# Later — diff against baseline, skip WMI (no admin)
Invoke-PersistenceAudit -BaselinePath .\baseline.json -Skip WMISubscriptions

# Grab the flag count without opening the file
$r = Invoke-PersistenceAudit -BaselinePath .\baseline.json
$r.FlagCount
$r.NewCount
```

## Output

Markdown file with one `## SectionName` per section. Flagged rows start with ⚠ and new rows start with 🆕.

The script also returns a summary object:

```
HostName     : WIN11-VM
RunTime      : 00:00:08.3421
SectionCount : 5
FlagCount    : 12
NewCount     : 0
OutFile      : C:\...\PersistenceAudit-WIN11-VM-20260416-0930.md
```

## Running the tests

```powershell
# Unit tests only (no admin, no WMI)
Invoke-Pester .\Invoke-PersistenceAudit.Tests.ps1 -Output Detailed -ExcludeTagFilter Integration

# All tests including integration
Invoke-Pester .\Invoke-PersistenceAudit.Tests.ps1 -Output Detailed
```

The integration test skips WMI subscriptions so it runs without admin.

## Known gaps

- **No remote support.** Runs localhost only. `Invoke-Command` wrapper is on the roadmap.
- **Service binary parsing is best-effort.** Paths like `%SystemRoot%\system32\svchost.exe` aren't expanded, so signature checks fall back to "Unknown" for those.
- **Baseline is name/path-based, not hash-based.** A replaced binary at the same path won't show as new. A full integrity check (hash-based) would require a separate pass.
