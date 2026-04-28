---
name: Invoke-SysmonAudit
role: SecurityAnalyst
tactic_folder: _Tooling
language: PowerShell
difficulty: easy
status: in-progress
entry_point: Invoke-SysmonAudit.ps1
requires:
  PowerShell: 7.2+
  Modules: []
  Privileges: non-elevated; admin not required for the checks
frameworks:
  mitre_attack:
    tactic: TA0007
    techniques: []
    data_sources: [DS0009, DS0024]
  nist_800_53: [SI-4, AU-2, CM-7]
inputs:
  - BaselineConfigPath: string (optional; XML config to hash for comparison)
  - ExpectedConfigHash: string (optional; SHA256 to compare against active config)
  - OutputPath: string (optional; JSON report path)
  - Quiet: switch (suppress console table)
outputs:
  - JSON file at -OutputPath if supplied
  - PSCustomObject: { HostName, RunTime, PassCount, FailCount, SkipCount, OutputPath, Results }
---

# Invoke-SysmonAudit

Sysmon is the telemetry backbone for most Windows host detection. If it's not
running, not signed, or running the wrong config, your SIEM is blind. This
script answers the question "is my sensor healthy?" across five read-only
checks in under a second.

Run it as part of pre-investigation prep, scheduled SOC hygiene, or a
compliance posture sweep.

## Checks

| # | Check | What it queries | Pass condition |
|---|---|---|---|
| 1 | Sysmon Installed | `Get-Service Sysmon64, Sysmon` | Service object returned |
| 2 | Sysmon Running | Service status | `Status -eq 'Running'` |
| 3 | SysmonDrv Loaded | `Get-CimInstance Win32_SystemDriver` where `Name='SysmonDrv'` | Driver found and `State -eq 'Running'` |
| 4 | Sysmon Binary Signed | `Get-AuthenticodeSignature` on the service binary | Status=Valid and signer contains "Sysinternals" or "Microsoft" |
| 5 | Config Hash Match | SHA256 of active config (via registry path) vs supplied baseline | Hashes match; Skipped if no baseline provided |

## Why no -WhatIf?

This script is purely read-only. It calls no cmdlets that change system
state, so `-WhatIf` / `-Confirm` are not applicable and have not been
implemented. The `PSUseShouldProcess` suppression attribute in the source
documents this explicitly.

## Usage

**Basic — check if Sysmon is healthy:**
```powershell
.\Invoke-SysmonAudit.ps1
Invoke-SysmonAudit
```

**With a baseline config file (derives expected hash from the XML):**
```powershell
Invoke-SysmonAudit -BaselineConfigPath C:\Configs\sysmon-baseline.xml
```

**With a pre-computed expected hash:**
```powershell
Invoke-SysmonAudit -ExpectedConfigHash 'A1B2C3D4...'
```

**JSON report, suppress console table:**
```powershell
Invoke-SysmonAudit -OutputPath C:\Reports\sysmon-audit.json -Quiet
```

**Pipe results into further analysis:**
```powershell
$audit = Invoke-SysmonAudit -Quiet
$audit.Results | Where-Object Status -eq 'Fail' | Select-Object Check, Remediation
```

## Output shape

```
HostName   : WORKSTATION01
RunTime    : 00:00:00.2134561
PassCount  : 4
FailCount  : 0
SkipCount  : 1
OutputPath : $null
Results    : [ { Check, Status, Detail, Remediation }, ... ]
```

Each `Results` entry:

| Property | Type | Description |
|---|---|---|
| Check | string | Human-readable check name |
| Status | string | `Pass`, `Fail`, `Skipped`, or `Warning` |
| Detail | string | What was found |
| Remediation | string | What to do if the check fails |

## Running the tests

From the repo root:
```powershell
Invoke-Pester -Path .\SecurityAnalyst\_Tooling\Invoke-SysmonAudit\Invoke-SysmonAudit.Tests.ps1 -Output Detailed
```

Lint:
```powershell
Invoke-ScriptAnalyzer -Path .\SecurityAnalyst\_Tooling\Invoke-SysmonAudit -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
```

## Known gaps

- **Local only.** `-ComputerName` remote auditing is not implemented; run
  via `Invoke-Command` for remote hosts.
- **Config semantics not validated.** The config hash check tells you whether
  the file changed, not whether the XML is valid or the rules are correct.
- **Signature accepts both Sysinternals and Microsoft signers.** Sysinternals
  tools are dual-signed. Both are treated as trusted.
- **Config path via registry only.** If `SysmonDrv\Parameters\ConfigFile`
  is absent (some Sysmon versions don't write it), the config check is
  Skipped rather than invoking `sysmon -c`, which would run an executable.
