# Security Analyst — Blue Team / SOC Scripts

PowerShell + Python scripts for defensive security work: endpoint triage, threat hunting, persistence auditing, log analysis, and threat-intel enrichment. Techniques map to MITRE ATT&CK where applicable.

## Layout

Scripts are grouped by the ATT&CK tactic they primarily support. Tools that don't fit neatly into one tactic (SIEM-lite, threat-intel CLI, phishing triage, Sysmon auditor) live under `_Tooling/`.

```
SecurityAnalyst/
├── _SHARED/            # shared helpers (SA.Common PS module, sa_common Python pkg)
├── _Tooling/           # cross-tactic tools
├── InitialAccess/
├── Execution/
├── Persistence/
├── LateralMovement/
├── Discovery/
└── Triage/
```

## Coverage matrix

| # | Script | Folder | Language | ATT&CK | Tests | Status |
|---|--------|--------|----------|--------|-------|--------|
| 1 | Invoke-QuickTriage | Triage | PowerShell | triage / T1036, T1059, T1543.003 | 13/13 Pester | shipped |
| 2 | Invoke-LogonHunt | InitialAccess | PowerShell | T1078, T1110 | 22/22 Pester | shipped |
| 3 | Invoke-ScriptBlockParse | Execution | Python | T1059.001, T1027, T1027.010 | 42/42 pytest | shipped |
| 4 | Invoke-RemoteExecHunt | LateralMovement | PowerShell | T1021, T1059, T1543, T1053 | 22/22 Pester | shipped |
| 5 | Invoke-IOCSweep | Triage | PowerShell | T1046, T1018, T1049, T1071, T1059 | 20/20 Pester | shipped |
| 6 | Invoke-SysmonAudit | _Tooling | PowerShell | DS0009, DS0024 (sensor health) | 33/33 Pester | shipped |
| 7 | Get-IOCIntel | _Tooling | Python | T1598 (enrichment) | 26/26 pytest | shipped |
| 8 | Invoke-PhishTriage | _Tooling | Python | T1566, T1566.001, T1566.002 | 21/21 pytest | shipped |
| 9 | Invoke-PersistenceAudit | Persistence | PowerShell | T1547.001, T1053.005, T1543.003, T1546.003 | — | blocked (Defender ML) |
| 10 | Get-ArtifactCollect | Triage | PowerShell | T1555, T1003 (defender) | — | draft (deferred) |
| 11 | mini-siem (capstone) | _Tooling | Python | detection engine | — | draft (deferred) |

Status: `draft` = spec only · `in-progress` = code exists, not yet through CI · `shipped` = passing CI + manually verified · `blocked` = waiting on external dependency

**Milestone progress:** 8/10 scripts shipped (PersistenceAudit blocked on Defender ML signature; ArtifactCollect + mini-siem deferred to dedicated sessions).

## Shared modules

- **PowerShell:** `_SHARED/PowerShell/SA.Common/` — `Import-Module ./SecurityAnalyst/_SHARED/PowerShell/SA.Common`. Exports `Write-SAReport` and `Test-SAElevation`.
- **Python:** `_SHARED/Python/sa_common/` — `pip install -e SecurityAnalyst/_SHARED/Python`. Provides `sa_common.io` and `sa_common.log`.

## Conventions

Every script folder has:

- `README.md` with YAML frontmatter (name, ATT&CK IDs, NIST controls, difficulty, status)
- The script itself (`Verb-Noun.ps1` or Python module)
- A test file (Pester or pytest)
- `samples/` (optional) — canned inputs/outputs for reviewers
- `docs/attack-mapping.md` — per-detection rationale + technique IDs

State-changing actions are gated behind `-WhatIf` (PS) / `--dry-run` (Py). No credentials in source — use env vars or `SecretManagement`.

## CI

- `.github/workflows/powershell.yml` — PSScriptAnalyzer + Pester on `windows-latest`
- `.github/workflows/python.yml` — ruff + pytest on `ubuntu-latest`

Both run on push/PR touching relevant paths.
