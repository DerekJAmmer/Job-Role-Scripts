# SysAdmin — System Administration Scripts

PowerShell scripts for AD management, server inventory, maintenance, and reporting. Maps to NIST 800-53 / CIS where relevant.

## Layout

Scripts are grouped by administrative function. Shared helpers live under `_SHARED/`.

```
SysAdmin/
├── _SHARED/            # shared helpers (SysAdmin.Common PS module)
├── ADManagement/       # Active Directory user, group, and object management
├── Inventory/          # server and asset inventory collection
├── Maintenance/        # scheduled tasks, reboots, disk cleanup
└── Reporting/          # health checks, compliance, dependency maps
```

## Coverage matrix

| # | Script | Folder | Difficulty | Frameworks | Tests | Status | Path | Last reviewed |
|---|--------|--------|------------|------------|-------|--------|------|---------------|
| 1 | New-ADUserBulk | ADManagement | easy | NIST AC-2, IA-4 | 53/53 Pester | shipped | ADManagement/New-ADUserBulk/ | 2026-04-28 shipped + reviewed |
| 2 | Get-ServerInventory | Inventory | easy | NIST CM-8 | 16/16 Pester | shipped | Inventory/Get-ServerInventory/ | 2026-04-28 shipped + reviewed |
| 3 | Invoke-ScheduledReboot | Maintenance | medium | NIST CM-3 | 36/36 Pester | shipped | Maintenance/Invoke-ScheduledReboot/ | 2026-04-28 shipped |
| 4 | Remove-StaleADObject | ADManagement | medium | NIST AC-2 | 45/45 Pester | shipped | ADManagement/Remove-StaleADObject/ | 2026-04-28 shipped |
| 5 | Backup-GPO | ADManagement | medium | NIST CM-2 | 25/25 Pester | shipped | ADManagement/Backup-GPO/ | 2026-04-28 shipped |
| 6 | Get-ShareACLAudit | Reporting | medium | NIST AC-3, AC-6 | 28/28 Pester | shipped | Reporting/Get-ShareACLAudit/ | 2026-04-28 shipped |
| 7 | Get-WindowsUpdateCompliance | Reporting | medium | NIST SI-2 | 33/33 Pester | shipped | Reporting/Get-WindowsUpdateCompliance/ | 2026-04-28 shipped |
| 8 | Invoke-DiskCleanup | Maintenance | easy | NIST SI-12 | 21/21 Pester | shipped | Maintenance/Invoke-DiskCleanup/ | 2026-04-28 shipped + reviewed |
| 9 | Get-PendingReboot | Inventory | easy | NIST CM-3 | 27/27 Pester | shipped | Inventory/Get-PendingReboot/ | 2026-04-28 shipped + reviewed |
| 10 | Get-FeatureDrift | Reporting | easy | NIST CM-2, CM-8 | 23/23 Pester | shipped | Reporting/Get-FeatureDrift/ | 2026-04-28 shipped + reviewed |

**Milestone progress: 10/10 scripts shipped.**

Status legend:

- `planned` — spec not yet started
- `in-progress` — code exists, not yet through CI
- `shipped` — passing CI and manually verified
- `blocked` — waiting on an external dependency

## Shared module

Import with:

```powershell
Import-Module ./SysAdmin/_SHARED/PowerShell/SysAdmin.Common
```

Exports `Write-SysAdminReport` and `Test-SysAdminElevation`.

## Conventions

Every script folder has:

- `README.md` with YAML frontmatter (name, NIST controls, CIS controls, difficulty, status)
- The script itself (`Verb-Noun.ps1`)
- A test file (Pester)
- `samples/` (optional) — canned inputs/outputs for reviewers

State-changing actions are gated behind `-WhatIf`. No credentials in source — use env vars or `SecretManagement`.

## CI

- `.github/workflows/powershell.yml` — PSScriptAnalyzer + Pester on `windows-latest`

Runs on push/PR touching relevant paths.
