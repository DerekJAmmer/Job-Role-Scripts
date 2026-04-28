---
role: Compliance
language: PowerShell
difficulty: easy / medium / hard
frameworks:
  nist_800_53: []
  cis_windows11: []
  stig: []
---

# Compliance — Windows Hardening, Policy Audit, and Baseline Drift Scripts

Compliance / Auditor scripts for Windows hardening, policy auditing, and baseline drift. Targets the Compliance/IT-auditor role on a portfolio. Scripts map to NIST 800-53, CIS Benchmarks for Windows 11, and DISA STIG where applicable.

## Layout

Scripts are grouped by audit function. Shared helpers live under `_SHARED/`.

```
Compliance/
├── _SHARED/            # shared helpers (Compliance.Common PS module)
├── PolicyAudit/        # password policy, audit policy, user-rights checks
├── BaselineAudit/      # CIS benchmark and DISA STIG compliance checks
├── Inventory/          # software inventory, BitLocker, USB policy status
└── Reporting/          # NIST 800-171 mapping and audit report generation
```

## Coverage matrix

| # | Script | Subfolder | Difficulty | Frameworks | Tests | Status | Last reviewed |
|---|--------|-----------|------------|------------|-------|--------|---------------|
| 1 | Get-PasswordPolicy | PolicyAudit | easy | NIST IA-5 / CIS 1.x | 48 | shipped | — |
| 2 | Get-AuditPolicy | PolicyAudit | easy | NIST AU-2 / CIS 17.x | 32 | shipped | — |
| 3 | Get-LoggingCoverage | PolicyAudit | easy | NIST AU-2 / CIS 18.9.100 | 35 | shipped | — |
| 4 | Test-CISBenchmark | BaselineAudit | hard | CIS Win11 | 25 | shipped | — |
| 5 | Test-STIGCompliance | BaselineAudit | hard | DISA STIG | 24 | shipped | — |
| 6 | Get-UserRightsAssignment | PolicyAudit | easy | NIST AC-3 | 26 | shipped | — |
| 7 | Get-SoftwareInventoryCVE | Inventory | medium | NIST SI-5 / RA-5 / CIS 2.3 | 21 | shipped | — |
| 8 | Test-NIST80017Mapping | Reporting | medium | NIST 800-171 | 21 | shipped | — |
| 9 | Get-BitLockerStatus | Inventory | easy | NIST SC-28 | 30 | shipped | — |
| 10 | Get-USBPolicyStatus | PolicyAudit | easy | NIST AC-19 / MP-7 | 31 | shipped | — |

**Milestone progress: 10/10 scripts shipped.**

Status legend:

- `planned` — spec not yet started
- `in-progress` — code exists, not yet through CI
- `shipped` — passing CI and manually verified
- `blocked` — waiting on an external dependency

## Next up

Role complete — all 10/10 scripts shipped. Next role: WindowsServerAdmin.

## Shared module

Import with:

```powershell
Import-Module ./Compliance/_SHARED/PowerShell/Compliance.Common
```

Exports `Write-ComplianceReport` and `Test-ComplianceElevation`.

Note: `Write-ComplianceReport` inlines its own `ConvertTo-HtmlEncodedCompliance` helper to keep the module self-contained. If a cross-role shared library is introduced in a future task (Tasks 18/19), that helper is a candidate for promotion to the shared layer.

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
