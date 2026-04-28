# Job-Role Scripts

Practical, job-ready PowerShell + Python scripts across IT and security roles. Built as a portfolio of working tools — not demos. Each script ships with tests (Pester / pytest), a README, and framework mappings (MITRE ATT&CK, NIST 800-53, CIS, DISA STIG) where relevant.

**Conventions**
- PowerShell 7+ for Windows / AD / Azure
- Python for parsing, network, and API work
- State-changing actions gated behind `-WhatIf` (PS) / `--dry-run` (Py)
- No credentials in source — env vars or `SecretManagement` only

## Table of Contents

- [SecurityAnalyst](#securityanalyst) — blue-team / SOC tooling
- [SysAdmin](#sysadmin) — Windows + AD operations
- [Compliance](#compliance) — CIS / STIG / NIST audits

---

## SecurityAnalyst

Detection, triage, and threat-hunting scripts mapped to MITRE ATT&CK. Shared helpers in [`SecurityAnalyst/_SHARED/`](SecurityAnalyst/_SHARED).

| Tactic | Script | Lang | ATT&CK |
|---|---|---|---|
| InitialAccess | [Invoke-LogonHunt](SecurityAnalyst/InitialAccess/Invoke-LogonHunt) | PowerShell | T1078, T1110 |
| Execution | [Invoke-ScriptBlockParse](SecurityAnalyst/Execution/Invoke-ScriptBlockParse) | Python | T1059.001, T1027 |
| Persistence | [Invoke-PersistenceAudit](SecurityAnalyst/Persistence/Invoke-PersistenceAudit) ⚠️ *WIP* | PowerShell | TA0003 |
| LateralMovement | [Invoke-RemoteExecHunt](SecurityAnalyst/LateralMovement/Invoke-RemoteExecHunt) | PowerShell | T1021, T1569 |
| Triage | [Invoke-QuickTriage](SecurityAnalyst/Triage/Invoke-QuickTriage) | PowerShell | — |
| Triage | [Invoke-IOCSweep](SecurityAnalyst/Triage/Invoke-IOCSweep) | PowerShell | — |
| _Tooling | [Get-IOCIntel](SecurityAnalyst/_Tooling/Get-IOCIntel) | Python | VT / AbuseIPDB / OTX |
| _Tooling | [Invoke-PhishTriage](SecurityAnalyst/_Tooling/Invoke-PhishTriage) | Python | T1566 |
| _Tooling | [Invoke-SysmonAudit](SecurityAnalyst/_Tooling/Invoke-SysmonAudit) | PowerShell | — |

---

## SysAdmin

Windows Server, Active Directory, and endpoint operations. 337 Pester tests across the role. Shared helpers in [`SysAdmin/_SHARED/`](SysAdmin/_SHARED).

| Category | Script | Purpose |
|---|---|---|
| ADManagement | [New-ADUserBulk](SysAdmin/ADManagement/New-ADUserBulk) | Bulk AD user provisioning from CSV |
| ADManagement | [Remove-StaleADObject](SysAdmin/ADManagement/Remove-StaleADObject) | Stage stale users/computers to disabled OU |
| ADManagement | [Backup-GPO](SysAdmin/ADManagement/Backup-GPO) | Export all GPOs and diff against last snapshot |
| Inventory | [Get-ServerInventory](SysAdmin/Inventory/Get-ServerInventory) | CPU/RAM/disk/OS/uptime across server list |
| Inventory | [Get-PendingReboot](SysAdmin/Inventory/Get-PendingReboot) | Detect pending-reboot conditions |
| Maintenance | [Invoke-ScheduledReboot](SysAdmin/Maintenance/Invoke-ScheduledReboot) | Batched maintenance-window reboot orchestrator |
| Maintenance | [Invoke-DiskCleanup](SysAdmin/Maintenance/Invoke-DiskCleanup) | Threshold-triggered temp/log/WinSxS cleanup |
| Reporting | [Get-WindowsUpdateCompliance](SysAdmin/Reporting/Get-WindowsUpdateCompliance) | WSUS/Intune missing-patch report |
| Reporting | [Get-ShareACLAudit](SysAdmin/Reporting/Get-ShareACLAudit) | Recursive ACL export, flag broad grants |
| Reporting | [Get-FeatureDrift](SysAdmin/Reporting/Get-FeatureDrift) | Compare installed Windows features to a manifest |

---

## Compliance

CIS, DISA STIG, and NIST 800-53 audit tooling. 293 Pester + pytest tests across the role. Shared helpers in [`Compliance/_SHARED/`](Compliance/_SHARED).

| Category | Script | Framework |
|---|---|---|
| BaselineAudit | [Test-CISBenchmark](Compliance/BaselineAudit/Test-CISBenchmark) | CIS Windows benchmark checks |
| BaselineAudit | [Test-STIGCompliance](Compliance/BaselineAudit/Test-STIGCompliance) | DISA STIG compliance checks |
| PolicyAudit | [Get-AuditPolicy](Compliance/PolicyAudit/Get-AuditPolicy) | Advanced audit-policy export |
| PolicyAudit | [Get-PasswordPolicy](Compliance/PolicyAudit/Get-PasswordPolicy) | Domain + fine-grained password policy |
| PolicyAudit | [Get-USBPolicyStatus](Compliance/PolicyAudit/Get-USBPolicyStatus) | Removable-storage policy status |
| PolicyAudit | [Get-UserRightsAssignment](Compliance/PolicyAudit/Get-UserRightsAssignment) | Local user rights export |
| PolicyAudit | [Get-LoggingCoverage](Compliance/PolicyAudit/Get-LoggingCoverage) | Log channel + size coverage report |
| Inventory | [Get-BitLockerStatus](Compliance/Inventory/Get-BitLockerStatus) | BitLocker volume status report |
| Inventory | [Get-SoftwareInventoryCVE](Compliance/Inventory/Get-SoftwareInventoryCVE) | Installed software with known-CVE lookup |
| Reporting | [Test-NIST80017Mapping](Compliance/Reporting/Test-NIST80017Mapping) | NIST 800-171 control mapping |

