# Control Mapping — Get-AuditPolicy

## NIST SP 800-53 Rev 5

| Control | Title | Relevance |
|---------|-------|-----------|
| AU-2    | Event Logging | Requires organizations to identify the types of events the system is capable of logging. `Get-AuditPolicy` surfaces the current Windows audit subcategory configuration, enabling verification that required event types are enabled. |

## CIS Microsoft Windows 11 Benchmark v3.0 — Section 17 (Advanced Audit Policy)

| CIS ID | Subcategory (examples)                        | Category              | Expected Setting          |
|--------|-----------------------------------------------|-----------------------|---------------------------|
| 17.1   | Credential Validation                         | Account Logon         | Success and Failure       |
| 17.2   | Security Group Management, User Account Mgmt  | Account Management    | Success and Failure       |
| 17.3   | Process Creation                              | Detailed Tracking     | Success                   |
| 17.4   | Directory Service Access, Changes             | DS Access             | Success and Failure       |
| 17.5   | Logon, Logoff, Account Lockout, Special Logon | Logon/Logoff          | Varies (see baseline JSON)|
| 17.6   | File Share, Filtering Platform Connection     | Object Access         | Varies                    |
| 17.7   | Audit Policy Change, Auth Policy Change       | Policy Change         | Success                   |
| 17.8   | Sensitive Privilege Use                       | Privilege Use         | Success and Failure       |
| 17.9   | Security State Change, System Integrity       | System                | Success and Failure       |

Full expected values for each subcategory are defined in `samples/cis-audit-baseline.json`.
