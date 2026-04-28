# Control Mapping — Get-LoggingCoverage

## NIST SP 800-53 Rev 5

### AU-2 — Event Logging

Requires organizations to identify the types of events the system can log in support of
the audit function. `Get-LoggingCoverage` directly audits PowerShell ScriptBlock logging,
Module logging, Transcription, Sysmon, and WEF — all event-generation mechanisms
relevant to AU-2(a) and AU-2(d).

### AU-12 — Audit Record Generation

Requires systems to generate audit records for events identified in AU-2. Each check in
`Get-LoggingCoverage` corresponds to a distinct audit-record source: PowerShell engine
events (4103, 4104), Sysmon process-creation and network events, and WEF-forwarded
records from endpoints to a central collector.

---

## CIS Windows 11 Benchmark

### 18.9.100 — PowerShell Logging

| CIS Control | Description | Script Setting |
|-------------|-------------|----------------|
| 18.9.100.1  | Turn on Module Logging — Enabled | `EnableModuleLogging` = 1 |
| 18.9.100.2  | Turn on PowerShell Script Block Logging — Enabled | `EnableScriptBlockLogging` = 1 |
| 18.9.100.3  | Turn on Script Execution (transcription) | `EnableTranscripting` = 1 |

---

## Check-to-Framework Matrix

| Script Check               | NIST AU-2 | NIST AU-12 | CIS 18.9.100 |
|----------------------------|:---------:|:----------:|:------------:|
| ScriptBlock Logging        | Yes       | Yes        | 18.9.100.2   |
| Module Logging             | Yes       | Yes        | 18.9.100.1   |
| Transcription              | Yes       | Yes        | 18.9.100.3   |
| Sysmon                     | Yes       | Yes        | —            |
| WEF (Wecsvc + subs)        | Yes       | Yes        | —            |
