# ATT&CK Mapping — Invoke-RemoteExecHunt

## Tactics covered

| Tactic | ID | Name |
|---|---|---|
| Lateral Movement | TA0008 | Lateral Movement |
| Execution | TA0002 | Execution |
| Persistence | TA0003 | Persistence |

---

## Technique mapping

### T1021 — Remote Services
**Detection:** PSRemoting (WinRM/91), ServiceInstall (Security 4697)

Attackers use legitimate remote access protocols to move laterally. WinRM (Windows Remote Management) is the transport for both `Enter-PSSession` and `Invoke-Command`. A WinRM session from an unexpected source is a reliable indicator.

Sub-techniques directly covered:
- **T1021.002** — SMB/Windows Admin Shares: service installs (PsExec-style) use SMC + service creation (4697)
- **T1021.006** — Windows Remote Management: WinRM/91 events

---

### T1047 — Windows Management Instrumentation
**Detection:** WMIExecution (WMI-Activity 5857, 5860, 5861)

WMI is a common remote execution vehicle — attackers call `Win32_Process.Create` remotely or register event subscriptions to trigger payloads. Temporary (5860) and permanent (5861) subscriptions are especially suspicious; legitimate software rarely registers WMI subscriptions at runtime.

---

### T1053.005 — Scheduled Task/Job: Scheduled Task
**Detection:** RemoteTaskCreate (Security 4698, 4702)

`schtasks /create /s <remote host>` or the COM Task Scheduler API can schedule tasks on remote systems. Attackers use this for both execution and persistence. Event 4698 fires on task creation; 4702 on modification.

---

### T1543.003 — Create or Modify System Process: Windows Service
**Detection:** ServiceInstall (Security 4697)

PsExec and similar tools register a temporary service (e.g. `PSEXESVC`) to execute commands on a remote host. The service is typically unsigned. Event 4697 captures all service installs system-wide.

---

### T1059 — Command and Scripting Interpreter
**Detection:** RemoteTaskCreate (task action command analysis)

Flagged when a new/modified scheduled task action calls a scripting interpreter (`powershell`, `cmd`, `wscript`, `cscript`, `mshta`) or common LOLBins (`rundll32`, `regsvr32`, `certutil`, etc.).

---

## NIST 800-53 controls

| Control | Title | Relevance |
|---|---|---|
| AU-3 | Content of Audit Records | Event IDs captured include user, time, source |
| AU-6 | Audit Record Review, Analysis, and Reporting | This script automates the analysis step |
| AU-12 | Audit Record Generation | Verifies that relevant events are being logged |
| SI-4 | System Monitoring | Detects anomalous remote execution patterns |

---

## Data sources (MITRE ATT&CK framework)

- Windows event logs: Security, WMI-Activity/Operational, WinRM/Operational
- Process: Service creation (4697)
- Scheduled job: Task creation / modification (4698, 4702)
- WMI: Provider activity, event subscriptions (5857, 5860, 5861)
- Network traffic: WinRM session metadata (91)
