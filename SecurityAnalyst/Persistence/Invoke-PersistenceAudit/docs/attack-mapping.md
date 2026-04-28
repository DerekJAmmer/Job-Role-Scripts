# ATT&CK mapping — Invoke-PersistenceAudit

Each section of the audit maps to one or more persistence techniques from MITRE ATT&CK TA0003.

| Section | What gets flagged | ATT&CK | Why it matters |
|---|---|---|---|
| RunKeys | Unsigned binary in HKLM/HKCU Run keys | T1547.001 (Boot/Logon Autostart: Registry Run Keys) | The classic "survive reboot" spot. Easy to add, runs at every logon. |
| ScheduledTasks | Task with an unsigned executable | T1053.005 (Scheduled Task/Job: Scheduled Task) | Attackers plant tasks after lateral movement. `at.exe` is gone but the WMI/XML interface is still very much alive. |
| Services | Service with an unsigned or missing binary | T1543.003 (Create or Modify System Process: Windows Service) | Services run as SYSTEM by default and start on boot. A new non-Microsoft service is worth investigating every time. |
| WMISubscriptions | Any event filter/consumer/binding | T1546.003 (Event Triggered Execution: Windows Management Instrumentation Event Subscription) | Extremely persistent — survives reboots, task deletion, and most cleanup scripts. Rare in legitimate software. |
| StartupFolders | Unsigned file in Common Startup or user Startup | T1547.001 (same as Run keys — startup folder is part of the same sub-technique) | Simple drag-and-drop persistence. Surprisingly common in commodity malware. |
| LSAPackages | Unknown Authentication or Notification Package | T1547.002 (Boot/Logon Autostart: Authentication Package) | LSA packages load into lsass.exe and can intercept credentials. Any non-standard entry here is a red flag. |

## NIST 800-53

- **SI-4** — This is system monitoring. Detecting unauthorized or unexpected autostart entries is exactly what SI-4 (System Monitoring) calls for.
- **CM-7** — Principle of least functionality. Unknown services and tasks are a configuration baseline deviation.
- **AU-6** — Audit review. Persistence changes should show up in audit logs — this script helps correlate what exists with what's expected.
