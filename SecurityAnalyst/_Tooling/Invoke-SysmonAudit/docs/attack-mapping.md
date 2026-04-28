# ATT&CK mapping — Invoke-SysmonAudit

Sysmon is the foundational data source for Windows host detection. Without it,
a huge chunk of ATT&CK telemetry isn't collected. This script doesn't detect
attacker behavior; it verifies the sensor that does is working.

## Data source coverage validated

| Sysmon event ID | What it sees | ATT&CK mapping |
|---|---|---|
| 1 | Process creation | T1059.* (Command and Scripting Interpreter) |
| 3 | Network connection | T1071 (Application Layer Protocol), T1041 (Exfiltration Over C2) |
| 7 | Image loaded | T1055 (Process Injection), T1574.002 (DLL Side-Loading) |
| 8 | CreateRemoteThread | T1055.001 (DLL Injection) |
| 10 | Process accessed | T1003.001 (LSASS Memory) |
| 11 | File created | T1105 (Ingress Tool Transfer), T1546 (Event Triggered Execution) |
| 12-14 | Registry events | T1547.* (Boot or Logon Autostart Execution) |

If this audit fails, you've lost visibility into all of the above. That's the impact.

## Data sources (DS)

- **DS0009 — Process** — Sysmon events 1, 8, 10 are the primary source of
  process-level telemetry. If the service is down, DS0009 coverage is gone.
- **DS0024 — Windows Registry** — Sysmon events 12-14 feed registry monitoring.
  Without Sysmon, most registry-based persistence detection is blind.

## NIST 800-53

- **SI-4** — Information system monitoring requires functional sensors. This is
  the sensor self-check.
- **AU-2** — Audit events: Sysmon defines what gets audited. If Sysmon is down,
  the audit policy is fiction.
- **CM-7** — Least functionality: knowing whether your monitoring agent is the
  version and config you intended is part of configuration management.
