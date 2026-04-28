# ATT&CK mapping — Invoke-QuickTriage

This script doesn't detect a single technique — it's more of a "what's going
on right now" snapshot. But each section has a reason to exist from an
attacker's perspective, and that reason maps back to ATT&CK.

| Section | What gets flagged | ATT&CK | Why it matters |
|---|---|---|---|
| Processes | Unsigned binary running from %TEMP% or %APPDATA% | T1036 (Masquerading), T1059 (Scripting) | Legit software installs under Program Files. If something's running out of AppData and it's unsigned, that's unusual. |
| Listeners | High port owned by a process in a weird location | T1071 (App Layer Protocol), T1205 (Traffic Signaling) | C2 tools tend to bind ephemeral ports from wherever they were dropped, not from system paths. |
| RecentPersistence (Service) | New service, non-Microsoft signer | T1543.003 (Windows Service) | Attackers love services — they survive reboots and run as SYSTEM. A fresh unsigned one is worth a look. |
| RecentPersistence (Task) | Scheduled task created in the last 30d | T1053.005 (Scheduled Task) | Same story as services. Common lateral movement follow-up. |
| DropsiteFiles | Executable or script that showed up recently in a user-writable folder | T1105 (Ingress Tool Transfer), T1204 (User Execution) | This is where stagers land. Even a benign-looking .ps1 in %TEMP% is worth noting. |
| Defender | Recent detections from Windows Defender | SI-4 (NIST) | If Defender already caught something, it'll show up here. |
| PSHistory | Recent ScriptBlock events (informational) | T1059.001 (PowerShell) | Quick read on what PS has been up to. For deeper analysis, use Invoke-ScriptBlockParse. |
| AdminMembership | Who's in Administrators (informational) | T1078 (Valid Accounts) | An unexpected account here is a flag — especially service accounts or names you don't recognize. |
| Sessions | Who's logged on (informational) | T1021 (Remote Services) | An unexpected RDP or interactive session is a lateral movement indicator worth investigating. |

## NIST 800-53

- **IR-4** — This is your incident handling first step.
- **SI-4** — Looking for signs of unauthorized activity is literally what SI-4 asks for.
- **AU-6** — The PS history and service/task creation data feeds directly into audit review.
