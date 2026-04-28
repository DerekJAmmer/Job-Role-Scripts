# ATT&CK mapping — Invoke-IOCSweep

Each detection surface exists because attackers leave specific traces.
Here's the connection back to ATT&CK for each check this script runs.

| Detection surface | What gets checked | ATT&CK | Why it matters |
|---|---|---|---|
| Hash | SHA256 of files in exec-likely paths | T1059 (Command and Scripting Interpreter), T1105 (Ingress Tool Transfer) | Malware and stagers get dropped to disk before they run. If you have a hash from a threat intel report, this tells you whether that exact binary landed on the box. |
| Connection | Active TCP connections to IOC IPs | T1046 (Network Service Discovery), T1071 (Application Layer Protocol) | C2 channels and data exfil show up as live connections. Catching an active connection to a known bad IP is about as direct as it gets. |
| Process | Running process names matched against IOC list | T1018 (Remote System Discovery), T1059 (Command and Scripting Interpreter) | Tools like Mimikatz, Cobalt Strike beacons, and custom loaders have recognisable process names. Stripping `.exe` and case-folding catches the common name-fudging attempts. |
| DNS | DNS client cache entries matching IOC domains (exact or subdomain) | T1049 (System Network Connections Discovery), T1071 (Application Layer Protocol) | A domain lookup leaves a trail in the DNS cache even after the TCP connection closes. Subdomain matching catches `cdn.evil.com` when your IOC is `evil.com`. |

## NIST 800-53

- **IR-4** — Sweeping for known IOCs is the first concrete step in incident handling after you have indicators to work from.
- **SI-4** — Checking active connections, processes, and files for known-bad artifacts is exactly what SI-4's "monitor the system" requirement looks like in practice.
- **AU-6** — The JSON report this script produces feeds directly into audit review and can be archived as evidence for the incident timeline.
