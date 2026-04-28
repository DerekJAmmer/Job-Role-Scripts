# ATT&CK mapping — Invoke-LogonHunt

| Detection | Event IDs | ATT&CK | Why it matters |
|---|---|---|---|
| BurstFailures | 4625 | T1110 (Brute Force), T1110.001 (Password Guessing), T1110.003 (Password Spraying) | Rapid repeated failures from the same source are the clearest brute-force signal in Windows event logs. Spray shows up as moderate failure counts spread across many accounts. |
| MultiSourceLogons | 4624 | T1078 (Valid Accounts) | An account logging in from multiple distinct IPs in a short window can mean credential reuse, pass-the-hash, or a compromised credential being used from an attacker-controlled machine. |
| ExplicitCredentials | 4624 type 9 | T1078 (Valid Accounts), T1021.001 (Remote Services: RDP), T1550.002 (Pass the Hash) | Logon type 9 is what you see with `runas /netonly` or pass-the-hash tools. Legit sysadmin use does happen, but it's rare enough to be worth reviewing every time. |
| OffHoursLogons | 4624 types 2/10 | T1078 (Valid Accounts), T1021.001 (Remote Services: RDP) | Attackers using stolen credentials often operate from different timezones or after hours when detection response is slower. An account that normally logs in 9–5 showing up at 2am is worth a look. |

## NIST 800-53

- **AU-6** — Audit review. These detections are exactly the kind of anomaly auditing AU-6 asks you to look for.
- **IR-4** — Incident handling. Burst failures and multi-source logons are often the first observable evidence of an active intrusion attempt.
- **SI-4** — System monitoring. Continuous logon monitoring at the event-log level maps directly to SI-4's requirement to monitor for unauthorized activity.
