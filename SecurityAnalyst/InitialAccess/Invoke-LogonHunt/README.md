---
name: Invoke-LogonHunt
role: SecurityAnalyst
tactic_folder: InitialAccess
language: PowerShell
difficulty: intermediate
status: in-progress
entry_point: Invoke-LogonHunt.ps1
requires:
  PowerShell: 7.2+
  Modules: []
  Privileges: needs access to the Security event log (non-elevated gets cached events; elevation gets more)
frameworks:
  mitre_attack:
    tactic: TA0001
    techniques: [T1078, T1110, T1110.001, T1110.003, T1021.001]
  nist_800_53: [AU-6, IR-4, SI-4]
inputs:
  - HoursBack: int (default 24)
  - StartTime: datetime (overrides HoursBack)
  - EndTime: datetime (default now)
  - MaxEvents: int (default 10000)
  - BurstThreshold: int (default 5 — failures from same source to call it a burst)
  - BurstWindowMin: int (default 5 — rolling window for burst detection in minutes)
  - MultiSourceThreshold: int (default 3 — distinct IPs for same account)
  - WorkHourStart/End: int (default 7 and 19)
  - OutFile: string
  - Skip: string[] (BurstFailures, MultiSourceLogons, ExplicitCredentials, OffHoursLogons)
outputs:
  - Markdown file at -OutFile
  - PSCustomObject: { HostName, RunTime, Events4624, Events4625, FindingCount, OutFile }
---

# Invoke-LogonHunt

Hunt the Security event log for logon patterns that stick out. Pulls 4624 (success) and 4625 (failure) events, runs them through four detection passes, and writes a Markdown report.

## Detections

| Detection | Event IDs | What it looks for | ATT&CK |
|---|---|---|---|
| BurstFailures | 4625 | N+ failures from the same source IP in a rolling window | T1110 (Brute Force) |
| MultiSourceLogons | 4624 | Same account logging in from N+ distinct IPs in an hour | T1078 (Valid Accounts) |
| ExplicitCredentials | 4624 | Type-9 logons (runas/netonly / pass-the-hash style) | T1078, T1021 |
| OffHoursLogons | 4624 | Interactive/RDP logons outside business hours for accounts that also log on during normal hours | T1078 |

## Usage

```powershell
# Last 24 hours with defaults
Invoke-LogonHunt

# 48-hour window, tighter burst threshold, custom output
Invoke-LogonHunt -HoursBack 48 -BurstThreshold 3 -OutFile .\logon-hunt.md

# Skip the off-hours detection (useful when covering global teams)
Invoke-LogonHunt -Skip OffHoursLogons

# Specific time window
Invoke-LogonHunt -StartTime '2026-04-15 00:00' -EndTime '2026-04-15 23:59'
```

## Output

Markdown report with one section per detection type.

The summary object:

```
HostName     : WIN11-VM
RunTime      : 00:00:03.8521
Events4624   : 1423
Events4625   : 87
FindingCount : 3
OutFile      : C:\...\LogonHunt-WIN11-VM-20260416-0930.md
```

## Tuning

Default thresholds are intentionally conservative — you'll want to adjust for your environment:

- **BurstThreshold / BurstWindowMin** — 5 failures in 5 min works on a workstation. On a DC with hundreds of users, bump this up or you'll get noise from legitimate password retries.
- **MultiSourceThreshold** — 3 IPs in an hour is low. For environments where users connect from multiple devices or VPN exit nodes, 5–10 is more realistic.
- **WorkHourStart / WorkHourEnd** — adjust for your timezone and shift schedule. `OffHoursLogons` is useless if your team spans multiple timezones — skip it in that case.

## Running the tests

```powershell
# Unit tests only (no event log access needed)
Invoke-Pester .\Invoke-LogonHunt.Tests.ps1 -ExcludeTagFilter Integration -Output Detailed

# All tests (needs Security log access)
Invoke-Pester .\Invoke-LogonHunt.Tests.ps1 -Output Detailed
```

## Known gaps

- **Localhost only.** Running against remote hosts isn't wired up yet.
- **No Kerberos failure analysis.** 4768/4769/4771 events would add Kerberoasting and AS-REP detection — that's in scope for a future iteration.
- **Off-hours detection is timezone-naive.** It compares local time only. If your DC logs in UTC and your workstation is in a different zone, results may be off by your UTC offset.
