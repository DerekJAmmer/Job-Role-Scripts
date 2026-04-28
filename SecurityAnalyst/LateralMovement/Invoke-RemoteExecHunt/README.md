---
role: SecurityAnalyst
tactic: LateralMovement
language: PowerShell
difficulty: intermediate
frameworks:
  mitre_attack: [T1021, T1021.002, T1021.006, T1047, T1053.005, T1543.003, T1059]
  nist_800_53: [AU-3, AU-6, AU-12, SI-4]
  cis_windows11: []
  stig: []
---

# Invoke-RemoteExecHunt

Hunts Windows event logs for signs of remote execution — the kind of activity that shows up when an attacker (or a tool like PsExec) runs something on a machine from across the network.

Covers four vectors:

| Detection | Event Source | Event IDs |
|---|---|---|
| Remote service install | Security | 4697 |
| Remote scheduled task | Security | 4698, 4702 |
| WMI execution / subscriptions | WMI-Activity/Operational | 5857, 5860, 5861 |
| PSRemoting / WinRM sessions | WinRM/Operational | 91 |

---

## Requirements

- PowerShell 7.2+
- Read access to the **Security** event log (elevation recommended — the log is often large and restricted)
- `Microsoft-Windows-WMI-Activity/Operational` and `Microsoft-Windows-WinRM/Operational` logs enabled on the target

---

## Usage

```powershell
# Basic run — last 24 hours, write report to current directory
Invoke-RemoteExecHunt

# Look back further
Invoke-RemoteExecHunt -HoursBack 72

# Suppress WinRM findings from your jump box / monitoring system
Invoke-RemoteExecHunt -AllowedSourceIPs '10.0.0.50', '10.0.0.51'

# Skip PSRemoting entirely if WinRM is routine in your environment
Invoke-RemoteExecHunt -Skip PSRemoting

# Custom output path
Invoke-RemoteExecHunt -OutFile C:\IR\remote-exec-$(hostname).md
```

---

## Parameters

| Parameter | Default | Notes |
|---|---|---|
| `-HoursBack` | 24 | How far back to pull events |
| `-StartTime` / `-EndTime` | — | Explicit time range (overrides `-HoursBack`) |
| `-MaxEvents` | 5000 | Cap per event ID — raise for high-volume environments |
| `-AllowedSourceIPs` | `@()` | PSRemoting: suppress findings from these source IPs |
| `-OutFile` | auto | Defaults to `.\RemoteExecHunt-<host>-<ts>.md` |
| `-Skip` | `@()` | Skip one or more detections |

---

## What gets flagged

**ServiceInstall** — any service install where the binary is unsigned or not Microsoft-signed. PsExec registers `PSEXESVC`; most remote-exec frameworks drop their own service.

**RemoteTaskCreate** — task creates/modifications where the action command contains known LOLBins: `powershell`, `cmd.exe`, `wscript`, `cscript`, `mshta`, `rundll32`, `regsvr32`, `certutil`, `bitsadmin`, `msiexec`, `wmic`.

**WMIExecution** — all 5860/5861 events (temporary and permanent WMI event subscriptions). Also 5857 if the provider namespace is outside `root/cimv2` or `root/microsoft`.

**PSRemoting** — every WinRM session (event 91). All flagged by default; use `-AllowedSourceIPs` to suppress known-good sources.

---

## Output

Returns a `[pscustomobject]` summary:

```
HostName      : MYHOST
RunTime       : 00:00:01.2345678
FindingCount  : 3
EventsScanned : 412
OutFile       : C:\...\RemoteExecHunt-MYHOST-20260417-1430.md
```

And writes a Markdown report grouped by detection type.

---

## Limitations / tuning tips

- **4697 / 4698 / 4702** require `Audit Object Access` → `Audit Other Object Access Events` to be enabled (or via GPO). Check with `auditpol /get /subcategory:"Other Object Access Events"`.
- **WMI-Activity/Operational** log is off by default on some builds. Enable: `wevtutil sl Microsoft-Windows-WMI-Activity/Operational /e:true`.
- **WinRM/91** only fires if WinRM is running. If remote management is fully disabled, this will always be empty.
- Service installs from well-known admin tools (SCCM, Intune, backup agents) will appear unsigned unless those vendors sign their binaries. Tune by adding a known-services allow-list if needed.
