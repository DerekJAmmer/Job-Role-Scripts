---
role: SysAdmin
language: PowerShell
difficulty: medium
frameworks:
  mitre_attack: []
  nist_800_53: [CM-3]
  cis_windows11: []
  stig: []
---

# Invoke-ScheduledReboot

Schedule a graceful maintenance-window reboot on one or more remote Windows hosts by
registering a one-time Task Scheduler task that runs `shutdown /r /t 0` at a specified
future time. The script validates pre-conditions before scheduling, then emits a per-host
result row to the pipeline (and optionally to a JSON file).

This script only *schedules* a future reboot. It does not execute shutdown immediately
and does not validate post-reboot state. The task is registered via `Register-ScheduledTask`
on the target host; removing the task is the operator's responsibility if plans change.

---

## Parameters

| Parameter           | Type       | Required | Default | Description |
|---------------------|------------|----------|---------|-------------|
| `ComputerName`      | `string[]` | Yes      | —       | One or more target host names. |
| `When`              | `datetime` | Yes      | —       | Scheduled reboot time. Must be >= 5 minutes in the future. |
| `PreCheck`          | `bool`     | No       | `$true` | Run pre-checks before scheduling. Pass `-PreCheck:$false` to bypass all checks. |
| `MaxActiveSessions` | `int`      | No       | `0`     | Max active sessions tolerated. Any active session fails the check when set to 0. |
| `OutputPath`        | `string`   | No       | —       | Write the result set as UTF-8 JSON to this path. |

`PreCheck` is a `[bool]` rather than a `[switch]` so callers can explicitly disable it
with `-PreCheck:$false` without ambiguity.

---

## Pre-checks

When `$PreCheck` is `$true` (default), the following checks run per host in order.
The first failure marks the host `Skipped` and stops further checks for that host.

| Check | Pass condition | Failure behaviour |
|-------|----------------|-------------------|
| Reachability | `Test-Connection ... -Quiet` returns `$true` | Skipped / Reason: Unreachable |
| Uptime | `Win32_OperatingSystem.LastBootUpTime` >= 1 hour ago | Skipped / Reason: Uptime check failed |
| Pending reboot | `Get-PendingReboot` result (if available) | **Informational only** — recorded in `PreCheckResults.PendingReboot` but never blocks scheduling. A pending reboot is itself a reason to reboot, so it should not stop the task from being registered. |
| Active sessions | `quser.exe` parsed session count <= `MaxActiveSessions` | Skipped / Reason: Sessions check failed. If `quser` fails or is unavailable, `ActiveSessions` is recorded as `'unknown'` and the host is **not** failed — not every host exposes `quser`. |

---

## Status values

| Status      | Meaning |
|-------------|---------|
| `Scheduled` | Task registered on the remote host via `Register-ScheduledTask`. |
| `Skipped`   | One or more pre-checks failed. See `Reason` field. |
| `WhatIf`    | `-WhatIf` was supplied; `ShouldProcess` returned false. No task was registered. |
| `Failed`    | `Register-ScheduledTask` threw an exception. See `Reason` field. Processing continues to the next host. |

---

## Output row shape

```powershell
[PSCustomObject]@{
    Host            = <string>
    Started         = <datetime>   # when this row was processed
    ScheduledFor    = <datetime>   # populated only on Scheduled
    Status          = <string>     # Scheduled | Skipped | WhatIf | Failed
    Reason          = <string>     # populated on Skipped and Failed
    PreCheckResults = [PSCustomObject]@{
        Reachable      = <bool|null>
        UptimeHours    = <double|null>
        PendingReboot  = <bool|null>   # null if Get-PendingReboot unavailable
        ActiveSessions = <int|'unknown'|null>
    }
}
```

---

## Safety

This function is declared with `ConfirmImpact = 'High'` and
`SupportsShouldProcess = $true`. Every call to `Register-ScheduledTask` is wrapped in
`$PSCmdlet.ShouldProcess(...)`, which means:

- Running with `-WhatIf` prints a preview of what would be scheduled on each host and
  returns rows with `Status = 'WhatIf'` without touching any remote system.
- Running with `-Confirm` (or when `$ConfirmPreference` is `High`) prompts before each
  host's task is registered.
- In unattended pipelines, suppress the confirm prompt by passing `-Confirm:$false`
  explicitly once you have validated intent.

Always run with `-WhatIf` first against any unfamiliar host list.

---

## Examples

```powershell
# Preview without scheduling anything
Invoke-ScheduledReboot -ComputerName SRV01 -When (Get-Date).AddHours(2) -WhatIf

# Schedule on two servers during a maintenance window
Invoke-ScheduledReboot -ComputerName SRV01,SRV02 -When '2026-05-01 02:00' -OutputPath C:\reports\reboot.json

# Skip all pre-checks (e.g. staging environment)
Invoke-ScheduledReboot -ComputerName SRV03 -When (Get-Date).AddMinutes(30) -PreCheck:$false

# Allow up to 2 active sessions before failing the check
Invoke-ScheduledReboot -ComputerName SRV04 -When (Get-Date).AddHours(1) -MaxActiveSessions 2
```

---

## Requirements

- PowerShell 7.2+
- `ScheduledTasks` module (ships with Windows 8 / Server 2012 and later)
- Remote access rights sufficient to register tasks on target hosts
- `quser.exe` available on target hosts for session checks (failure is tolerated)
